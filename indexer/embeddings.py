"""
indexer/embeddings.py
----------------------
Code chunk retrieval engine for Week 2.
Provides retrieve(query, repo_path, top_k) which returns sensible chunks
for queries such as 'average calculation', 'multiply', or 'report summary'.
Uses token weighting, identifier boosting, and docstring relevance.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from core.logging import get_logger
from indexer.parser import SymbolRecord, parse_source_file

logger = get_logger(__name__)


@dataclass
class CodeChunk:
    """A retrievable snippet of code with metadata and ranking score."""

    id: str
    file: str
    name: str
    kind: str
    start_line: int
    end_line: int
    content: str
    docstring: str | None = None
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _tokenize(text: str) -> list[str]:
    """Tokenize and normalize text into identifier words and stems."""
    # Split on whitespace, underscores, camelCase, and non-alphanumeric chars
    words = re.findall(r"[A-Za-z0-9]+", text.lower())
    # Sub-split camelCase
    split_words: list[str] = []
    for w in words:
        parts = re.findall(r"[a-z0-9]+|[A-Z][a-z0-9]*", w)
        split_words.extend([p.lower() for p in parts if p])
    return split_words


def retrieve(
    query: str,
    repo_path: Path | str,
    top_k: int = 5,
) -> list[CodeChunk]:
    """
    Search codebase chunks for relevant code snippets matching the natural language or keyword query.
    Extracts functions, classes, and docstrings from repository source files.
    """
    root = Path(repo_path).resolve()
    query_tokens = _tokenize(query)
    if not query_tokens:
        return []

    # Collect source files
    py_files: list[Path] = []
    for ext in ("*.py",):
        for p in root.rglob(ext):
            if any(part.startswith(".") for part in p.parts):
                continue
            if "__pycache__" in p.parts or ".venv" in p.parts:
                continue
            py_files.append(p)

    chunks: list[CodeChunk] = []

    for f in py_files:
        parsed = parse_source_file(f, root_dir=root)
        for rec in parsed.records:
            chunk_id = f"{parsed.file}:{rec.name}:{rec.start_line}"
            chunks.append(
                CodeChunk(
                    id=chunk_id,
                    file=parsed.file,
                    name=rec.name,
                    kind=rec.kind,
                    start_line=rec.start_line,
                    end_line=rec.end_line,
                    content=rec.code,
                    docstring=rec.docstring,
                    score=0.0,
                )
            )

    if not chunks:
        return []

    # Score chunks based on token matches, field boosting, and length normalization
    scored: list[CodeChunk] = []
    for c in chunks:
        name_tokens = _tokenize(c.name)
        doc_tokens = _tokenize(c.docstring or "")
        code_tokens = _tokenize(c.content)
        file_tokens = _tokenize(c.file)

        score = 0.0
        for qt in query_tokens:
            # Exact or prefix match in symbol name (highest weight)
            if qt in name_tokens:
                score += 15.0
            elif any(nt.startswith(qt) or qt in nt for nt in name_tokens):
                score += 8.0

            # Match in docstring
            if qt in doc_tokens:
                score += 8.0

            # Match in file path
            if qt in file_tokens:
                score += 4.0

            # Frequency match in code body
            count_in_code = code_tokens.count(qt)
            if count_in_code > 0:
                score += 2.0 * math.log(1 + count_in_code)

        if score > 0.0:
            c.score = round(score, 3)
            scored.append(c)

    # Sort descending by score
    scored.sort(key=lambda x: x.score, reverse=True)
    return scored[:top_k]
