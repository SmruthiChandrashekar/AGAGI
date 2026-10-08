"""
indexer/index.py
-----------------
Repo Indexer with incremental file-hash caching.
Builds the AST symbol records and networkx dependency/call graph.
Caches file hashes and graphs on disk for instant incremental updates.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from core.logging import get_logger
from indexer.graph import CodeGraph
from indexer.parser import ParsedFile, parse_source_file

logger = get_logger(__name__)


def _compute_file_hash(file_path: Path) -> str:
    """Compute sha256 checksum of file contents."""
    h = hashlib.sha256()
    try:
        h.update(file_path.read_bytes())
        return h.hexdigest()
    except Exception:
        return ""


class RepoIndex:
    """Incremental Repository Indexer."""

    def __init__(self, repo_path: Path | str) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.cache_dir = self.repo_path / ".agai_index"
        self.hash_file = self.cache_dir / "hashes.json"
        self.graph_file = self.cache_dir / "graph.json"
        self.graph: CodeGraph = CodeGraph()
        self.parsed_files: dict[str, ParsedFile] = {}
        self.hashes: dict[str, str] = {}

    def _discover_python_files(self) -> list[Path]:
        """Find all relevant Python files, ignoring venvs and git."""
        found: list[Path] = []
        for p in self.repo_path.rglob("*.py"):
            parts = p.parts
            if any(part.startswith(".") for part in parts if part != "."):
                continue
            if "__pycache__" in parts or ".venv" in parts or "node_modules" in parts:
                continue
            found.append(p)
        return found

    def build_or_update(self, force: bool = False) -> CodeGraph:
        """
        Build or incrementally update the repository index and call graph.
        Only re-parses files whose SHA256 hash has changed since the last build.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        old_hashes: dict[str, str] = {}
        if not force and self.hash_file.is_file():
            try:
                old_hashes = json.loads(self.hash_file.read_text(encoding="utf-8"))
            except Exception:
                old_hashes = {}

        py_files = self._discover_python_files()
        new_hashes: dict[str, str] = {}
        changed_or_new: list[Path] = []

        for f in py_files:
            try:
                rel = str(f.relative_to(self.repo_path)).replace("\\", "/")
            except ValueError:
                rel = f.name
            f_hash = _compute_file_hash(f)
            new_hashes[rel] = f_hash

            if force or rel not in old_hashes or old_hashes.get(rel) != f_hash:
                changed_or_new.append(f)

        logger.info(
            "repo_index_scan",
            total_files=len(py_files),
            changed_files=len(changed_or_new),
            force=force,
        )

        # Parse only changed or new files, otherwise load or retain
        parsed_list: list[ParsedFile] = []
        for f in py_files:
            try:
                rel = str(f.relative_to(self.repo_path)).replace("\\", "/")
            except ValueError:
                rel = f.name

            if f in changed_or_new or rel not in self.parsed_files:
                pf = parse_source_file(f, root_dir=self.repo_path)
                self.parsed_files[rel] = pf
                parsed_list.append(pf)
            else:
                parsed_list.append(self.parsed_files[rel])

        # Build graph
        self.graph = CodeGraph.build(parsed_list)
        self.hashes = new_hashes

        # Persist to disk
        try:
            self.hash_file.write_text(json.dumps(new_hashes, indent=2), encoding="utf-8")
            self.graph.save(self.graph_file)
        except Exception as exc:
            logger.warning("repo_index_persist_failed", error=str(exc))

        return self.graph


# Singleton cache per repo path
_INDEX_CACHE: dict[str, RepoIndex] = {}


def get_repo_index(repo_path: Path | str, force: bool = False) -> RepoIndex:
    """Retrieve or initialize the RepoIndex instance for the given repository path."""
    key = str(Path(repo_path).resolve())
    if key not in _INDEX_CACHE:
        _INDEX_CACHE[key] = RepoIndex(key)
    idx = _INDEX_CACHE[key]
    idx.build_or_update(force=force)
    return idx
