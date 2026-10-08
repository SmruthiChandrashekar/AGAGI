"""
indexer/parser.py
------------------
Tree-sitter AST code parser for Python with robust error handling.
Extracts functions, classes, methods, imports, docstrings, and call references.
Falls back gracefully to ast if needed, and never crashes on malformed files.
"""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)

# Tree-sitter setup
_HAS_TREE_SITTER = False
try:
    from tree_sitter import Language, Parser
    import tree_sitter_python

    _PY_LANG = Language(tree_sitter_python.language())
    _TS_PARSER = Parser(_PY_LANG)
    _HAS_TREE_SITTER = True
except Exception as _exc:  # pragma: no cover
    logger.warning("tree_sitter_init_failed", error=str(_exc))
    _HAS_TREE_SITTER = False


@dataclass
class SymbolRecord:
    """A parsed function, class, method, or code entity."""

    name: str
    kind: str  # "function", "class", "method"
    file: str
    start_line: int  # 1-indexed
    end_line: int  # 1-indexed
    code: str
    calls: list[str] = field(default_factory=list)
    docstring: str | None = None
    is_test: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ParsedFile:
    """Parsed representation of a source file."""

    file: str
    records: list[SymbolRecord] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)  # imported modules / symbols
    parse_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "records": [r.to_dict() for r in self.records],
            "imports": self.imports,
            "parse_error": self.parse_error,
        }


def _extract_calls_from_ts_node(node: Any, source_bytes: bytes) -> list[str]:
    """Recursively collect function/method call names from a tree-sitter node."""
    calls: list[str] = []

    def visit(n: Any) -> None:
        if n.type == "call":
            # function part can be identifier or attribute
            fn_node = n.child_by_field_name("function")
            if fn_node:
                if fn_node.type == "identifier":
                    name = source_bytes[fn_node.start_byte : fn_node.end_byte].decode("utf-8", errors="ignore")
                    if name:
                        calls.append(name)
                elif fn_node.type == "attribute":
                    attr_node = fn_node.child_by_field_name("attribute")
                    if attr_node:
                        name = source_bytes[attr_node.start_byte : attr_node.end_byte].decode("utf-8", errors="ignore")
                        if name:
                            calls.append(name)
        for child in n.children:
            visit(child)

    visit(node)
    # Deduplicate while preserving order
    return list(dict.fromkeys(calls))


def _parse_with_tree_sitter(file_path: Path, rel_path: str, code_bytes: bytes) -> ParsedFile:
    """Parse a Python file using tree-sitter."""
    tree = _TS_PARSER.parse(code_bytes)
    root = tree.root_node

    records: list[SymbolRecord] = []
    imports: list[str] = []
    is_test_file = "test" in rel_path.lower()

    def process_node(node: Any, parent_class: str | None = None) -> None:
        for child in node.children:
            # 1. Imports
            if child.type in ("import_statement", "import_from_statement"):
                text = code_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    clean = line.strip()
                    if clean:
                        imports.append(clean)

            # 2. Function definition
            elif child.type == "function_definition":
                name_node = child.child_by_field_name("name")
                name = (
                    code_bytes[name_node.start_byte : name_node.end_byte].decode("utf-8", errors="ignore")
                    if name_node
                    else "anonymous"
                )
                start_line = child.start_point[0] + 1
                end_line = child.end_point[0] + 1
                snippet = code_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="ignore")
                calls = _extract_calls_from_ts_node(child, code_bytes)

                # Docstring
                docstring: str | None = None
                body_node = child.child_by_field_name("body")
                if body_node and body_node.children:
                    first_stmt = body_node.children[0]
                    if first_stmt.type == "expression_statement" and first_stmt.children:
                        if first_stmt.children[0].type == "string":
                            docstring = code_bytes[
                                first_stmt.children[0].start_byte : first_stmt.children[0].end_byte
                            ].decode("utf-8", errors="ignore").strip("\"'")

                full_name = f"{parent_class}.{name}" if parent_class else name
                kind = "method" if parent_class else "function"
                is_test = is_test_file or name.startswith("test_") or name.endswith("_test")

                records.append(
                    SymbolRecord(
                        name=full_name,
                        kind=kind,
                        file=rel_path,
                        start_line=start_line,
                        end_line=end_line,
                        code=snippet,
                        calls=calls,
                        docstring=docstring,
                        is_test=is_test,
                    )
                )

            # 3. Class definition
            elif child.type == "class_definition":
                name_node = child.child_by_field_name("name")
                name = (
                    code_bytes[name_node.start_byte : name_node.end_byte].decode("utf-8", errors="ignore")
                    if name_node
                    else "AnonymousClass"
                )
                start_line = child.start_point[0] + 1
                end_line = child.end_point[0] + 1
                snippet = code_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="ignore")
                is_test = is_test_file or "Test" in name

                records.append(
                    SymbolRecord(
                        name=name,
                        kind="class",
                        file=rel_path,
                        start_line=start_line,
                        end_line=end_line,
                        code=snippet,
                        calls=[],
                        is_test=is_test,
                    )
                )

                # Process methods inside class body
                body_node = child.child_by_field_name("body")
                if body_node:
                    process_node(body_node, parent_class=name)

    process_node(root)
    return ParsedFile(file=rel_path, records=records, imports=imports)


def _parse_with_ast_fallback(file_path: Path, rel_path: str, source_text: str) -> ParsedFile:
    """Fallback AST parser using standard library `ast`."""
    try:
        tree = ast.parse(source_text, filename=str(file_path))
    except SyntaxError as err:
        return ParsedFile(file=rel_path, records=[], imports=[], parse_error=f"SyntaxError: {err}")

    records: list[SymbolRecord] = []
    imports: list[str] = []
    lines = source_text.splitlines()
    is_test_file = "test" in rel_path.lower()

    def get_snippet(node: ast.AST) -> str:
        s_line = getattr(node, "lineno", 1) - 1
        e_line = getattr(node, "end_lineno", s_line + 1)
        return "\n".join(lines[s_line:e_line])

    def get_calls(node: ast.AST) -> list[str]:
        calls = []
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Name):
                    calls.append(n.func.id)
                elif isinstance(n.func, ast.Attribute):
                    calls.append(n.func.attr)
        return list(dict.fromkeys(calls))

    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports.append(ast.unparse(node))
        elif isinstance(node, ast.FunctionDef):
            start = node.lineno
            end = node.end_lineno or start
            records.append(
                SymbolRecord(
                    name=node.name,
                    kind="function",
                    file=rel_path,
                    start_line=start,
                    end_line=end,
                    code=get_snippet(node),
                    calls=get_calls(node),
                    docstring=ast.get_docstring(node),
                    is_test=is_test_file or node.name.startswith("test_"),
                )
            )
        elif isinstance(node, ast.ClassDef):
            start = node.lineno
            end = node.end_lineno or start
            records.append(
                SymbolRecord(
                    name=node.name,
                    kind="class",
                    file=rel_path,
                    start_line=start,
                    end_line=end,
                    code=get_snippet(node),
                    calls=[],
                    docstring=ast.get_docstring(node),
                    is_test=is_test_file or "Test" in node.name,
                )
            )
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    m_start = item.lineno
                    m_end = item.end_lineno or m_start
                    records.append(
                        SymbolRecord(
                            name=f"{node.name}.{item.name}",
                            kind="method",
                            file=rel_path,
                            start_line=m_start,
                            end_line=m_end,
                            code=get_snippet(item),
                            calls=get_calls(item),
                            docstring=ast.get_docstring(item),
                            is_test=is_test_file or item.name.startswith("test_"),
                        )
                    )

    return ParsedFile(file=rel_path, records=records, imports=imports)


def parse_source_file(file_path: Path | str, root_dir: Path | str | None = None) -> ParsedFile:
    """
    Parse a source file and extract its symbol records and imports.
    Handles syntax errors gracefully and never raises an unhandled exception.
    """
    path = Path(file_path).resolve()
    rel_path = path.name
    if root_dir:
        try:
            rel_path = str(path.relative_to(Path(root_dir).resolve())).replace("\\", "/")
        except ValueError:
            rel_path = path.name

    if not path.is_file():
        return ParsedFile(file=rel_path, parse_error=f"File not found: {path}")

    try:
        raw_bytes = path.read_bytes()
    except Exception as exc:
        return ParsedFile(file=rel_path, parse_error=f"Read error: {exc}")

    # Try tree-sitter first
    if _HAS_TREE_SITTER:
        try:
            return _parse_with_tree_sitter(path, rel_path, raw_bytes)
        except Exception as exc:
            logger.debug("tree_sitter_parse_failed_falling_back", file=rel_path, error=str(exc))

    # Fallback to python standard library ast
    try:
        source_text = raw_bytes.decode("utf-8", errors="replace")
        return _parse_with_ast_fallback(path, rel_path, source_text)
    except Exception as exc:
        return ParsedFile(file=rel_path, parse_error=f"Parse failure: {exc}")
