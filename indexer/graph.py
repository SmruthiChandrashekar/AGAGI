"""
indexer/graph.py
-----------------
networkx dependency & call graph builder.
Constructs a graph linking files, functions, classes, imports, calls,
and maps each test suite to the exact code it exercises.
Supports fast JSON serialization to disk for instant subsequent loads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx

from core.logging import get_logger
from indexer.parser import ParsedFile, SymbolRecord

logger = get_logger(__name__)


class CodeGraph:
    """Directed dependency and call graph powered by NetworkX."""

    def __init__(self, graph: nx.DiGraph | None = None) -> None:
        self.graph: nx.DiGraph = graph if graph is not None else nx.DiGraph()

    # ── Node ID Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def file_node_id(rel_path: str) -> str:
        return f"file:{rel_path}"

    @staticmethod
    def symbol_node_id(rel_path: str, name: str) -> str:
        return f"symbol:{rel_path}:{name}"

    # ── Graph Construction ───────────────────────────────────────────────────

    @classmethod
    def build(cls, parsed_files: list[ParsedFile]) -> CodeGraph:
        """Construct the complete graph from a list of parsed files."""
        cg = cls()
        g = cg.graph

        # Index all symbols for fast lookup by name and module
        # name -> list of (file, SymbolRecord)
        name_to_records: dict[str, list[tuple[str, SymbolRecord]]] = {}
        # stem (e.g. "calc") -> list of files (e.g. ["calc.py"])
        stem_to_files: dict[str, list[str]] = {}

        for pf in parsed_files:
            file_id = cg.file_node_id(pf.file)
            is_test_file = "test" in pf.file.lower()
            g.add_node(file_id, node_type="file", path=pf.file, is_test=is_test_file)

            stem = Path(pf.file).stem
            stem_to_files.setdefault(stem, []).append(pf.file)

            for rec in pf.records:
                sym_id = cg.symbol_node_id(pf.file, rec.name)
                is_test = rec.is_test or is_test_file or "test" in rec.name.lower()
                g.add_node(
                    sym_id,
                    node_type="symbol",
                    kind=rec.kind,
                    file=pf.file,
                    name=rec.name,
                    start_line=rec.start_line,
                    end_line=rec.end_line,
                    is_test=is_test,
                    docstring=rec.docstring,
                    code=rec.code,
                )
                # File contains symbol
                g.add_edge(file_id, sym_id, relation="contains")
                name_to_records.setdefault(rec.name, []).append((pf.file, rec))

                # Also index short name if it's a class method
                if "." in rec.name:
                    short_name = rec.name.split(".")[-1]
                    name_to_records.setdefault(short_name, []).append((pf.file, rec))

        # Add Import Edges
        for pf in parsed_files:
            from_file_id = cg.file_node_id(pf.file)
            for imp in pf.imports:
                for target_stem, target_files in stem_to_files.items():
                    if target_stem in imp:
                        for tf in target_files:
                            if tf != pf.file:
                                g.add_edge(from_file_id, cg.file_node_id(tf), relation="imports")

        # Add Call Edges and Test Linkage Edges
        for pf in parsed_files:
            for rec in pf.records:
                caller_id = cg.symbol_node_id(pf.file, rec.name)
                for called_name in rec.calls:
                    # Look up potential targets
                    targets = name_to_records.get(called_name, [])
                    for target_file, target_rec in targets:
                        target_id = cg.symbol_node_id(target_file, target_rec.name)
                        # Avoid self-referencing
                        if caller_id != target_id:
                            g.add_edge(caller_id, target_id, relation="calls")
                            # If caller is a test, mark edge as exercising code
                            if rec.is_test or "test" in pf.file.lower():
                                g.add_edge(caller_id, target_id, relation="exercises")
                                g.add_edge(cg.file_node_id(pf.file), cg.file_node_id(target_file), relation="tests")

        return cg

    # ── Graph Traversal & Impact Analysis ─────────────────────────────────────

    def get_symbol_by_location(self, file_path: str, line_no: int) -> dict[str, Any] | None:
        """Find the innermost function/method containing line_no in file_path."""
        best: dict[str, Any] | None = None
        best_span = float("inf")

        clean_file = file_path.replace("\\", "/")
        for node, data in self.graph.nodes(data=True):
            if data.get("node_type") == "symbol" and data.get("file", "").replace("\\", "/") == clean_file:
                s = data.get("start_line", 0)
                e = data.get("end_line", 0)
                if s <= line_no <= e:
                    span = e - s
                    if span < best_span:
                        best_span = span
                        best = {"id": node, **data}

        return best

    def get_callers(self, symbol_node: str, max_depth: int = 5) -> dict[str, list[dict[str, Any]]]:
        """
        Walk reverse edges (in_edges) to find direct and indirect callers.
        Returns {'direct': [...], 'indirect': [...]}.
        """
        direct: list[dict[str, Any]] = []
        indirect: list[dict[str, Any]] = []
        visited: set[str] = {symbol_node}

        # Level 1: Direct callers
        current_level: list[str] = []
        for pred, _, data in self.graph.in_edges(symbol_node, data=True):
            if data.get("relation") in ("calls", "exercises") and pred not in visited:
                visited.add(pred)
                pred_data = {"id": pred, **self.graph.nodes[pred]}
                direct.append(pred_data)
                current_level.append(pred)

        # Levels 2..max_depth: Indirect callers
        depth = 1
        while current_level and depth < max_depth:
            next_level: list[str] = []
            for node in current_level:
                for pred, _, data in self.graph.in_edges(node, data=True):
                    if data.get("relation") in ("calls", "exercises") and pred not in visited:
                        visited.add(pred)
                        pred_data = {"id": pred, **self.graph.nodes[pred]}
                        indirect.append(pred_data)
                        next_level.append(pred)
            current_level = next_level
            depth += 1

        return {"direct": direct, "indirect": indirect}

    def compute_impact(
        self, changed_symbols: list[dict[str, Any]], changed_files: list[str]
    ) -> dict[str, Any]:
        """
        Given changed symbols and changed files, walk the graph to identify:
          - direct callers
          - indirect callers
          - affected files
          - affected tests
          - risk hint
        """
        all_callers: list[dict[str, Any]] = []
        affected_files_set: set[str] = set(f.replace("\\", "/") for f in changed_files)
        affected_tests_set: set[str] = set()

        for sym in changed_symbols:
            sym_id = sym.get("id") or self.symbol_node_id(sym.get("file", ""), sym.get("name", ""))
            if sym_id in self.graph:
                callers_res = self.get_callers(sym_id)
                for c in callers_res["direct"] + callers_res["indirect"]:
                    all_callers.append(c)
                    c_file = c.get("file")
                    if c_file:
                        c_file_clean = c_file.replace("\\", "/")
                        affected_files_set.add(c_file_clean)
                        if c.get("is_test") or "test" in c_file_clean.lower():
                            affected_tests_set.add(c_file_clean)

        # Also check file-level import edges for any test files that import changed files
        for cf in changed_files:
            cf_clean = cf.replace("\\", "/")
            cf_id = self.file_node_id(cf_clean)
            if cf_id in self.graph:
                for pred, _, data in self.graph.in_edges(cf_id, data=True):
                    if data.get("relation") in ("imports", "tests"):
                        pred_node = self.graph.nodes[pred]
                        pred_path = pred_node.get("path", "").replace("\\", "/")
                        if "test" in pred_path.lower():
                            affected_tests_set.add(pred_path)
                            affected_files_set.add(pred_path)

        # Build risk hint
        caller_count = len(all_callers)
        aff_file_count = len(affected_files_set)
        test_count = len(affected_tests_set)

        if changed_symbols:
            primary_name = changed_symbols[0].get("name", "entity")
            risk_hint = (
                f"Changed symbol '{primary_name}' has {caller_count} direct/indirect callers "
                f"across {aff_file_count} files; exercises {test_count} test suite(s)."
            )
        else:
            risk_hint = f"Changes affect {aff_file_count} files and {test_count} test suite(s)."

        return {
            "changed_symbols": changed_symbols,
            "callers": all_callers,
            "affected_files": sorted(affected_files_set),
            "affected_tests": sorted(affected_tests_set),
            "risk_hint": risk_hint,
        }

    # ── Summary & Serialization ──────────────────────────────────────────────

    def get_summary(self) -> dict[str, int]:
        files_cnt = sum(1 for _, d in self.graph.nodes(data=True) if d.get("node_type") == "file")
        symbols_cnt = sum(1 for _, d in self.graph.nodes(data=True) if d.get("node_type") == "symbol")
        tests_cnt = sum(
            1 for _, d in self.graph.nodes(data=True) if d.get("node_type") == "symbol" and d.get("is_test")
        )
        edges_cnt = self.graph.number_of_edges()
        return {
            "files": files_cnt,
            "symbols": symbols_cnt,
            "tests": tests_cnt,
            "edges": edges_cnt,
        }

    def save(self, file_path: Path | str) -> None:
        """Serialize graph to a JSON file on disk."""
        target = Path(file_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        data = nx.node_link_data(self.graph)
        target.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, file_path: Path | str) -> CodeGraph:
        """Deserialize graph from a JSON file."""
        target = Path(file_path).resolve()
        if not target.is_file():
            return cls()
        data = json.loads(target.read_text(encoding="utf-8"))
        g = nx.node_link_graph(data, directed=True)
        return cls(g)
