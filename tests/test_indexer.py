"""
tests/test_indexer.py
---------------------
Unit tests for Week 2 Repo Indexer, parser, graph, and retrieval engine.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from indexer.embeddings import retrieve
from indexer.graph import CodeGraph
from indexer.index import RepoIndex
from indexer.parser import parse_source_file


def test_parser_extracts_functions_and_classes() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        f = Path(tmpdir) / "math_mod.py"
        f.write_text(
            '"""Math utilities."""\n\n'
            "def add(a, b):\n"
            '    """Add two numbers."""\n'
            "    return a + b\n\n"
            "class Calculator:\n"
            "    def compute(self, x):\n"
            "        return add(x, 10)\n",
            encoding="utf-8",
        )

        parsed = parse_source_file(f)
        assert parsed.parse_error is None
        assert len(parsed.records) >= 3

        names = [r.name for r in parsed.records]
        assert "add" in names
        assert "Calculator" in names
        assert "Calculator.compute" in names

        calc_compute = next(r for r in parsed.records if r.name == "Calculator.compute")
        assert "add" in calc_compute.calls


def test_parser_graceful_on_syntax_error() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        broken_file = Path(tmpdir) / "broken.py"
        broken_file.write_text("def broken():\n    return +++\n", encoding="utf-8")

        # Must not raise an exception
        parsed = parse_source_file(broken_file)
        assert parsed.file == "broken.py"


def test_code_graph_and_impact() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "calc.py").write_text(
            "def average(nums):\n    return sum(nums) / len(nums)\n",
            encoding="utf-8",
        )
        (root / "report.py").write_text(
            "from calc import average\n\n"
            "def generate_report(data):\n"
            "    return average(data)\n",
            encoding="utf-8",
        )
        (root / "test_report.py").write_text(
            "import unittest\nfrom report import generate_report\n\n"
            "class TestReport(unittest.TestCase):\n"
            "    def test_run(self):\n"
            "        generate_report([1, 2])\n",
            encoding="utf-8",
        )

        p1 = parse_source_file(root / "calc.py", root_dir=root)
        p2 = parse_source_file(root / "report.py", root_dir=root)
        p3 = parse_source_file(root / "test_report.py", root_dir=root)

        cg = CodeGraph.build([p1, p2, p3])
        summary = cg.get_summary()
        assert summary["files"] == 3
        assert summary["symbols"] >= 3

        # Locate symbol in calc.py
        sym = cg.get_symbol_by_location("calc.py", 1)
        assert sym is not None
        assert sym["name"] == "average"

        # Walk impact for average
        impact = cg.compute_impact([sym], ["calc.py"])
        assert "report.py" in impact["affected_files"]
        assert "test_report.py" in impact["affected_tests"]
        assert len(impact["callers"]) >= 1


def test_retriever_query() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "analytics.py").write_text(
            "def compute_moving_average(values):\n"
            '    """Calculate moving average window."""\n'
            "    return sum(values)\n",
            encoding="utf-8",
        )

        results = retrieve("moving average", root)
        assert len(results) > 0
        assert results[0].name == "compute_moving_average"
        assert results[0].score > 0.0


def test_repo_index_incremental() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        f = root / "sample.py"
        f.write_text("def alpha(): return 1\n", encoding="utf-8")

        idx = RepoIndex(root)
        g1 = idx.build_or_update()
        assert (root / ".agai_index" / "hashes.json").exists()
        assert (root / ".agai_index" / "graph.json").exists()

        # Incremental second run with no changes
        g2 = idx.build_or_update()
        assert g2.get_summary()["symbols"] == g1.get_summary()["symbols"]
