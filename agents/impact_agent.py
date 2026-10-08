"""
agents/impact_agent.py
----------------------
Impact Agent v2 (Week 2):
  - Incremental code parsing and dependency/call graph inspection
  - Maps changed diff lines to the functions and classes that contain them
  - Walks the graph to find direct and indirect callers
  - Determines affected files, affected tests, and blast radius
  - Formulates human-readable risk hints (e.g. 'changed function has 6 callers')
  - Feeds affected tests forward so merge simulation can run them first
"""

from __future__ import annotations

from typing import Any

from core.logging import get_logger
from core.state import PipelineStage, ReviewState
from indexer.index import get_repo_index
from tools.git_ops import get_diff, list_changed_files, parse_diff_changed_lines

logger = get_logger(__name__)


def run_impact_agent(state: ReviewState) -> dict[str, Any]:
    """
    Execute Impact Analysis v2 using AST parser and call/dependency graph.
    """
    logger.info("stage_start", stage="impact_agent_v2")
    cs = state.get("changeset")
    if not cs:
        logger.warning("impact_agent_missing_changeset")
        return {
            "stage": PipelineStage.IMPACT_ANALYSIS,
            "affected_files": [],
            "affected_tests": [],
            "changed_functions": [],
            "risk_hint": "No changeset provided.",
            "graph_summary": {},
            "blast_radius_score": 0.0,
            "diff": "",
            "raw_diff": "",
        }

    # 1. Compute Git Diff and Changed Files
    try:
        raw_diff = get_diff(cs.repo_path, cs.base_ref, cs.head_ref)
    except Exception as exc:
        logger.warning("get_diff_failed", error=str(exc))
        raw_diff = ""

    try:
        changed_files = list_changed_files(cs.repo_path, cs.base_ref, cs.head_ref)
    except Exception as exc:
        logger.warning("list_changed_files_failed", error=str(exc))
        changed_files = []

    # 2. Build or incrementally load Repository Code Graph
    try:
        repo_idx = get_repo_index(cs.repo_path)
        code_graph = repo_idx.graph
        graph_summary = code_graph.get_summary()
    except Exception as exc:
        logger.warning("repo_index_failed", error=str(exc))
        repo_idx = None
        code_graph = None
        graph_summary = {}

    # 3. Map changed lines from diff to functions/symbols
    diff_lines_map = parse_diff_changed_lines(raw_diff)
    changed_symbols: list[dict[str, Any]] = []
    seen_symbols: set[str] = set()

    if code_graph:
        for file_path, lines in diff_lines_map.items():
            for line_no in lines:
                sym = code_graph.get_symbol_by_location(file_path, line_no)
                if sym and sym["id"] not in seen_symbols:
                    seen_symbols.add(sym["id"])
                    changed_symbols.append(sym)

        # 4. Walk dependency & call graph for callers and affected tests
        impact = code_graph.compute_impact(changed_symbols, changed_files)
        affected_files = impact["affected_files"]
        affected_tests = impact["affected_tests"]
        risk_hint = impact["risk_hint"]
        callers = impact["callers"]
    else:
        # Fallback if graph unavailable
        affected_files = list(changed_files)
        affected_tests = [
            f for f in changed_files if "test" in f.lower() or f.startswith("tests/")
        ]
        callers = []
        risk_hint = f"Diff touches {len(changed_files)} files."

    # 5. Compute Blast Radius Score (0.0 to 1.0)
    # Scaled by: number of callers, affected tests, and changed file count
    caller_factor = min(0.4, len(callers) * 0.1)
    file_factor = min(0.3, len(affected_files) * 0.08)
    test_factor = min(0.3, len(affected_tests) * 0.1)
    blast_radius = round(min(1.0, caller_factor + file_factor + test_factor), 2)
    if blast_radius == 0.0 and (changed_files or raw_diff):
        blast_radius = 0.1

    logger.info(
        "impact_agent_v2_complete",
        changed_symbols=[s.get("name") for s in changed_symbols],
        caller_count=len(callers),
        affected_files_count=len(affected_files),
        affected_tests_count=len(affected_tests),
        blast_radius=blast_radius,
    )

    return {
        "stage": PipelineStage.IMPACT_ANALYSIS,
        "affected_files": affected_files,
        "affected_tests": affected_tests,
        "changed_functions": changed_symbols,
        "risk_hint": risk_hint,
        "graph_summary": graph_summary,
        "blast_radius_score": blast_radius,
        "diff": raw_diff,
        "raw_diff": raw_diff,
    }
