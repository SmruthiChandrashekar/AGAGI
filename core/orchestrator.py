"""
core/orchestrator.py
--------------------
LangGraph Review Pipeline (Week 5):
  ingest → impact → merge_simulation → [security || dependency] → triage → review → rca → fix → report
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from agents.dependency_agent import run_dependency_agent
from agents.fix_agent import run_fix_agent
from agents.impact_agent import run_impact_agent
from agents.merge_sim_agent import run_merge_simulation_agent
from agents.rca_agent import run_rca_agent
from agents.reporter_agent import run_reporter_agent
from agents.review_agent import run_review_agent
from agents.security_agent import run_security_agent
from agents.triage_agent import run_triage_agent
from core.logging import get_logger
from core.state import (
    ChangeSet,
    PipelineStage,
    ReviewState,
    make_initial_state,
)

logger = get_logger(__name__)


# ── Pipeline Nodes ────────────────────────────────────────────────────────────


def node_ingest(state: ReviewState) -> dict[str, Any]:
    """Ingest step: Validates the incoming changeset."""
    logger.info("stage_start", stage="ingest")
    cs = state.get("changeset")
    if not cs:
        return {"stage": PipelineStage.FAILED, "error": "No ChangeSet provided to review engine."}

    logger.info("ingest_changeset_ready", repo=str(cs.repo_path), base=cs.base_ref, head=cs.head_ref)
    return {"stage": PipelineStage.INIT}


def node_impact(state: ReviewState) -> dict[str, Any]:
    """Impact step: Analyzes changed files, AST changes, and blast radius."""
    return run_impact_agent(state)


def node_merge_simulation(state: ReviewState) -> dict[str, Any]:
    """Merge simulation step: Tests merge isolated in sandbox, isolates main baseline."""
    return run_merge_simulation_agent(state)


def node_security(state: ReviewState) -> dict[str, Any]:
    """Security analysis step: Scans changed files with Semgrep, Gitleaks, Bandit."""
    return run_security_agent(state)


def node_dependency(state: ReviewState) -> dict[str, Any]:
    """Dependency analysis step: Scans modified manifest files with OSV/pip-audit."""
    return run_dependency_agent(state)


def node_triage(state: ReviewState) -> dict[str, Any]:
    """LLM triage step: Filters false positives, ranks severity, generates explanations."""
    return run_triage_agent(state)


def node_review(state: ReviewState) -> dict[str, Any]:
    """Code review step: Reviews changed functions for logic bugs and edge cases."""
    return run_review_agent(state)


def node_rca(state: ReviewState) -> dict[str, Any]:
    """Root-cause analysis step: Diagnoses test regressions and confirmed vulnerabilities."""
    return run_rca_agent(state)


def node_fix(state: ReviewState) -> dict[str, Any]:
    """Fix generator step: Proposes unified diffs and validates with git apply --check."""
    return run_fix_agent(state)


def node_report(state: ReviewState) -> dict[str, Any]:
    """Report step: Synthesizes findings, regressions, root causes, patches, and verdict."""
    return run_reporter_agent(state)


# ── Graph Builder ─────────────────────────────────────────────────────────────


def build_graph() -> StateGraph:
    """
    Build LangGraph review workflow for Week 5:
    ingest → impact → merge_simulation → [security || dependency] → triage → review → rca → fix → report
    """
    g = StateGraph(ReviewState)

    g.add_node("ingest", node_ingest)
    g.add_node("impact", node_impact)
    g.add_node("merge_simulation", node_merge_simulation)
    g.add_node("security", node_security)
    g.add_node("dependency", node_dependency)
    g.add_node("triage", node_triage)
    g.add_node("review", node_review)
    g.add_node("rca", node_rca)
    g.add_node("fix", node_fix)
    g.add_node("report", node_report)

    g.set_entry_point("ingest")
    g.add_edge("ingest", "impact")
    g.add_edge("impact", "merge_simulation")

    # Fan-out: run Security and Dependency scanners in parallel
    g.add_edge("merge_simulation", "security")
    g.add_edge("merge_simulation", "dependency")

    # Fan-in: combine findings for LLM triage
    g.add_edge("security", "triage")
    g.add_edge("dependency", "triage")

    # Linear Week 5 pipeline: triage → review → rca → fix → report
    g.add_edge("triage", "review")
    g.add_edge("review", "rca")
    g.add_edge("rca", "fix")
    g.add_edge("fix", "report")
    g.add_edge("report", END)

    return g


# Module singleton compiled graph
_graph = build_graph().compile()


def run_review(changeset: ChangeSet) -> ReviewState:
    """Execute the review pipeline synchronously and return the final ReviewState."""
    initial = make_initial_state(changeset)
    final: ReviewState = _graph.invoke(initial)  # type: ignore[assignment]
    return final
