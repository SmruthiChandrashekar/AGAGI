"""
core/orchestrator.py
--------------------
LangGraph Review Pipeline (Week 6, Days 1-2: human approval gate):
  ingest → impact → merge_simulation → [security || dependency] → triage
         → review → rca → fix → approval → report

Two ways to run it:
  - run_review(changeset): no pause, same behaviour as Week 5 (used by the
    dashboard and existing tests until the approval UI is wired up).
  - start_review(changeset) / resume_review(thread_id, decision): pauses at
    the approval step when patches exist and waits for a human decision.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import Command, interrupt

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
    ApprovalDecision,
    ApprovalStatus,
    ChangeSet,
    Patch,
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


def _as_patch(p: Patch | dict[str, Any]) -> Patch:
    """Patches may come back from the checkpointer as dicts; normalise to Patch."""
    return p if isinstance(p, Patch) else Patch.model_validate(p)


def node_approval(state: ReviewState) -> dict[str, Any]:
    """
    Human approval gate.

    - No patches, or approval not required: pass straight through. Nothing is approved.
    - Otherwise: pause the graph with interrupt() and wait for an ApprovalDecision.
      Only patches whose index the human explicitly lists are marked approved.

    Note: LangGraph re-runs this node from the top when resumed, so everything
    before interrupt() must stay side-effect free.
    """
    patches = [_as_patch(p) for p in (state.get("patches") or [])]

    if not patches or not state.get("require_approval", False):
        return {"stage": PipelineStage.HUMAN_APPROVAL}

    payload = {
        "message": "Approve which patches? Nothing is applied without approval.",
        "patches": [
            {
                "index": i,
                "finding_id": p.finding_id,
                "target_files": p.target_files,
                "rationale": p.rationale,
                "unified_diff": p.unified_diff,
            }
            for i, p in enumerate(patches)
        ],
    }

    raw_decision = interrupt(payload)
    decision = (
        raw_decision
        if isinstance(raw_decision, ApprovalDecision)
        else ApprovalDecision.model_validate(raw_decision)
    )

    # Hard gate: only explicitly listed, in-range indices count, and only when approved.
    approved_indices: set[int] = set()
    if decision.status == ApprovalStatus.APPROVED:
        approved_indices = {i for i in decision.approved_patch_indices if 0 <= i < len(patches)}

    now = datetime.utcnow()
    updated: list[Patch] = []
    for i, p in enumerate(patches):
        if i in approved_indices:
            updated.append(
                p.model_copy(
                    update={"approved": True, "approved_by": decision.reviewed_by, "approved_at": now}
                )
            )
        else:
            updated.append(p.model_copy(update={"approved": False, "approved_by": None, "approved_at": None}))

    approved = [p for p in updated if p.approved]

    if decision.status == ApprovalStatus.ESCALATED:
        status = ApprovalStatus.ESCALATED
    elif approved:
        status = ApprovalStatus.APPROVED
    else:
        status = ApprovalStatus.REJECTED

    logger.info(
        "approval_decision",
        status=str(status),
        approved=len(approved),
        total=len(patches),
        reviewed_by=decision.reviewed_by,
    )

    return {
        "stage": PipelineStage.HUMAN_APPROVAL,
        "patches": updated,
        "patch_proposals": updated,
        "approved_patches": approved,
        "approval_decision": decision,
        "approval_status": status,
    }


def node_report(state: ReviewState) -> dict[str, Any]:
    """Report step: Synthesizes findings, regressions, root causes, patches, and verdict."""
    return run_reporter_agent(state)


# ── Graph Builder ─────────────────────────────────────────────────────────────


def build_graph() -> StateGraph:
    """
    Build LangGraph review workflow:
    ingest → impact → merge_simulation → [security || dependency] → triage
           → review → rca → fix → approval → report
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
    g.add_node("approval", node_approval)
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

    g.add_edge("triage", "review")
    g.add_edge("review", "rca")
    g.add_edge("rca", "fix")
    g.add_edge("fix", "approval")
    g.add_edge("approval", "report")
    g.add_edge("report", END)

    return g


# No-pause graph: identical behaviour to Week 5 (approval step passes straight through).
_graph = build_graph().compile()

# Pausable graph: needs a checkpointer so a paused run can be resumed later.
_checkpointer = InMemorySaver()
_hitl_graph = build_graph().compile(checkpointer=_checkpointer)


def _config(thread_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread_id}}


def _snapshot(thread_id: str) -> dict[str, Any]:
    """Return where a pausable run currently stands."""
    snap = _hitl_graph.get_state(_config(thread_id))
    pending: Any = None
    for task in snap.tasks:
        if task.interrupts:
            pending = task.interrupts[0].value
            break
    return {
        "thread_id": thread_id,
        "paused": bool(snap.next),
        "pending_approval": pending,
        "state": snap.values,
    }


def run_review(changeset: ChangeSet) -> ReviewState:
    """Execute the review pipeline without pausing and return the final ReviewState."""
    initial = make_initial_state(changeset, require_approval=False)
    final: ReviewState = _graph.invoke(initial)  # type: ignore[assignment]
    return final


def start_review(changeset: ChangeSet) -> dict[str, Any]:
    """
    Run the pipeline in approval mode.

    Returns {"thread_id", "paused", "pending_approval", "state"}.
    If "paused" is True, show "pending_approval" to the human, then call resume_review().
    """
    thread_id = uuid.uuid4().hex
    initial = make_initial_state(changeset, require_approval=True)
    initial["thread_id"] = thread_id
    _hitl_graph.invoke(initial, config=_config(thread_id))
    return _snapshot(thread_id)


def resume_review(thread_id: str, decision: ApprovalDecision) -> dict[str, Any]:
    """Resume a paused run with the human's decision and run it to the end."""
    current = _hitl_graph.get_state(_config(thread_id))
    if not current.next:
        raise ValueError(f"No paused review found for thread_id={thread_id!r}")

    _hitl_graph.invoke(
        Command(resume=decision.model_dump(mode="json")),
        config=_config(thread_id),
    )
    return _snapshot(thread_id)