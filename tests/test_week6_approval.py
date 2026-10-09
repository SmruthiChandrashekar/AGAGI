"""Week 6 Days 1-2: human approval gate tests (no LLM, no git)."""

from __future__ import annotations

import uuid

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import Command

import core.audit as audit_mod
from core.audit import AuditLog
from core.orchestrator import node_approval
from core.state import ApprovalDecision, ApprovalStatus, Patch, ReviewState


@pytest.fixture(autouse=True)
def isolated_audit(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(audit_mod, "audit_log", AuditLog(tmp_path / "audit.db"))


def _mini_graph():  # type: ignore[no-untyped-def]
    g = StateGraph(ReviewState)
    g.add_node("approval", node_approval)
    g.set_entry_point("approval")
    g.add_edge("approval", END)
    return g.compile(checkpointer=InMemorySaver())


def _cfg() -> dict:
    return {"configurable": {"thread_id": uuid.uuid4().hex}}


def _patch(name: str) -> Patch:
    return Patch(
        unified_diff=f"--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-x\n+y\n",
        rationale=f"fix {name}",
        target_files=[name],
    )


def test_approval_skipped_when_not_required() -> None:
    g, cfg = _mini_graph(), _cfg()
    out = g.invoke({"patches": [_patch("a.py")], "require_approval": False}, cfg)
    assert g.get_state(cfg).next == ()
    assert not any(p.approved for p in out["patches"])
    assert out["approved_patches"] == []


def test_approval_skipped_when_no_patches() -> None:
    g, cfg = _mini_graph(), _cfg()
    g.invoke({"patches": [], "require_approval": True}, cfg)
    assert g.get_state(cfg).next == ()


def test_approval_pauses_then_applies_only_chosen_patches() -> None:
    g, cfg = _mini_graph(), _cfg()
    g.invoke({"patches": [_patch("a.py"), _patch("b.py")], "require_approval": True}, cfg)

    snap = g.get_state(cfg)
    assert snap.next == ("approval",)
    payload = snap.tasks[0].interrupts[0].value
    assert len(payload["patches"]) == 2

    decision = ApprovalDecision(
        status=ApprovalStatus.APPROVED, approved_patch_indices=[1], reviewed_by="sarthak"
    )
    out = g.invoke(Command(resume=decision.model_dump(mode="json")), cfg)

    assert out["approval_status"] == ApprovalStatus.APPROVED
    assert [p.approved for p in out["patches"]] == [False, True]
    assert len(out["approved_patches"]) == 1
    assert out["approved_patches"][0].approved_by == "sarthak"


def test_reject_approves_nothing_even_if_indices_given() -> None:
    g, cfg = _mini_graph(), _cfg()
    g.invoke({"patches": [_patch("a.py")], "require_approval": True}, cfg)

    decision = ApprovalDecision(status=ApprovalStatus.REJECTED, approved_patch_indices=[0])
    out = g.invoke(Command(resume=decision.model_dump(mode="json")), cfg)

    assert out["approval_status"] == ApprovalStatus.REJECTED
    assert out["approved_patches"] == []
    assert not out["patches"][0].approved


def test_out_of_range_index_is_ignored() -> None:
    g, cfg = _mini_graph(), _cfg()
    g.invoke({"patches": [_patch("a.py")], "require_approval": True}, cfg)

    decision = ApprovalDecision(status=ApprovalStatus.APPROVED, approved_patch_indices=[5])
    out = g.invoke(Command(resume=decision.model_dump(mode="json")), cfg)

    assert out["approval_status"] == ApprovalStatus.REJECTED
    assert out["approved_patches"] == []
