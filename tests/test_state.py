"""Smoke tests for the ReviewState schema."""
from __future__ import annotations

from pathlib import Path

from core.state import ChangeSet, PipelineStage, make_initial_state


def test_make_initial_state_sets_stage() -> None:
    cs = ChangeSet(repo_path=Path("/tmp"), base_ref="main", head_ref="HEAD")
    state = make_initial_state(cs)
    assert state["stage"] == PipelineStage.INIT


def test_make_initial_state_empty_findings() -> None:
    cs = ChangeSet(repo_path=Path("/tmp"), base_ref="main", head_ref="dev")
    state = make_initial_state(cs)
    assert state["review_findings"] == []
    assert state["security_findings"] == []
    assert state["dependency_findings"] == []


def test_changeset_fields() -> None:
    cs = ChangeSet(repo_path=Path("."), base_ref="v1.0", head_ref="feature/x", pr_number=42)
    assert cs.pr_number == 42
    assert cs.base_ref == "v1.0"
