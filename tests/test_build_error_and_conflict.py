"""Build failures get a root cause, and conflicting branches get no patch (no AI needed)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import core.audit as audit_mod
import core.orchestrator as orch
from agents.fix_agent import run_fix_agent
from agents.rca_agent import _build_failure_cause
from core.audit import AuditLog
from core.state import ChangeSet
from tools.build_calc_demo import build_calc_demo

SAMPLE_LOG = """\
test_calc.py:2: in <module>
    from calc import add, subtract, average
E     File "/tmp/worktree_x/calc.py", line 21
E       return +++  # Syntax error
E                   ^^^^^^^^^^^^^^^
E   SyntaxError: invalid syntax
"""


@pytest.fixture(scope="module")
def calc_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_calc_demo(tmp_path_factory.mktemp("demo") / "calculator")


@pytest.fixture(autouse=True)
def isolated_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AuditLog:
    log = AuditLog(tmp_path / "audit.db")
    monkeypatch.setattr(audit_mod, "audit_log", log)
    return log


def _ai_down(*_a: Any, **_k: Any) -> Any:
    raise RuntimeError("AI unavailable in tests")


def _run_without_ai(repo: Path, branch: str) -> dict[str, Any]:
    mocks = [
        patch("agents.review_agent.chat_structured", side_effect=_ai_down),
        patch("agents.triage_agent.chat_structured", side_effect=_ai_down),
        patch("agents.rca_agent.chat_structured", side_effect=_ai_down),
        patch("agents.fix_agent.chat_structured", side_effect=_ai_down),
    ]
    for m in mocks:
        m.start()
    try:
        return dict(orch.run_review(ChangeSet(repo_path=repo, base_ref="main", head_ref=branch)))
    finally:
        for m in mocks:
            m.stop()


def test_build_failure_cause_names_file_line_and_error(tmp_path: Path) -> None:
    (tmp_path / "calc.py").write_text("x = 1\n", encoding="utf-8")
    rc = _build_failure_cause(SAMPLE_LOG, tmp_path)
    assert rc is not None
    assert rc.root_cause_file == "calc.py"
    assert rc.root_cause_line == 21
    assert "SyntaxError: invalid syntax" in rc.explanation


def test_build_failure_cause_ignores_library_frames(tmp_path: Path) -> None:
    log = 'E  File "/venv/lib/python3.11/site-packages/_pytest/x.py", line 5\nE  ImportError: boom\n'
    assert _build_failure_cause(log, tmp_path) is None


def test_build_error_branch_gets_root_cause_without_ai(calc_repo: Path) -> None:
    s = _run_without_ai(calc_repo, "build-error")
    assert s["merge_outcome"] == "build error"
    rcs = s["root_causes"]
    assert len(rcs) == 1
    assert rcs[0].root_cause_file == "calc.py"
    assert rcs[0].root_cause_line is not None


def test_conflict_branch_gets_no_patch(calc_repo: Path) -> None:
    s = _run_without_ai(calc_repo, "conflict")
    assert s["merge_outcome"] == "conflict"
    assert s["patches"] == []


def test_fix_agent_skips_on_merge_conflict() -> None:
    out = run_fix_agent(
        {"merge_outcome": "conflict", "root_causes": [{"root_cause_file": "calc.py", "explanation": "x"}]}  # type: ignore[typeddict-item]
    )
    assert out == {"patches": [], "patch_proposals": []}
