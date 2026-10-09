"""
Week 6 end-to-end tests on the real calculator demo repo.

The AI is replaced by scripted answers so the tests are repeatable; everything else
is real: git worktrees and merges, the test runs, the Bandit scan, the approval
pause/resume, the Verifier and the retry loop.
"""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import core.audit as audit_mod
import core.orchestrator as orch
from agents.fix_agent import GeneratedPatchOutput
from agents.review_agent import CodeReviewOutput
from core.audit import AuditLog
from core.state import ApprovalDecision, ApprovalStatus, ChangeSet, ReviewVerdict
from tools.build_calc_demo import build_calc_demo
from tools.git_ops import cleanup_worktree, create_merged_worktree


@pytest.fixture(scope="module")
def calc_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_calc_demo(tmp_path_factory.mktemp("demo") / "calculator")


@pytest.fixture(autouse=True)
def isolated_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AuditLog:
    log = AuditLog(tmp_path / "audit.db")
    monkeypatch.setattr(audit_mod, "audit_log", log)
    return log


def _merged_file(repo: Path, branch: str, rel: str) -> str:
    wt = create_merged_worktree(repo, "main", branch)
    try:
        return (wt / rel).read_text(encoding="utf-8")
    finally:
        cleanup_worktree(repo, wt)


def _diff(rel: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
    )


def _ai_down(*_a: Any, **_k: Any) -> Any:
    raise RuntimeError("AI unavailable in tests")


def _mocks(fix_outputs: list[GeneratedPatchOutput]) -> list[Any]:
    """Review says 'clean', triage and RCA fall back to rules, fix returns scripted patches."""
    outputs = iter(fix_outputs)

    def fix_side_effect(*_a: Any, **_k: Any) -> GeneratedPatchOutput:
        return next(outputs)

    return [
        patch("agents.review_agent.chat_structured", return_value=CodeReviewOutput(issues=[], summary="ok")),
        patch("agents.triage_agent.chat_structured", side_effect=_ai_down),
        patch("agents.rca_agent.chat_structured", side_effect=_ai_down),
        patch("agents.fix_agent.chat_structured", side_effect=fix_side_effect),
    ]


def _run(mocks: list[Any], fn: Any, *args: Any) -> Any:
    for m in mocks:
        m.start()
    try:
        return fn(*args)
    finally:
        for m in mocks:
            m.stop()


def _good_breaks_test_patch(repo: Path) -> GeneratedPatchOutput:
    merged = _merged_file(repo, "breaks-test", "calc.py")
    fixed = merged.replace("def average(nums, round_to):", "def average(nums, round_to=2):")
    assert fixed != merged
    return GeneratedPatchOutput(unified_diff=_diff("calc.py", merged, fixed), rationale="Default round_to")


def _useless_breaks_test_patch(repo: Path) -> GeneratedPatchOutput:
    merged = _merged_file(repo, "breaks-test", "calc.py")
    changed = merged.replace('"""Calculate rounded average."""', '"""Calculate a rounded average."""')
    return GeneratedPatchOutput(unified_diff=_diff("calc.py", merged, changed), rationale="Docstring only")


def _approve(thread_id: str, indices: list[int]) -> dict[str, Any]:
    decision = ApprovalDecision(
        status=ApprovalStatus.APPROVED, approved_patch_indices=indices, reviewed_by="sarthak"
    )
    return orch.resume_review(thread_id, decision)


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_breaks_test_rca_blames_changed_definition(calc_repo: Path) -> None:
    mocks = _mocks([_good_breaks_test_patch(calc_repo)])
    run = _run(mocks, orch.start_review, ChangeSet(repo_path=calc_repo, base_ref="main", head_ref="breaks-test"))

    assert run["paused"] is True
    rcs = run["state"]["root_causes"]
    assert len(rcs) == 1
    assert rcs[0].root_cause_file == "calc.py"
    assert set(rcs[0].related_tests) == {"test_average", "test_generate_report"}
    assert run["pending_approval"]["patches"][0]["target_files"] == ["calc.py"]


def test_approved_fix_is_verified_and_files_untouched(calc_repo: Path, isolated_audit: AuditLog) -> None:
    before = (calc_repo / "calc.py").read_text(encoding="utf-8")
    mocks = _mocks([_good_breaks_test_patch(calc_repo)])
    cs = ChangeSet(repo_path=calc_repo, base_ref="main", head_ref="breaks-test")

    run = _run(mocks, orch.start_review, cs)
    final = _run(mocks, _approve, run["thread_id"], [0])
    s = final["state"]

    assert final["paused"] is False
    assert s["verifier_output"].verified is True
    assert s["verifier_output"].tests_passed is True
    assert s["verification_history"][0]["verified"] is True
    assert s["escalated"] is False
    assert "## 7. Human Approval & Verification" in s["report_markdown"]
    assert "verified on a copy of the merged code" in s["report_markdown"]
    # The user's own checkout is never modified
    assert (calc_repo / "calc.py").read_text(encoding="utf-8") == before

    events = [e["event"] for e in isolated_audit.events(run["thread_id"])]
    assert "approval_decision" in events and "verification" in events


def test_rejected_fix_is_never_verified(calc_repo: Path, isolated_audit: AuditLog) -> None:
    mocks = _mocks([_good_breaks_test_patch(calc_repo)])
    run = _run(mocks, orch.start_review, ChangeSet(repo_path=calc_repo, base_ref="main", head_ref="breaks-test"))

    decision = ApprovalDecision(status=ApprovalStatus.REJECTED, approved_patch_indices=[0], reviewed_by="sarthak")
    final = _run(mocks, orch.resume_review, run["thread_id"], decision)
    s = final["state"]

    assert final["paused"] is False
    assert s["approval_status"] == ApprovalStatus.REJECTED
    assert s["approved_patches"] == []
    assert not s.get("verification_history")
    assert s["verdict"] == ReviewVerdict.NEEDS_CHANGES
    assert [e["details"]["status"] for e in isolated_audit.events(run["thread_id"])] == ["rejected"]


def test_failed_fix_retries_then_escalates(calc_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orch.settings, "max_fix_iterations", 2)
    useless = _useless_breaks_test_patch(calc_repo)
    mocks = _mocks([useless, useless, useless])
    cs = ChangeSet(repo_path=calc_repo, base_ref="main", head_ref="breaks-test")

    run = _run(mocks, orch.start_review, cs)
    assert run["pending_approval"]["attempt"] == 1

    second = _run(mocks, _approve, run["thread_id"], [0])
    # The first fix failed verification, so a new fix is proposed and needs approval again
    assert second["paused"] is True
    assert second["pending_approval"]["attempt"] == 2
    assert "still failing" in (second["pending_approval"]["previous_failure"] or "")

    final = _run(mocks, _approve, run["thread_id"], [0])
    s = final["state"]
    assert final["paused"] is False
    assert len(s["verification_history"]) == 2
    assert not any(h["verified"] for h in s["verification_history"])
    assert s["escalated"] is True
    assert s["verdict"] == ReviewVerdict.ESCALATED
    assert "Escalated" in s["report_markdown"]


def test_unsafe_eval_fix_clears_scanner_finding(calc_repo: Path) -> None:
    merged = _merged_file(calc_repo, "unsafe-eval", "calc.py")
    fixed = merged.replace("    return eval(expr)", "    return ast.literal_eval(expr)")
    fixed = fixed.replace('"""Basic arithmetic functions with docstrings."""\n',
                          '"""Basic arithmetic functions with docstrings."""\nimport ast\n', 1)
    assert fixed != merged
    good = GeneratedPatchOutput(unified_diff=_diff("calc.py", merged, fixed), rationale="No eval")

    mocks = _mocks([good])
    run = _run(mocks, orch.start_review, ChangeSet(repo_path=calc_repo, base_ref="main", head_ref="unsafe-eval"))

    findings = run["state"]["findings"]
    if not findings:
        pytest.skip("No scanner flagged eval in this environment (bandit/semgrep unavailable)")
    assert run["paused"] is True

    final = _run(mocks, _approve, run["thread_id"], [0])
    vo = final["state"]["verifier_output"]
    assert vo.scanners_passed is True, final["state"]["verification_history"]
    assert vo.verified is True


def test_run_review_never_pauses_or_verifies(calc_repo: Path) -> None:
    mocks = _mocks([_good_breaks_test_patch(calc_repo)])
    s = _run(mocks, orch.run_review, ChangeSet(repo_path=calc_repo, base_ref="main", head_ref="breaks-test"))
    assert s["verdict"] == ReviewVerdict.NEEDS_CHANGES
    assert len(s["patches"]) == 1
    assert s["approved_patches"] == []
    assert not s.get("verification_history")


def test_approval_endpoints_end_to_end(calc_repo: Path) -> None:
    from fastapi.testclient import TestClient

    from ui.server import app

    client = TestClient(app)
    assert client.get("/approve").status_code == 200
    status = client.get("/api/status").json()
    assert "demo_repo_path" in status and "llm_ready" in status

    mocks = _mocks([_good_breaks_test_patch(calc_repo)])
    body = {"repo_path": str(calc_repo), "base_ref": "main", "head_ref": "breaks-test"}

    started = _run(mocks, lambda: client.post("/api/review/start", json=body))
    assert started.status_code == 200, started.text
    data = started.json()
    assert data["paused"] is True
    assert data["pending_approval"]["patches"][0]["target_files"] == ["calc.py"]

    decided = _run(
        mocks,
        lambda: client.post(
            f"/api/review/{data['thread_id']}/decision",
            json={"approve": True, "approved_patch_indices": [0], "reviewed_by": "sarthak"},
        ),
    )
    assert decided.status_code == 200, decided.text
    result = decided.json()
    assert result["paused"] is False
    assert result["verifier_output"]["verified"] is True
    assert result["approved_patches"][0]["approved_by"] == "sarthak"

    audit = client.get(f"/api/review/{data['thread_id']}/audit").json()["events"]
    assert {e["event"] for e in audit} >= {"approval_decision", "verification"}

    # Resuming a finished run is a clean 404, not a crash
    again = client.post(f"/api/review/{data['thread_id']}/decision", json={"approve": False})
    assert again.status_code == 404
