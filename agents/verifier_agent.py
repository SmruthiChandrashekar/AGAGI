"""
agents/verifier_agent.py
------------------------
Verifier Agent (Week 6):
  - Runs only after a human approved one or more patches
  - Builds a fresh, throwaway copy of the merged code (base + head) and applies
    ONLY the approved patches there; the user's own files are never touched
  - Re-runs the full test suite and the security scanners on the patched code
  - Verified = every patch applied, the code builds, no test fails that was not
    already failing on the base branch, and the scanners find nothing new while
    the targeted findings are gone
  - On failure, writes plain-English feedback that RCA and the fix generator use
    on the next attempt, and counts the attempt toward the retry limit
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agents.merge_sim_agent import _is_build_error, _run_test_suite_in_sandbox
from tools.test_env import get_test_timeout
from core.audit import record_for_state
from core.logging import get_logger
from core.state import (
    Finding,
    Patch,
    PipelineStage,
    ReviewState,
    Severity,
    SimulationResult,
    TestCaseResult,
    VerifierOutput,
)
from tools.bandit_runner import run_bandit
from tools.git_ops import apply_patch, cleanup_worktree, create_merged_worktree, create_worktree
from tools.gitleaks_runner import run_gitleaks
from tools.semgrep_runner import run_semgrep

logger = get_logger(__name__)

VERIFY_TEST_TIMEOUT_SECONDS = 90
_SERIOUS = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


def _as_model(cls: Any, value: Any) -> Any:
    """State values may come back from the checkpointer as dicts; normalise them."""
    return value if isinstance(value, cls) else cls.model_validate(value)


def _finding_key(f: Finding) -> tuple[str, str]:
    return ((f.file or "").replace("\\", "/"), f.rule_id or f.title)


def _scan_files(workspace: Path, files: list[str]) -> list[Finding]:
    """Run every available scanner on the given files. A scanner that is missing is skipped."""
    found: list[Finding] = []
    for name, runner in (("semgrep", run_semgrep), ("gitleaks", run_gitleaks), ("bandit", run_bandit)):
        targets = files if name != "bandit" else [f for f in files if f.endswith(".py")]
        if not targets:
            continue
        try:
            found.extend(runner(workspace, targets))
        except Exception as exc:
            logger.info("verifier_scanner_skipped", scanner=name, error=str(exc)[:200])
    return found


def _build_feedback(
    apply_errors: list[str],
    build_error: str,
    timed_out: bool,
    still_failing: list[TestCaseResult],
    new_issues: list[Finding],
    unresolved: list[Finding],
    patches: list[Patch],
) -> str:
    """Plain-English summary of why verification failed, for the next RCA/fix attempt."""
    parts: list[str] = []
    if apply_errors:
        parts.append("Patch did not apply to the merged code:\n" + "\n".join(apply_errors))
    if build_error:
        parts.append(f"Code no longer builds or imports after the patch:\n{build_error[-1200:]}")
    if timed_out:
        parts.append("The test suite timed out after the patch was applied.")
    if still_failing:
        lines = [f"- {t.name}: {t.error_message or 'failed'}" for t in still_failing[:10]]
        parts.append("Tests still failing after the patch:\n" + "\n".join(lines))
    if new_issues:
        lines = [f"- {f.file}:{f.line} {f.rule_id or f.title}" for f in new_issues[:10]]
        parts.append("The patch introduced new security findings:\n" + "\n".join(lines))
    if unresolved:
        lines = [f"- {f.file}:{f.line} {f.rule_id or f.title}" for f in unresolved[:10]]
        parts.append("The targeted security findings are still present:\n" + "\n".join(lines))
    tried = "\n\n".join(f"Patch for {', '.join(p.target_files)}:\n{p.unified_diff}" for p in patches)
    parts.append("Patch(es) that were tried:\n" + tried[:2500])
    return "\n\n".join(parts)


def run_verifier_agent(state: ReviewState) -> dict[str, Any]:
    """Apply approved patches in a throwaway merged copy and re-validate everything."""
    logger.info("stage_start", stage="verifier_agent", iteration=state.get("iteration_count", 0))

    cs = state.get("changeset")
    approved = [_as_model(Patch, p) for p in (state.get("approved_patches") or [])]
    iteration = int(state.get("iteration_count") or 0)
    history = list(state.get("verification_history") or [])

    if not cs or not approved:
        out = VerifierOutput(verified=False, summary="Nothing to verify: no approved patches.")
        return {"stage": PipelineStage.APPLY_AND_VERIFY, "verifier_output": out}

    pre_existing = [_as_model(TestCaseResult, t) for t in (state.get("pre_existing_failures") or [])]
    baseline_failing = {t.test_id for t in pre_existing} | {t.name for t in pre_existing}

    original_findings = [
        _as_model(Finding, f) for f in (state.get("findings") or [])
    ]
    original_findings = [f for f in original_findings if not f.is_false_positive]
    targeted_ids = {p.finding_id for p in approved if p.finding_id}
    targeted_findings = [f for f in original_findings if f.id in targeted_ids]
    # Everything the scanners reported before the patch, including findings triage
    # dismissed, so an old warning is never mistaken for one the patch introduced.
    seen_before = [
        _as_model(Finding, f)
        for key in ("security_findings", "triaged_findings", "findings")
        for f in (state.get(key) or [])
    ]
    before_keys = {_finding_key(f) for f in seen_before}

    patched_files = sorted({f.replace("\\", "/") for p in approved for f in p.target_files})

    applied: list[str] = []
    apply_errors: list[str] = []
    build_error = ""
    timed_out = False
    still_failing: list[TestCaseResult] = []
    all_cases: list[TestCaseResult] = []
    new_issues: list[Finding] = []
    unresolved: list[Finding] = []
    test_log = ""

    try:
        wt = create_merged_worktree(cs.repo_path, cs.base_ref, cs.head_ref)
    except Exception as exc:
        logger.info("verifier_merge_unavailable_using_head", error=str(exc)[:200])
        wt = create_worktree(cs.repo_path, cs.head_ref)

    try:
        # 1. Apply only what the human approved
        for p in approved:
            ok, err = apply_patch(wt, p.unified_diff)
            label = ", ".join(p.target_files) or "patch"
            if ok:
                applied.append(label)
            else:
                apply_errors.append(f"- {label}: {err[:400]}")

        if not apply_errors:
            # 2. Full test suite on the patched code
            code, out, err, timed_out, all_cases = _run_test_suite_in_sandbox(
                wt, timeout_seconds=max(VERIFY_TEST_TIMEOUT_SECONDS, get_test_timeout()),
                xml_name=".verify_junit.xml", repo_path=cs.repo_path,
            )
            test_log = f"{out}\n{err}".strip()
            if not timed_out and ((code == 2 and not all_cases) or _is_build_error(out, err)):
                build_error = test_log or "build error"
            for tc in all_cases:
                if tc.status in ("failed", "error") and tc.test_id not in baseline_failing and tc.name not in baseline_failing:
                    still_failing.append(tc)
            if code not in (0, 5) and not all_cases and not build_error and not timed_out:
                build_error = test_log or f"test command exited with code {code}"

            # 3. Scanners on the files the patches touched
            after = _scan_files(wt, patched_files)
            after_keys = {_finding_key(f) for f in after}
            new_issues = [
                f for f in after if _finding_key(f) not in before_keys and f.severity in _SERIOUS
            ]
            unresolved = [f for f in targeted_findings if _finding_key(f) in after_keys]
    finally:
        cleanup_worktree(cs.repo_path, wt)

    tests_passed = not apply_errors and not build_error and not timed_out and not still_failing
    scanners_passed = not apply_errors and not new_issues and not unresolved
    verified = tests_passed and scanners_passed

    if verified:
        summary = (
            f"Verified: {len(applied)} approved patch(es) applied to a fresh merged copy; "
            f"{len(all_cases)} test(s) ran with no new failures and the scanners found nothing new."
        )
        feedback = None
    else:
        reasons = []
        if apply_errors:
            reasons.append("patch did not apply")
        if build_error:
            reasons.append("build error")
        if timed_out:
            reasons.append("tests timed out")
        if still_failing:
            reasons.append(f"{len(still_failing)} test(s) still failing")
        if new_issues:
            reasons.append(f"{len(new_issues)} new security finding(s)")
        if unresolved:
            reasons.append(f"{len(unresolved)} targeted finding(s) not fixed")
        summary = "Verification failed: " + ", ".join(reasons) + "."
        feedback = _build_feedback(
            apply_errors, build_error, timed_out, still_failing, new_issues, unresolved, approved
        )

    vo = VerifierOutput(
        verified=verified,
        patches_applied=applied,
        build_passed=not apply_errors and not build_error,
        tests_passed=tests_passed,
        scanners_passed=scanners_passed,
        regressions_detected=[t.name for t in still_failing],
        summary=summary,
    )
    sim = SimulationResult(
        success=verified,
        status="passed" if tests_passed else ("build error" if (build_error or apply_errors) else "test failure"),
        build_passed=vo.build_passed,
        tests_passed=tests_passed,
        failing_tests=[t.name for t in still_failing],
        regressions=still_failing,
        all_tests=all_cases,
        build_log_snippet=(build_error or "\n".join(apply_errors))[-2000:],
        test_log_snippet=test_log[-2500:],
    )

    attempt = {
        "attempt": iteration + 1,
        "verified": verified,
        "summary": summary,
        "patched_files": patched_files,
        "failing_tests": [t.name for t in still_failing],
        "new_findings": [f"{f.file}:{f.line} {f.rule_id or f.title}" for f in new_issues],
        "unresolved_findings": [f"{f.file}:{f.line} {f.rule_id or f.title}" for f in unresolved],
    }
    history.append(attempt)

    logger.info("verifier_agent_complete", verified=verified, attempt=iteration + 1, summary=summary)
    record_for_state(dict(state), "verification", **attempt)

    next_iteration = iteration if verified else iteration + 1
    return {
        "stage": PipelineStage.APPLY_AND_VERIFY,
        "verifier_output": vo,
        "verification_result": sim,
        "verification_feedback": feedback,
        "verification_history": history,
        "iteration_count": next_iteration,
        "iteration": next_iteration,
    }
