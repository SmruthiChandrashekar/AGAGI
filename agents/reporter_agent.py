"""
agents/reporter_agent.py
------------------------
Reporter Agent:
  - Aggregates changed files, blast radius, merge outcome, test regressions, and security findings
  - Groups triaged findings by severity with LLM explanations and suggested fixes
  - Incorporates code review comments, root-cause analyses, and validated proposed patches
  - Makes critical confirmed findings and unresolved regressions blockers in the review verdict
  - Generates comprehensive Markdown and JSON reports
"""

from __future__ import annotations

from typing import Any

from core.logging import get_logger
from core.state import (
    Finding,
    Patch,
    PipelineStage,
    ReviewState,
    ReviewVerdict,
    RootCause,
    Severity,
)

logger = get_logger(__name__)


def run_reporter_agent(state: ReviewState) -> dict[str, Any]:
    """
    Format findings, simulation results, root causes, and patches into a final report.
    """
    logger.info("stage_start", stage="reporter_agent")
    cs = state.get("changeset")
    merge_outcome = state.get("merge_outcome", "all passed")
    merge_res = state.get("merge_result")
    affected_files = state.get("affected_files", [])
    blast_radius = state.get("blast_radius_score", 0.0)
    findings = state.get("findings", state.get("all_findings", []))
    review_findings = state.get("review_findings", [])
    root_causes: list[RootCause] = state.get("root_causes", [])
    patches: list[Patch] = state.get("patches", state.get("patch_proposals", []))
    conflicted_files = state.get("conflicted_files", [])
    test_results = state.get("test_results", {})

    regressions = state.get("regressions") or (merge_res.regressions if merge_res else [])
    pre_existing = state.get("pre_existing_failures") or (merge_res.pre_existing_failures if merge_res else [])

    # Filter confirmed findings vs false positives
    confirmed = [f for f in findings if not f.is_false_positive]
    confirmed_critical = [f for f in confirmed if f.severity == Severity.CRITICAL]
    confirmed_high = [f for f in confirmed if f.severity == Severity.HIGH]
    confirmed_other = [f for f in confirmed if f.severity not in (Severity.CRITICAL, Severity.HIGH)]

    # ── Compute Verdict & Risk Score ─────────────────────────────────────────
    # Rule 1: Conflicts, timeouts, and confirmed critical security findings are hard BLOCKERS
    if merge_outcome == "conflict":
        verdict = ReviewVerdict.BLOCKED
        risk_score = 10.0
    elif confirmed_critical:
        verdict = ReviewVerdict.BLOCKED
        risk_score = 9.8
    elif merge_outcome == "timeout":
        verdict = ReviewVerdict.BLOCKED
        risk_score = 8.0
    elif merge_outcome in ("build error", "install error"):
        verdict = ReviewVerdict.NEEDS_CHANGES
        risk_score = 8.5
    elif merge_outcome in ("test failure", "tests failed") or bool(regressions):
        verdict = ReviewVerdict.NEEDS_CHANGES
        risk_score = 7.5
    elif confirmed_high or confirmed_other or bool(review_findings):
        verdict = ReviewVerdict.NEEDS_CHANGES
        risk_score = min(
            8.5,
            round(4.0 + len(confirmed_high) * 1.5 + len(confirmed_other) * 0.5 + len(review_findings) * 0.5, 1),
        )
    else:
        verdict = ReviewVerdict.SAFE
        risk_score = round(min(3.0, blast_radius * 3.0), 1)

    # Week 6: approval / verification outcome
    escalated = bool(state.get("escalated"))
    verifier_output = state.get("verifier_output")
    verification_history: list[dict[str, Any]] = state.get("verification_history") or []
    approval_status = state.get("approval_status")
    approval_decision = state.get("approval_decision")
    approved_patches: list[Patch] = state.get("approved_patches") or []
    if escalated:
        verdict = ReviewVerdict.ESCALATED

    # ── Format Markdown Report ───────────────────────────────────────────────
    status_badges = {
        "passed": "[PASS] ALL PASSED",
        "all passed": "[PASS] ALL PASSED",
        "conflict": "[FAIL] MERGE CONFLICT",
        "install error": "[FAIL] INSTALL ERROR",
        "build error": "[FAIL] BUILD ERROR",
        "timeout": "[FAIL] TIMEOUT",
        "test failure": "[FAIL] TEST FAILURE",
        "tests failed": "[FAIL] TEST FAILURE",
    }
    badge = status_badges.get(merge_outcome, (merge_outcome or "").upper())

    report_lines: list[str] = [
        f"# AGENTIC REVIEW REPORT // {badge}",
        "",
        f"**Repository:** `{cs.repo_path if cs else 'unknown'}`",
        f"**Base Ref:** `{cs.base_ref if cs else 'unknown'}` | **Head Ref:** `{cs.head_ref if cs else 'unknown'}`",
        f"**Verdict:** `{verdict.value.upper()}` | **Risk Score:** `{risk_score}/10.0` | **Blast Radius:** `{blast_radius}`",
        "",
        "## 1. Merge Simulation Status",
        f"- **Simulation Outcome:** `{(merge_outcome or 'UNKNOWN').upper()}`",
    ]

    if merge_res:
        report_lines.append(f"- **Build Passed:** {merge_res.build_passed}")
        report_lines.append(f"- **Tests Passed:** {merge_res.tests_passed}")

    if regressions:
        report_lines.append(f"- **New Regressions ({len(regressions)}) [BLOCKERS]:**")
        for reg in regressions:
            loc = f" (`{reg.failing_file}:{reg.failing_line}`)" if reg.failing_file and reg.failing_line else ""
            err = f" - {reg.error_message}" if reg.error_message else ""
            report_lines.append(f"  - ❌ `{reg.name}`{loc}{err}")

    if pre_existing:
        report_lines.append(f"- **Pre-existing Failures on `{cs.base_ref if cs else 'main'}` ({len(pre_existing)}) [NOT BLAMED ON PR]:**")
        for pe in pre_existing:
            report_lines.append(f"  - ⚠️ `{pe.name}` (already failing on baseline)")

    if conflicted_files:
        report_lines.append(f"- **Conflicted Files ({len(conflicted_files)}):**")
        for cf in conflicted_files:
            report_lines.append(f"  - `{cf}`")

    # Impact Section
    risk_hint = state.get("risk_hint")
    graph_summary = state.get("graph_summary") or {}
    changed_functions = state.get("changed_functions") or []
    affected_tests = state.get("affected_tests") or []

    report_lines.extend([
        "",
        "## 2. Impact Analysis & Blast Radius",
    ])

    if graph_summary:
        report_lines.append(
            f"- **Graph Summary:** {graph_summary.get('files', 0)} files, {graph_summary.get('symbols', 0)} symbols, {graph_summary.get('tests', 0)} tests, {graph_summary.get('edges', 0)} dependency edges"
        )

    if risk_hint:
        report_lines.append(f"- **Risk Hint:** {risk_hint}")

    if changed_functions:
        report_lines.append("- **Changed Functions / Entities:**")
        for cf in changed_functions[:10]:
            name = cf.get("name") if isinstance(cf, dict) else str(cf)
            file_name = cf.get("file", "") if isinstance(cf, dict) else ""
            report_lines.append(f"  - `{file_name}:{name}`" if file_name else f"  - `{name}`")

    if affected_tests:
        report_lines.append(f"- **Affected Test Targets ({len(affected_tests)}):**")
        for at in affected_tests:
            report_lines.append(f"  - `{at}`")

    report_lines.extend([
        "",
        f"### Affected Files ({len(affected_files)}):",
    ])
    if affected_files:
        for f in affected_files[:25]:
            report_lines.append(f"- `{f}`")
        if len(affected_files) > 25:
            report_lines.append(f"- _... and {len(affected_files) - 25} more files_")
    else:
        report_lines.append("_No file modifications detected._")

    # Security & Vulnerability Findings Section
    report_lines.extend([
        "",
        f"## 3. Security & Dependency Findings ({len(confirmed)} confirmed issues)",
    ])

    if not confirmed:
        report_lines.append("No security vulnerabilities or vulnerable dependencies detected in this pull request.")
    else:
        groups: list[tuple[str, list[Finding]]] = [
            ("🚨 CRITICAL FINDINGS [MERGE BLOCKERS]", confirmed_critical),
            ("⚠️ HIGH SEVERITY FINDINGS", confirmed_high),
            ("ℹ️ MEDIUM / LOW FINDINGS", confirmed_other),
        ]

        for group_title, group_findings in groups:
            if not group_findings:
                continue
            report_lines.append("")
            report_lines.append(f"### {group_title} ({len(group_findings)})")

            for idx, f in enumerate(group_findings, start=1):
                loc = f"`{f.file or 'global'}:{f.line or '?'}`"
                cwe_tag = f" [{f.cwe}]" if f.cwe else ""
                report_lines.append(f"#### {idx}. [{f.source_tool.upper()}] {f.rule_id or f.title}{cwe_tag} at {loc}")
                if f.code_snippet:
                    report_lines.append(f"```\n{f.code_snippet}\n```")
                report_lines.append(f"- **Explanation:** {f.explanation}")
                if f.fix_suggestion:
                    report_lines.append(f"- **Suggested Fix:** {f.fix_suggestion}")

    # Code Review Comments Section (Week 5)
    if review_findings:
        report_lines.extend([
            "",
            f"## 4. Code Review Comments ({len(review_findings)})",
        ])
        for idx, rf in enumerate(review_findings, start=1):
            report_lines.append(
                f"{idx}. **[{rf.severity.upper()}]** `{rf.file}:{rf.line}` - {rf.explanation}"
            )

    # Root-Cause Analysis Section (Week 5)
    if root_causes:
        report_lines.extend([
            "",
            f"## 5. Root-Cause Analysis ({len(root_causes)} diagnosed issues)",
        ])
        for idx, rc in enumerate(root_causes, start=1):
            loc = f"`{rc.root_cause_file}:{rc.root_cause_line or '?'}`"
            report_lines.append(f"### Diagnosis #{idx} ({loc})")
            report_lines.append(f"- **Root Cause:** {rc.explanation}")
            if rc.confidence < 1.0:
                report_lines.append(
                    "- _Diagnosed by built-in rules because the AI was unavailable "
                    "(run `python -m tools.check_llm`)._"
                )
            if rc.related_tests:
                report_lines.append(f"- **Triggered Failures:** {', '.join(rc.related_tests)}")

    # Proposed Patches Section (Week 5)
    if patches:
        report_lines.extend([
            "",
            f"## 6. Proposed Fixes & Unified Diffs ({len(patches)} patch(es) that apply cleanly)",
        ])
        for idx, p in enumerate(patches, start=1):
            target_str = ", ".join(p.target_files) if p.target_files else "designated files"
            report_lines.append(f"### Patch #{idx}: Target `{target_str}`")
            report_lines.append(f"- **Rationale:** {p.rationale}")
            report_lines.append("```diff")
            report_lines.append(p.unified_diff)
            report_lines.append("```")

    # Human Approval & Verification Section (Week 6)
    if state.get("require_approval") or verification_history or escalated:
        report_lines.extend(["", "## 7. Human Approval & Verification"])
        status_text = str(approval_status.value if hasattr(approval_status, "value") else approval_status)
        who = getattr(approval_decision, "reviewed_by", None) if approval_decision else None
        report_lines.append(
            f"- **Approval:** `{(status_text or 'pending').upper()}`" + (f" by `{who}`" if who else "")
        )
        if approved_patches:
            files = sorted({f for p in approved_patches for f in p.target_files})
            report_lines.append(f"- **Approved patches:** {len(approved_patches)} ({', '.join(files)})")
        for h in verification_history:
            icon = "✅" if h.get("verified") else "❌"
            report_lines.append(f"- {icon} **Attempt {h.get('attempt')}:** {h.get('summary')}")
            for t in h.get("failing_tests") or []:
                report_lines.append(f"  - still failing: `{t}`")
            for f in h.get("new_findings") or []:
                report_lines.append(f"  - new finding: `{f}`")
            for f in h.get("unresolved_findings") or []:
                report_lines.append(f"  - not fixed: `{f}`")
        if verifier_output is not None and getattr(verifier_output, "verified", False):
            report_lines.append(
                "- **Result:** The approved fix is verified on a copy of the merged code. "
                "Apply it to the branch to resolve this review. Your files were not changed."
            )
        if escalated:
            report_lines.append(
                f"- **Escalated:** No verified fix after {len(verification_history)} attempt(s). "
                "A human needs to fix this manually."
            )

    report_markdown = "\n".join(report_lines)

    report_json: dict[str, Any] = {
        "verdict": verdict.value,
        "risk_score": risk_score,
        "merge_outcome": merge_outcome,
        "blast_radius_score": blast_radius,
        "affected_files": affected_files,
        "conflicted_files": conflicted_files,
        "failing_tests": merge_res.failing_tests if merge_res else [],
        "regressions": [r.model_dump() for r in regressions],
        "pre_existing_failures": [p.model_dump() for p in pre_existing],
        "findings_count": len(confirmed),
        "critical_count": len(confirmed_critical),
        "high_count": len(confirmed_high),
        "findings": [f.model_dump() for f in confirmed],
        "review_comments": [rf.model_dump() for rf in review_findings],
        "root_causes": [rc.model_dump() for rc in root_causes],
        "patches": [p.model_dump() for p in patches],
        "test_results": test_results,
        "approval_status": str(approval_status.value if hasattr(approval_status, "value") else approval_status),
        "approved_patches": [p.model_dump(mode="json") for p in approved_patches],
        "verification": verifier_output.model_dump() if verifier_output is not None else None,
        "verification_history": verification_history,
        "escalated": escalated,
    }

    logger.info("reporter_agent_complete", verdict=verdict.value, risk_score=risk_score)

    return {
        "stage": PipelineStage.DONE,
        "verdict": verdict,
        "risk_score": risk_score,
        "report_markdown": report_markdown,
        "report_json": report_json,
    }
