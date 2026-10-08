"""Tests for Day 2 shared data models and schemas."""

from __future__ import annotations

from pathlib import Path

from core.state import (
    ApprovalStatus,
    ChangeSet,
    Finding,
    FindingType,
    FixAgentOutput,
    ImpactOutput,
    IndexerOutput,
    MergeSimOutput,
    Patch,
    PipelineStage,
    ReporterOutput,
    ReviewAgentOutput,
    ReviewState,
    ReviewVerdict,
    RootCause,
    SecurityAgentOutput,
    Severity,
    TriageOutput,
    VerifierOutput,
    make_initial_state,
)


def test_changeset_model() -> None:
    cs = ChangeSet(repo_path="/repo", base_ref="main", head_ref="feature/vuln-fix")
    assert isinstance(cs.repo_path, Path)
    assert cs.base_ref == "main"
    assert cs.head_ref == "feature/vuln-fix"
    assert cs.pr_number is None


def test_finding_model() -> None:
    finding = Finding(
        type=FindingType.SECURITY,
        severity=Severity.HIGH,
        file="app/views.py",
        line=42,
        cwe="CWE-89",
        explanation="SQL injection via unescaped query parameter",
        source_tool="semgrep",
    )
    assert finding.type == "security"
    assert finding.severity == Severity.HIGH
    assert finding.file == "app/views.py"
    assert finding.file_path == "app/views.py"
    assert finding.line == 42
    assert finding.line_start == 42
    assert finding.cwe == "CWE-89"
    assert "SQL injection" in finding.explanation
    assert finding.source_tool == "semgrep"
    assert finding.source == "semgrep"


def test_patch_model() -> None:
    diff_text = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n"
    patch = Patch(
        unified_diff=diff_text,
        rationale="Sanitize user input before executing database statement",
        target_files=["app.py"],
    )
    assert patch.unified_diff == diff_text
    assert "Sanitize" in patch.rationale
    assert patch.target_files == ["app.py"]
    assert patch.affected_files == ["app.py"]
    assert patch.approved is False


def test_review_state_schema_and_initial_state() -> None:
    cs = ChangeSet(repo_path=Path("/tmp"), base_ref="main", head_ref="feat")
    state: ReviewState = make_initial_state(cs)

    # Core required fields
    assert state["changeset"] == cs
    assert state["diff"] == ""
    assert state["merge_result"] is None
    assert state["test_results"] is None
    assert state["findings"] == []
    assert state["patches"] == []
    assert state["approval_status"] == ApprovalStatus.PENDING
    assert state["iteration_count"] == 0
    assert state["stage"] == PipelineStage.INIT


def test_structured_agent_outputs() -> None:
    # 1. Indexer
    idx = IndexerOutput(
        index_id="idx-123",
        primary_language="python",
        build_system="poetry",
        test_command="pytest",
        file_count=15,
    )
    assert idx.primary_language == "python"

    # 2. Impact
    impact = ImpactOutput(
        affected_files=["api.py"],
        affected_tests=["tests/test_api.py"],
        blast_radius_score=0.45,
    )
    assert impact.blast_radius_score == 0.45

    # 3. Merge Sim
    sim = MergeSimOutput(
        success=True,
        build_passed=True,
        tests_passed=True,
    )
    assert sim.success is True

    # 4. Review Agent
    rev = ReviewAgentOutput(
        findings=[
            Finding(
                type=FindingType.BUG,
                severity=Severity.MEDIUM,
                file="api.py",
                line=10,
                explanation="Uncaught ValueError on float conversion",
                source_tool="review_agent",
            )
        ]
    )
    assert len(rev.findings) == 1

    # 5. Security Agent
    sec = SecurityAgentOutput(
        findings=[],
        scanners_run=["semgrep", "bandit"],
        false_positives_filtered=2,
    )
    assert "semgrep" in sec.scanners_run

    # 6. Triage & RCA
    triage = TriageOutput(
        triaged_findings=[],
        root_causes=[
            RootCause(
                root_cause_file="api.py",
                root_cause_line=10,
                explanation="Input parameter not validated",
            )
        ],
        has_fixable_issues=True,
    )
    assert len(triage.root_causes) == 1

    # 7. Fix Generator
    fix = FixAgentOutput(
        patches=[
            Patch(
                unified_diff="--- a\n+++ b",
                rationale="Add input guard",
                target_files=["api.py"],
            )
        ]
    )
    assert len(fix.patches) == 1

    # 8. Verifier
    ver = VerifierOutput(
        verified=True,
        patches_applied=["patch-0"],
        build_passed=True,
        tests_passed=True,
        scanners_passed=True,
    )
    assert ver.verified is True

    # 9. Reporter
    rep = ReporterOutput(
        verdict=ReviewVerdict.SAFE,
        risk_score=1.2,
        safe_to_merge=True,
        report_markdown="# Safe",
    )
    assert rep.verdict == ReviewVerdict.SAFE
