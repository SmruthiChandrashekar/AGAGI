"""
core/state.py
-------------
Shared LangGraph state schema and supporting Pydantic data models.
Defines ChangeSet, Finding, Patch, ReviewState, and structured agent outputs.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ── Enumerations ─────────────────────────────────────────────────────────────


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(StrEnum):
    SECURITY = "security"
    BUG = "bug"
    VULNERABILITY = "vulnerability"
    STYLE = "style"
    DEPENDENCY = "dependency"
    TEST_FAILURE = "test_failure"
    PERFORMANCE = "performance"
    ARCHITECTURE = "architecture"


class ReviewVerdict(StrEnum):
    SAFE = "safe"
    NEEDS_CHANGES = "needs_changes"
    BLOCKED = "blocked"
    ESCALATED = "escalated"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"


class PipelineStage(StrEnum):
    INIT = "init"
    INDEXING = "indexing"
    IMPACT_ANALYSIS = "impact_analysis"
    MERGE_SIMULATION = "merge_simulation"
    PARALLEL_ANALYSIS = "parallel_analysis"
    TRIAGE_RCA = "triage_rca"
    FIX_GENERATION = "fix_generation"
    HUMAN_APPROVAL = "human_approval"
    APPLY_AND_VERIFY = "apply_and_verify"
    REPORTING = "reporting"
    DONE = "done"
    FAILED = "failed"


# ── Core Domain Models ───────────────────────────────────────────────────────


class ChangeSet(BaseModel):
    """
    Mode-agnostic description of what is being reviewed.
    The only input the core review engine sees.
    """

    model_config = ConfigDict(populate_by_name=True)

    repo_path: Path = Field(description="Path to the local git repository")
    base_ref: str = Field(description="Base git ref (e.g. 'main', SHA, 'origin/main')")
    head_ref: str = Field(description="Head git ref (e.g. branch name or SHA)")
    pr_number: int | None = Field(default=None, description="PR number (Mode A only)")
    pr_title: str | None = Field(default=None, description="PR title (Mode A only)")
    pr_author: str | None = Field(default=None, description="PR author (Mode A only)")

    @field_validator("repo_path", mode="before")
    @classmethod
    def _coerce_path(cls, v: Any) -> Path:
        if isinstance(v, str):
            return Path(v)
        return v


class Finding(BaseModel):
    """
    A single issue discovered by any analysis agent or tool.
    Supports both standard field names and tool-specific aliases.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: f"FINDING-{uuid.uuid4().hex[:8].upper()}")
    type: str = Field(
        default=FindingType.SECURITY,
        description="Issue category: security, bug, style, dependency, test_failure",
    )
    severity: Severity = Field(default=Severity.MEDIUM, description="Finding severity level")
    file: str | None = Field(
        default=None,
        alias="file_path",
        description="Target file path where the issue occurs",
    )
    line: int | None = Field(
        default=None,
        alias="line_start",
        description="Line number where the issue occurs",
    )
    cwe: str | None = Field(
        default=None,
        description="CWE identifier, e.g. 'CWE-89' (SQL Injection)",
    )
    explanation: str = Field(
        default="",
        alias="description",
        description="Detailed explanation of the issue and why it is a problem",
    )
    source_tool: str = Field(
        default="unknown",
        alias="source",
        description="Originating tool or agent (semgrep, bandit, osv, review_agent, etc.)",
    )
    code_snippet: str | None = Field(
        default=None,
        description="Code snippet flagged by scanner or agent",
    )

    # Optional metadata
    title: str = Field(default="", description="Short summary title")
    line_end: int | None = Field(default=None, description="End line number if multiline")
    rule_id: str | None = Field(default=None, description="Scanner rule ID (e.g. bandit.B608)")
    is_false_positive: bool = Field(default=False, description="Whether triaged as false positive")
    fix_suggestion: str | None = Field(default=None, description="Proposed resolution guidance")

    @model_validator(mode="after")
    def _populate_title(self) -> Finding:
        if not self.title and self.explanation:
            self.title = self.explanation.splitlines()[0][:80]
        elif not self.title:
            self.title = f"{self.type.title()} finding in {self.file or 'unknown'}"
        return self

    @property
    def file_path(self) -> str | None:
        return self.file

    @file_path.setter
    def file_path(self, val: str | None) -> None:
        self.file = val

    @property
    def line_start(self) -> int | None:
        return self.line

    @line_start.setter
    def line_start(self, val: int | None) -> None:
        self.line = val

    @property
    def description(self) -> str:
        return self.explanation

    @description.setter
    def description(self, val: str) -> None:
        self.explanation = val

    @property
    def source(self) -> str:
        return self.source_tool

    @source.setter
    def source(self, val: str) -> None:
        self.source_tool = val

    @property
    def tool(self) -> str:
        return self.source_tool

    @tool.setter
    def tool(self, val: str) -> None:
        self.source_tool = val

    @property
    def rule(self) -> str | None:
        return self.rule_id

    @rule.setter
    def rule(self, val: str | None) -> None:
        self.rule_id = val


class Patch(BaseModel):
    """
    A minimal unified diff patch proposed to fix a root-cause finding.
    """

    model_config = ConfigDict(populate_by_name=True)

    unified_diff: str = Field(description="Unified diff text that can be applied with git apply")
    rationale: str = Field(description="Technical rationale explaining how the patch fixes the issue")
    target_files: list[str] = Field(
        default_factory=list,
        alias="affected_files",
        description="List of files touched by this patch",
    )

    # Optional metadata
    finding_id: str | None = Field(default=None, description="ID of the finding being resolved")
    approved: bool = Field(default=False, description="Whether human approval was granted")
    approved_by: str | None = Field(default=None, description="Identifier of the approver")
    approved_at: datetime | None = Field(default=None, description="Approval timestamp")

    @property
    def affected_files(self) -> list[str]:
        return self.target_files

    @affected_files.setter
    def affected_files(self, val: list[str]) -> None:
        self.target_files = val


# Compatibility alias
PatchProposal = Patch


class RootCause(BaseModel):
    """Root-cause analysis outcome tracing findings back to code origin."""

    finding_id: str | None = None
    root_cause_file: str
    root_cause_line: int | None = None
    explanation: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class TestCaseResult(BaseModel):
    """Structured result of an individual test case."""

    name: str
    file: str = "unknown"
    classname: str = ""
    status: str = "passed"  # "passed", "failed", "error", "skipped"
    error_message: str | None = None
    failing_file: str | None = None
    failing_line: int | None = None
    duration: float = 0.0

    @property
    def test_id(self) -> str:
        file_part = self.file or self.classname
        return f"{file_part}::{self.name}"


class SimulationResult(BaseModel):
    """Outcome of the Merge Simulation Agent or Verifier Agent."""

    success: bool
    status: str = "passed"  # "conflict" | "install error" | "build error" | "test failure" | "timeout" | "passed"
    merge_conflict: bool = False
    build_passed: bool = False
    tests_passed: bool = False
    failing_tests: list[str] = Field(default_factory=list)
    regressions: list[TestCaseResult] = Field(default_factory=list)
    pre_existing_failures: list[TestCaseResult] = Field(default_factory=list)
    all_tests: list[TestCaseResult] = Field(default_factory=list)
    build_log_snippet: str = ""
    test_log_snippet: str = ""


# Compatibility alias
MergeSimulationResult = SimulationResult


# ── Structured Agent Output Schemas ──────────────────────────────────────────


class IndexerOutput(BaseModel):
    """Structured response from the Repo Indexer Agent."""

    index_id: str
    primary_language: str
    build_system: str | None = None
    test_command: str | None = None
    file_count: int = 0
    summary: str = ""


class ImpactOutput(BaseModel):
    """Structured response from the Diff and Impact Agent."""

    affected_files: list[str] = Field(default_factory=list)
    affected_tests: list[str] = Field(default_factory=list)
    affected_modules: list[str] = Field(default_factory=list)
    blast_radius_score: float = Field(default=0.0, ge=0.0, le=1.0)
    raw_diff: str = ""
    summary: str = ""


class MergeSimOutput(BaseModel):
    """Structured response from the Merge Simulation Agent."""

    success: bool
    merge_conflict: bool = False
    build_passed: bool = False
    tests_passed: bool = False
    failing_tests: list[str] = Field(default_factory=list)
    build_log_snippet: str = ""
    test_log_snippet: str = ""


class ReviewAgentOutput(BaseModel):
    """Structured response from the Code Review Agent."""

    findings: list[Finding] = Field(default_factory=list)
    summary: str = ""


class SecurityAgentOutput(BaseModel):
    """Structured response from the Security Agent."""

    findings: list[Finding] = Field(default_factory=list)
    scanners_run: list[str] = Field(default_factory=list)
    false_positives_filtered: int = 0
    summary: str = ""


class DependencyAgentOutput(BaseModel):
    """Structured response from the Dependency Agent."""

    findings: list[Finding] = Field(default_factory=list)
    vulnerable_packages: list[str] = Field(default_factory=list)
    license_warnings: list[str] = Field(default_factory=list)
    summary: str = ""


class TriageOutput(BaseModel):
    """Structured response from the Failure Triage and RCA Agent."""

    triaged_findings: list[Finding] = Field(default_factory=list)
    root_causes: list[RootCause] = Field(default_factory=list)
    has_fixable_issues: bool = False
    recommended_action: str = ""


class FixAgentOutput(BaseModel):
    """Structured response from the Fix Generator Agent."""

    patches: list[Patch] = Field(default_factory=list)
    unresolved_findings: list[str] = Field(default_factory=list)
    summary: str = ""


class VerifierOutput(BaseModel):
    """Structured response from the Verifier Agent."""

    verified: bool
    patches_applied: list[str] = Field(default_factory=list)
    build_passed: bool = False
    tests_passed: bool = False
    scanners_passed: bool = False
    regressions_detected: list[str] = Field(default_factory=list)
    summary: str = ""


class ReporterOutput(BaseModel):
    """Structured response from the Reporter / HITL Agent."""

    verdict: ReviewVerdict
    risk_score: float = Field(ge=0.0, le=10.0)
    safe_to_merge: bool
    report_markdown: str
    report_json: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecision(BaseModel):
    """Human-in-the-loop approval input."""

    status: ApprovalStatus
    approved_patch_indices: list[int] = Field(default_factory=list)
    feedback: str | None = None
    reviewed_by: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ── LangGraph State Schema ────────────────────────────────────────────────────


class ReviewState(TypedDict, total=False):
    """
    State schema threading through the LangGraph review pipeline.

    Includes fields for:
    - changeset (the only engine input)
    - diff (unified diff text)
    - merge result & test results
    - findings (parallel & triaged)
    - patches & approval status
    - iteration count (fix-retry loop control)
    """

    # Messages / LangGraph trace
    messages: Annotated[list[BaseMessage], add_messages]

    # Input
    changeset: ChangeSet | None

    # Pipeline position & loop control
    stage: PipelineStage
    iteration_count: int
    iteration: int  # compatibility alias

    # Diff
    diff: str
    raw_diff: str  # compatibility alias

    # Index & impact analysis
    repo_index_id: str | None
    affected_files: list[str]
    affected_tests: list[str]
    changed_functions: list[dict[str, Any]] | list[str]
    risk_hint: str | None
    graph_summary: dict[str, Any] | None
    blast_radius_score: float

    # Simulation & test results
    merge_result: SimulationResult | None
    simulation_result: SimulationResult | None  # compatibility alias
    merge_outcome: str | None  # "conflict" | "install error" | "build error" | "test failure" | "timeout" | "passed"
    conflicted_files: list[str]
    conflict_hunks: list[dict[str, Any]]
    regressions: list[TestCaseResult]
    pre_existing_failures: list[TestCaseResult]
    test_results: dict[str, Any] | None

    # Findings
    findings: list[Finding]
    all_findings: list[Finding]  # compatibility alias
    review_findings: list[Finding]
    security_findings: list[Finding]
    dependency_findings: list[Finding]
    triaged_findings: list[Finding]

    # Triage & Root Cause Analysis
    root_causes: list[RootCause | dict[str, Any]]

    # Fix proposals & Human Approval
    patches: list[Patch]
    patch_proposals: list[Patch]  # compatibility alias
    approval_status: ApprovalStatus

    # Verification (post-patch)
    verification_result: SimulationResult | None

    # Final outputs
    verdict: ReviewVerdict | None
    risk_score: float | None
    report_markdown: str | None
    report_json: dict[str, Any] | None

    # Pipeline execution metadata
    started_at: datetime
    finished_at: datetime | None
    error: str | None


def make_initial_state(changeset: ChangeSet) -> ReviewState:
    """Factory that produces a fully-initialised ReviewState."""
    now = datetime.utcnow()
    return ReviewState(
        messages=[],
        changeset=changeset,
        stage=PipelineStage.INIT,
        iteration_count=0,
        iteration=0,
        diff="",
        raw_diff="",
        repo_index_id=None,
        affected_files=[],
        affected_tests=[],
        changed_functions=[],
        risk_hint=None,
        graph_summary=None,
        blast_radius_score=0.0,
        merge_result=None,
        simulation_result=None,
        merge_outcome=None,
        conflicted_files=[],
        conflict_hunks=[],
        regressions=[],
        pre_existing_failures=[],
        test_results=None,
        findings=[],
        all_findings=[],
        review_findings=[],
        security_findings=[],
        dependency_findings=[],
        root_causes=[],
        patches=[],
        patch_proposals=[],
        approval_status=ApprovalStatus.PENDING,
        verification_result=None,
        verdict=None,
        risk_score=None,
        report_markdown=None,
        report_json=None,
        started_at=now,
        finished_at=None,
        error=None,
    )
