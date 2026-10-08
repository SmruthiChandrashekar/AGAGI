"""
core/state.py
-------------
Shared LangGraph state schema (TypedDict) and supporting Pydantic models.
Every agent reads from and writes to a ``ReviewState`` instance that the
orchestrator threads through the graph.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, Field
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage


# ── Enumerations ─────────────────────────────────────────────────────────────


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ReviewVerdict(StrEnum):
    SAFE = "safe"
    NEEDS_CHANGES = "needs_changes"
    BLOCKED = "blocked"
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


# ── Input / shared value objects ──────────────────────────────────────────────


class ChangeSet(BaseModel):
    """
    Mode-agnostic description of what is being reviewed.
    Both the GitHub adapter and the CLI adapter produce one of these.
    """

    repo_path: Path = Field(description="Absolute path to the local git repository")
    base_ref: str = Field(description="Base git ref (e.g. 'main', a SHA, or 'origin/main')")
    head_ref: str = Field(description="Head git ref (e.g. a branch name or SHA)")
    pr_number: int | None = Field(default=None, description="PR number (Mode A only)")
    pr_title: str | None = Field(default=None, description="PR title (Mode A only)")
    pr_author: str | None = Field(default=None, description="PR author (Mode A only)")


class Finding(BaseModel):
    """A single issue discovered by any analysis agent."""

    id: str = Field(description="Unique finding ID (e.g. 'SEC-001')")
    source: str = Field(description="Agent or tool that produced this finding")
    title: str
    description: str
    severity: Severity
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    cwe: str | None = Field(default=None, description="CWE identifier, e.g. 'CWE-89'")
    rule_id: str | None = Field(default=None, description="Scanner rule ID (Semgrep, Bandit…)")
    is_false_positive: bool = False
    fix_suggestion: str | None = None


class PatchProposal(BaseModel):
    """A minimal unified diff patch proposed by the Fix Generator."""

    finding_id: str
    rationale: str
    unified_diff: str
    affected_files: list[str]
    approved: bool = False
    approved_by: str | None = None
    approved_at: datetime | None = None


class SimulationResult(BaseModel):
    """Outcome of the Merge Simulation Agent."""

    success: bool
    merge_conflict: bool = False
    build_passed: bool = False
    tests_passed: bool = False
    failing_tests: list[str] = Field(default_factory=list)
    build_log_snippet: str = ""
    test_log_snippet: str = ""


# ── LangGraph state ───────────────────────────────────────────────────────────


class ReviewState(dict):
    """
    Typed dictionary that flows through the LangGraph graph.

    Convention:
    - All fields are optional with sensible defaults so any agent can run
      in isolation during unit tests.
    - ``messages`` uses the LangGraph ``add_messages`` reducer so concurrent
      agent writes are merged, not overwritten.
    """

    # Conversation / message history (LangGraph managed)
    messages: Annotated[list[BaseMessage], add_messages]

    # Input
    changeset: ChangeSet | None

    # Pipeline position
    stage: PipelineStage
    iteration: int  # current fix-retry iteration (0-based)

    # Index / graph data
    repo_index_id: str | None  # points to cached index in ChromaDB
    affected_files: list[str]
    affected_tests: list[str]
    blast_radius_score: float  # 0.0 – 1.0

    # Diff
    raw_diff: str  # full unified diff text

    # Simulation
    simulation_result: SimulationResult | None

    # Analysis findings (populated in parallel)
    review_findings: list[Finding]
    security_findings: list[Finding]
    dependency_findings: list[Finding]

    # Triage / RCA
    all_findings: list[Finding]  # deduplicated, ranked
    root_causes: list[dict[str, Any]]  # free-form RCA objects

    # Fixes
    patch_proposals: list[PatchProposal]

    # Verification (post-apply)
    verification_result: SimulationResult | None

    # Output
    verdict: ReviewVerdict | None
    risk_score: float | None  # 0.0 – 10.0
    report_markdown: str | None
    report_json: dict[str, Any] | None

    # Metadata
    started_at: datetime
    finished_at: datetime | None
    error: str | None


def make_initial_state(changeset: ChangeSet) -> ReviewState:
    """Factory that produces a fully-initialised ``ReviewState``."""
    return ReviewState(
        messages=[],
        changeset=changeset,
        stage=PipelineStage.INIT,
        iteration=0,
        repo_index_id=None,
        affected_files=[],
        affected_tests=[],
        blast_radius_score=0.0,
        raw_diff="",
        simulation_result=None,
        review_findings=[],
        security_findings=[],
        dependency_findings=[],
        all_findings=[],
        root_causes=[],
        patch_proposals=[],
        verification_result=None,
        verdict=None,
        risk_score=None,
        report_markdown=None,
        report_json=None,
        started_at=datetime.utcnow(),
        finished_at=None,
        error=None,
    )
