"""core/exceptions.py – project-wide custom exception hierarchy."""
from __future__ import annotations


class AgenticReviewerError(Exception):
    """Base exception for all agentic-reviewer errors."""


class ConfigurationError(AgenticReviewerError):
    """Raised when required configuration is missing or invalid."""


class GitOperationError(AgenticReviewerError):
    """Raised when a git operation (diff, worktree, merge) fails."""


class SandboxError(AgenticReviewerError):
    """Raised when the Docker sandbox cannot be set up or run."""


class LLMError(AgenticReviewerError):
    """Raised on unrecoverable LLM API failures after retries."""


class ScannerError(AgenticReviewerError):
    """Raised when an external scanner (Semgrep, Bandit, …) fails."""


class PatchError(AgenticReviewerError):
    """Raised when a patch cannot be applied cleanly."""


class ApprovalRequiredError(AgenticReviewerError):
    """Raised to signal the human-in-the-loop gate must pause execution."""
