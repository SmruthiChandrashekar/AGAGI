"""
agents/security_agent.py
-------------------------
Security Agent:
  - Scans only changed files from PR diff
  - Runs Semgrep, Gitleaks, and Bandit (for Python)
  - Normalizes findings into Finding model
  - Deduplicates overlapping findings across tools
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.logging import get_logger
from core.state import Finding, ReviewState
from tools.bandit_runner import run_bandit
from tools.deduplicator import deduplicate_findings
from tools.gitleaks_runner import run_gitleaks
from tools.project_detector import detect_project
from tools.semgrep_runner import run_semgrep

logger = get_logger(__name__)


def run_security_agent(state: ReviewState) -> dict[str, Any]:
    """
    Execute static security analysis tools (Semgrep, Gitleaks, Bandit)
    only on the files modified in this changeset.
    """
    logger.info("stage_start", stage="security_agent")

    cs = state.get("changeset")
    if not cs:
        logger.warning("security_agent_missing_changeset")
        return {"security_findings": []}

    repo_dir = Path(cs.repo_path).resolve()
    affected_files = state.get("affected_files", [])

    # Filter to existing files in the repo
    target_files: list[str] = []
    for f in affected_files:
        p = Path(f)
        full = p if p.is_absolute() else (repo_dir / p)
        if full.is_file():
            try:
                target_files.append(str(full.relative_to(repo_dir)))
            except ValueError:
                target_files.append(str(full))

    if not target_files:
        logger.info("security_agent_no_target_files_to_scan")
        return {"security_findings": []}

    all_findings: list[Finding] = []
    scanners_run: list[str] = []

    # 1. Semgrep (Code Vulnerabilities)
    try:
        semgrep_findings = run_semgrep(repo_dir, target_files)
        all_findings.extend(semgrep_findings)
        scanners_run.append("semgrep")
    except Exception as exc:
        logger.warning("semgrep_run_failed", error=str(exc))

    # 2. Gitleaks (Hardcoded Secrets)
    try:
        gitleaks_findings = run_gitleaks(repo_dir, target_files)
        all_findings.extend(gitleaks_findings)
        scanners_run.append("gitleaks")
    except Exception as exc:
        logger.warning("gitleaks_run_failed", error=str(exc))

    # 3. Bandit (Python Vulnerabilities)
    try:
        project_info = detect_project(repo_dir)
        is_python = (
            getattr(project_info, "primary_language", "") == "python"
            or getattr(project_info, "language", "") == "python"
            or any(f.endswith(".py") for f in target_files)
        )
    except Exception:
        is_python = any(f.endswith(".py") for f in target_files)

    if is_python:
        try:
            bandit_findings = run_bandit(repo_dir, target_files)
            all_findings.extend(bandit_findings)
            scanners_run.append("bandit")
        except Exception as exc:
            logger.warning("bandit_run_failed", error=str(exc))

    # Deduplicate overlapping findings across tools
    deduped = deduplicate_findings(all_findings)

    logger.info(
        "security_agent_complete",
        scanners=scanners_run,
        raw_count=len(all_findings),
        deduped_count=len(deduped),
    )

    return {"security_findings": deduped}
