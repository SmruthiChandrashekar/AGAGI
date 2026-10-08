"""
agents/dependency_agent.py
---------------------------
Dependency Agent:
  - Scans dependency manifests (e.g. requirements.txt) ONLY when they changed in the PR
  - Runs OSV-Scanner / pip-audit
  - Reports vulnerable packages with version, CVE, severity, and fix version
  - Skips license and supply-chain checks
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.logging import get_logger
from core.state import Finding, ReviewState
from tools.osv_scanner import is_dependency_manifest, run_dependency_scan

logger = get_logger(__name__)


def run_dependency_agent(state: ReviewState) -> dict[str, Any]:
    """
    Run dependency vulnerability scans only when dependency files are modified.
    """
    logger.info("stage_start", stage="dependency_agent")

    cs = state.get("changeset")
    if not cs:
        logger.warning("dependency_agent_missing_changeset")
        return {"dependency_findings": []}

    repo_dir = Path(cs.repo_path).resolve()
    affected_files = state.get("affected_files", [])

    # Check if any dependency manifest changed
    manifests_changed = [f for f in affected_files if is_dependency_manifest(f)]

    if not manifests_changed:
        logger.info("dependency_agent_skipped_no_manifest_changes")
        return {"dependency_findings": []}

    try:
        findings: list[Finding] = run_dependency_scan(repo_dir, manifests_changed)
    except Exception as exc:
        logger.warning("dependency_scan_error", error=str(exc))
        findings = []

    logger.info("dependency_agent_complete", findings_count=len(findings))
    return {"dependency_findings": findings}
