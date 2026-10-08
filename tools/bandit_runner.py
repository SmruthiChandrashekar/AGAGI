"""
tools/bandit_runner.py
-----------------------
Runs Bandit AST security analysis on changed Python files.
Supports execution inside Docker sandbox or local isolated subprocess.
Normalizes findings into the core Finding model.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from core.logging import get_logger
from core.state import Finding, FindingType, Severity
from tools.docker_runner import is_docker_available, run_in_sandbox

logger = get_logger(__name__)

SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def run_bandit(
    repo_dir: Path | str,
    target_files: Sequence[str | Path],
    timeout_seconds: int = 60,
) -> list[Finding]:
    """
    Run Bandit on the specified Python files in repo_dir and return normalized Findings.
    Only files with a .py extension that actually exist are analyzed.
    """
    repo_path = Path(repo_dir).resolve()
    py_files: list[str] = []

    for f in target_files:
        p = Path(f)
        full_p = p if p.is_absolute() else (repo_path / p)
        if full_p.suffix == ".py" and full_p.is_file():
            # Use relative path if possible
            try:
                rel = full_p.relative_to(repo_path)
                py_files.append(str(rel))
            except ValueError:
                py_files.append(str(full_p))

    if not py_files:
        logger.debug("bandit_skipped_no_python_files", count=len(target_files))
        return []

    logger.info("running_bandit", files_count=len(py_files), repo=str(repo_path))

    cmd_args = ["bandit", "-f", "json", "-q"] + py_files
    stdout = ""

    if is_docker_available():
        res = run_in_sandbox(
            command=cmd_args,
            workspace_dir=repo_path,
            timeout_seconds=timeout_seconds,
            network="none",
        )
        stdout = res.stdout
    else:
        # Local execution via active Python venv or system bandit
        bandit_bin = shutil.which("bandit")
        if bandit_bin:
            exec_cmd = [bandit_bin, "-f", "json", "-q"] + py_files
        else:
            exec_cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q"] + py_files

        try:
            proc = subprocess.run(
                exec_cmd,
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            stdout = proc.stdout
        except Exception as exc:
            logger.warning("bandit_local_execution_error", error=str(exc))
            return []

    return parse_bandit_json(stdout, repo_path)


def parse_bandit_json(raw_json: str, repo_path: Path | None = None) -> list[Finding]:
    """Parse Bandit JSON output into a list of normalized Finding models."""
    if not raw_json or not raw_json.strip():
        return []

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        logger.warning("bandit_json_decode_failed", error=str(exc), raw_preview=raw_json[:200])
        return []

    findings: list[Finding] = []
    results = data.get("results", [])

    for item in results:
        test_id = item.get("test_id", "unknown")
        test_name = item.get("test_name", "")
        rule_str = f"bandit.{test_id}" if test_id else "bandit"
        sev_str = (item.get("issue_severity") or "MEDIUM").upper()
        severity = SEVERITY_MAP.get(sev_str, Severity.MEDIUM)

        filename = item.get("filename", "")
        if repo_path and filename:
            try:
                filename = str(Path(filename).relative_to(repo_path))
            except ValueError:
                pass

        cwe_obj = item.get("issue_cwe") or {}
        cwe_id = cwe_obj.get("id")
        cwe = f"CWE-{cwe_id}" if cwe_id else None

        line = item.get("line_number")
        line_range = item.get("line_range") or []
        line_end = line_range[-1] if line_range and len(line_range) > 1 else None

        code_snippet = (item.get("code") or "").strip()
        explanation = item.get("issue_text") or f"Bandit finding: {test_name}"

        finding = Finding(
            type=FindingType.SECURITY,
            severity=severity,
            source_tool="bandit",
            rule_id=rule_str,
            file=filename,
            line=line,
            line_end=line_end,
            code_snippet=code_snippet,
            cwe=cwe,
            explanation=explanation,
            title=f"{rule_str}: {explanation[:80]}",
        )
        findings.append(finding)

    logger.info("bandit_scan_complete", findings_count=len(findings))
    return findings
