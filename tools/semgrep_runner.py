"""
tools/semgrep_runner.py
------------------------
Runs Semgrep OSS code vulnerability analysis on changed files.
Supports execution inside Docker sandbox or local isolated subprocess.
Normalizes findings into the core Finding model.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from core.logging import get_logger
from core.state import Finding, FindingType, Severity
from tools.docker_runner import is_docker_available, run_in_sandbox

logger = get_logger(__name__)

SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def run_semgrep(
    repo_dir: Path | str,
    target_files: Sequence[str | Path],
    timeout_seconds: int = 90,
    config: str = "auto",
) -> list[Finding]:
    """
    Run Semgrep on changed files in repo_dir and return normalized Findings.
    """
    repo_path = Path(repo_dir).resolve()
    valid_files: list[str] = []

    for f in target_files:
        p = Path(f)
        full_p = p if p.is_absolute() else (repo_path / p)
        if full_p.is_file():
            try:
                rel = full_p.relative_to(repo_path)
                valid_files.append(str(rel))
            except ValueError:
                valid_files.append(str(full_p))

    if not valid_files:
        logger.debug("semgrep_skipped_no_target_files")
        return []

    logger.info("running_semgrep", files_count=len(valid_files), repo=str(repo_path))

    cmd_args = ["semgrep", "scan", "--json", "--quiet", f"--config={config}"] + valid_files
    stdout = ""

    if is_docker_available():
        res = run_in_sandbox(
            command=cmd_args,
            workspace_dir=repo_path,
            image="semgrep/semgrep:latest",
            timeout_seconds=timeout_seconds,
            network="none",
        )
        stdout = res.stdout
    else:
        semgrep_bin = shutil.which("semgrep")
        if semgrep_bin:
            exec_cmd = [semgrep_bin, "scan", "--json", "--quiet", f"--config={config}"] + valid_files
        else:
            exec_cmd = [sys.executable, "-m", "semgrep", "scan", "--json", "--quiet", f"--config={config}"] + valid_files

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
            logger.warning("semgrep_local_execution_error", error=str(exc))
            return []

    return parse_semgrep_json(stdout, repo_path)


def parse_semgrep_json(raw_json: str, repo_path: Path | None = None) -> list[Finding]:
    """Parse Semgrep JSON output into a list of normalized Finding models."""
    if not raw_json or not raw_json.strip():
        return []

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        logger.warning("semgrep_json_decode_failed", error=str(exc), raw_preview=raw_json[:200])
        return []

    findings: list[Finding] = []
    results = data.get("results", [])

    for item in results:
        check_id = item.get("check_id", "semgrep.rule")
        path_str = item.get("path", "")
        if repo_path and path_str:
            try:
                path_str = str(Path(path_str).relative_to(repo_path))
            except ValueError:
                pass

        start_info = item.get("start", {})
        line_start = start_info.get("line")
        end_info = item.get("end", {})
        line_end = end_info.get("line")

        extra = item.get("extra", {})
        sev_raw = (extra.get("severity") or "WARNING").upper()
        severity = SEMGREP_SEVERITY_MAP.get(sev_raw, Severity.MEDIUM)

        message = extra.get("message") or f"Semgrep issue detected by rule {check_id}"
        lines_code = (extra.get("lines") or "").strip()

        # Extract CWE if available
        cwe_raw = extra.get("metadata", {}).get("cwe")
        cwe: str | None = None
        if isinstance(cwe_raw, list) and cwe_raw:
            cwe_candidate = str(cwe_raw[0])
            m = re.search(r"CWE-\d+", cwe_candidate, re.IGNORECASE)
            cwe = m.group(0).upper() if m else cwe_candidate
        elif isinstance(cwe_raw, str):
            m = re.search(r"CWE-\d+", cwe_raw, re.IGNORECASE)
            cwe = m.group(0).upper() if m else cwe_raw

        finding = Finding(
            type=FindingType.SECURITY,
            severity=severity,
            source_tool="semgrep",
            rule_id=check_id,
            file=path_str,
            line=line_start,
            line_end=line_end,
            code_snippet=lines_code,
            cwe=cwe,
            explanation=message,
            title=f"{check_id}: {message[:80]}",
        )
        findings.append(finding)

    logger.info("semgrep_scan_complete", findings_count=len(findings))
    return findings
