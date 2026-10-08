"""
tools/gitleaks_runner.py
-------------------------
Runs Gitleaks secret detection on changed files to uncover hardcoded credentials,
tokens, and keys. Supports execution in Docker sandbox or via built-in regex rules fallback.
Normalizes findings into the core Finding model.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

from core.logging import get_logger
from core.state import Finding, FindingType, Severity
from tools.docker_runner import is_docker_available, run_in_sandbox

logger = get_logger(__name__)

# Built-in high-confidence secret patterns when Gitleaks binary is unavailable
SECRET_PATTERNS = [
    (
        "aws-access-token",
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "AWS Access Key ID",
        Severity.CRITICAL,
    ),
    (
        "github-pat",
        r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}",
        "GitHub Personal Access Token",
        Severity.CRITICAL,
    ),
    (
        "private-key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "Unencrypted Private Key",
        Severity.CRITICAL,
    ),
    (
        "slack-token",
        r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "Slack Token",
        Severity.HIGH,
    ),
    (
        "generic-api-key",
        r"""(?i)(?:api_key|apikey|secret_key|client_secret|access_token|password|auth_token)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,80}['"]""",
        "Hardcoded API Secret or Credential",
        Severity.HIGH,
    ),
]


def run_gitleaks(
    repo_dir: Path | str,
    target_files: Sequence[str | Path],
    timeout_seconds: int = 60,
) -> list[Finding]:
    """
    Run Gitleaks on changed files in repo_dir and return normalized Findings.
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
        logger.debug("gitleaks_skipped_no_target_files")
        return []

    logger.info("running_gitleaks", files_count=len(valid_files), repo=str(repo_path))

    # 1. Docker sandbox execution if available
    if is_docker_available():
        report_file = ".gitleaks_report.json"
        cmd_args = [
            "gitleaks",
            "detect",
            "--no-git",
            f"--report-path={report_file}",
            "--report-format=json",
        ]
        res = run_in_sandbox(
            command=cmd_args,
            workspace_dir=repo_path,
            image="zricethezav/gitleaks:latest",
            timeout_seconds=timeout_seconds,
            network="none",
        )
        report_path = repo_path / report_file
        if report_path.is_file():
            try:
                content = report_path.read_text(encoding="utf-8")
                report_path.unlink()
                return parse_gitleaks_json(content, repo_path, valid_files)
            except Exception as exc:
                logger.warning("gitleaks_report_read_error", error=str(exc))

    # 2. Local CLI binary if installed
    gitleaks_bin = shutil.which("gitleaks")
    if gitleaks_bin:
        report_file = repo_path / ".gitleaks_report.json"
        cmd = [
            gitleaks_bin,
            "detect",
            "--no-git",
            f"--source={repo_path}",
            f"--report-path={report_file}",
            "--report-format=json",
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout_seconds, check=False)
            if report_file.is_file():
                content = report_file.read_text(encoding="utf-8")
                report_file.unlink()
                return parse_gitleaks_json(content, repo_path, valid_files)
        except Exception as exc:
            logger.warning("gitleaks_local_cli_error", error=str(exc))

    # 3. Built-in high-accuracy pattern scanning fallback
    return scan_secrets_builtin(repo_path, valid_files)


def parse_gitleaks_json(
    raw_json: str,
    repo_path: Path | None = None,
    filter_files: Sequence[str] | None = None,
) -> list[Finding]:
    """Parse Gitleaks JSON report into normalized Finding models."""
    if not raw_json or not raw_json.strip():
        return []

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        logger.warning("gitleaks_json_decode_failed", error=str(exc))
        return []

    if not isinstance(data, list):
        return []

    findings: list[Finding] = []
    filter_set = set(filter_files) if filter_files else None

    for item in data:
        filename = item.get("File", "")
        if repo_path and filename:
            try:
                filename = str(Path(filename).relative_to(repo_path))
            except ValueError:
                pass

        if filter_set and filename not in filter_set:
            continue

        rule_id = item.get("RuleID", "hardcoded-secret")
        desc = item.get("Description", "Hardcoded secret detected")
        line = item.get("StartLine")
        line_end = item.get("EndLine")
        match_snippet = item.get("Match", "")

        finding = Finding(
            type=FindingType.SECURITY,
            severity=Severity.CRITICAL if "key" in rule_id or "token" in rule_id else Severity.HIGH,
            source_tool="gitleaks",
            rule_id=f"gitleaks.{rule_id}",
            file=filename,
            line=line,
            line_end=line_end,
            code_snippet=match_snippet,
            cwe="CWE-798",
            explanation=f"Hardcoded credential or secret detected: {desc}",
            title=f"Secret: {desc}",
        )
        findings.append(finding)

    logger.info("gitleaks_scan_complete", findings_count=len(findings))
    return findings


def scan_secrets_builtin(repo_path: Path, target_files: Sequence[str]) -> list[Finding]:
    """Fallback scanner using compiled high-confidence regex patterns."""
    findings: list[Finding] = []

    for rel_file in target_files:
        fpath = repo_path / rel_file
        if not fpath.is_file():
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for line_num, line_str in enumerate(content.splitlines(), start=1):
            # Skip test mock data or comments explicitly labeled mock/dummy
            if "dummy" in line_str.lower() or "mock" in line_str.lower():
                continue

            for rule_id, pattern, desc, severity in SECRET_PATTERNS:
                if re.search(pattern, line_str):
                    snippet = line_str.strip()
                    finding = Finding(
                        type=FindingType.SECURITY,
                        severity=severity,
                        source_tool="gitleaks",
                        rule_id=f"gitleaks.{rule_id}",
                        file=rel_file,
                        line=line_num,
                        code_snippet=snippet,
                        cwe="CWE-798",
                        explanation=f"Hardcoded secret detected ({desc}). Credentials should never be committed to source code.",
                        title=f"Secret: {desc}",
                    )
                    findings.append(finding)
                    break

    logger.info("gitleaks_builtin_scan_complete", findings_count=len(findings))
    return findings
