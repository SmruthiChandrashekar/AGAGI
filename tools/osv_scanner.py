"""
tools/osv_scanner.py
---------------------
Runs dependency vulnerability scanning on changed manifest files
using pip-audit (Python) or OSV-Scanner.
Reports vulnerable package name, installed version, CVE ID, severity,
and the recommended fixed version. Skips license and supply-chain checks.
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

DEPENDENCY_MANIFEST_PATTERNS = {
    "requirements.txt",
    "requirements-dev.txt",
    "pipfile",
    "pipfile.lock",
    "pyproject.toml",
    "setup.py",
    "package.json",
    "package-lock.json",
    "yarn.lock",
}


def is_dependency_manifest(path: str | Path) -> bool:
    """Return True if the file name matches a recognized dependency manifest."""
    name = Path(path).name.lower()
    return name in DEPENDENCY_MANIFEST_PATTERNS or name.startswith("requirements")


def run_dependency_scan(
    repo_dir: Path | str,
    changed_files: Sequence[str | Path],
    timeout_seconds: int = 90,
) -> list[Finding]:
    """
    Run dependency vulnerability scans ONLY if dependency manifests are among changed_files.
    Skips license and supply-chain checks.
    """
    repo_path = Path(repo_dir).resolve()

    manifest_files: list[str] = []
    for f in changed_files:
        p = Path(f)
        full_p = p if p.is_absolute() else (repo_path / p)
        if is_dependency_manifest(p) and full_p.is_file():
            try:
                manifest_files.append(str(full_p.relative_to(repo_path)))
            except ValueError:
                manifest_files.append(str(full_p))

    if not manifest_files:
        logger.info("dependency_scan_skipped_no_manifest_changed")
        return []

    logger.info("running_dependency_scan", manifests=manifest_files, repo=str(repo_path))
    findings: list[Finding] = []

    for manifest in manifest_files:
        mf_path = repo_path / manifest
        # Check if Python requirements file
        if "requirements" in manifest.lower() or manifest.endswith((".txt", ".py")):
            mf_findings = scan_python_manifest(repo_path, mf_path, timeout_seconds)
            findings.extend(mf_findings)
        else:
            # Try osv-scanner if available
            mf_findings = scan_with_osv_scanner(repo_path, mf_path, timeout_seconds)
            findings.extend(mf_findings)

    logger.info("dependency_scan_complete", findings_count=len(findings))
    return findings


def scan_python_manifest(
    repo_path: Path, manifest_path: Path, timeout_seconds: int = 60
) -> list[Finding]:
    """Run pip-audit on a requirements file and parse the JSON results."""
    rel_path = str(manifest_path.relative_to(repo_path)) if manifest_path.is_relative_to(repo_path) else str(manifest_path)
    stdout = ""

    pip_audit_bin = shutil.which("pip-audit")
    if pip_audit_bin:
        cmd = [pip_audit_bin, "-r", str(manifest_path), "-f", "json"]
    else:
        cmd = [sys.executable, "-m", "pip_audit", "-r", str(manifest_path), "-f", "json"]

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        stdout = proc.stdout
    except Exception as exc:
        logger.warning("pip_audit_execution_failed", error=str(exc))
        return []

    return parse_pip_audit_json(stdout, rel_path)


def parse_pip_audit_json(raw_json: str, manifest_rel_path: str) -> list[Finding]:
    """Parse pip-audit JSON into normalized Finding models."""
    if not raw_json or not raw_json.strip():
        return []

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    # pip-audit outputs {"dependencies": [...]}
    deps = data.get("dependencies", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])

    for dep in deps:
        pkg_name = dep.get("name", "")
        pkg_version = dep.get("version", "")
        vulns = dep.get("vulns", [])

        for vuln in vulns:
            vuln_id = vuln.get("id", "VULN")
            aliases = vuln.get("aliases", [])
            # Prefer CVE identifier if present
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

            fix_versions = vuln.get("fix_versions", [])
            fix_str = ", ".join(fix_versions) if fix_versions else "No fix available yet"

            desc = vuln.get("description") or f"Vulnerability {cve_id} in {pkg_name} {pkg_version}"
            desc = desc.strip()

            finding = Finding(
                type=FindingType.DEPENDENCY,
                severity=Severity.HIGH,
                source_tool="pip-audit",
                rule_id=cve_id,
                file=manifest_rel_path,
                line=None,
                code_snippet=f"{pkg_name}=={pkg_version}",
                explanation=f"Package `{pkg_name}` (version `{pkg_version}`) has known vulnerability `{cve_id}`. Fixed in: `{fix_str}`. {desc[:200]}",
                title=f"Vulnerable Dependency: {pkg_name} ({cve_id})",
                fix_suggestion=f"Upgrade `{pkg_name}` to version {fix_str}",
            )
            findings.append(finding)

    return findings


def scan_with_osv_scanner(
    repo_path: Path, manifest_path: Path, timeout_seconds: int = 60
) -> list[Finding]:
    """Fallback scanner using OSV-Scanner if available."""
    osv_bin = shutil.which("osv-scanner")
    if not osv_bin:
        return []

    rel_path = str(manifest_path.relative_to(repo_path)) if manifest_path.is_relative_to(repo_path) else str(manifest_path)
    cmd = [osv_bin, "--json", f"-L={manifest_path}"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return parse_osv_json(proc.stdout, rel_path)
    except Exception as exc:
        logger.warning("osv_scanner_failed", error=str(exc))
        return []


def parse_osv_json(raw_json: str, manifest_rel_path: str) -> list[Finding]:
    """Parse OSV-Scanner JSON output into normalized Finding models."""
    if not raw_json or not raw_json.strip():
        return []

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    results = data.get("results", [])

    for res in results:
        packages = res.get("packages", [])
        for pkg_entry in packages:
            pkg_info = pkg_entry.get("package", {})
            pkg_name = pkg_info.get("name", "")
            pkg_version = pkg_info.get("version", "")
            vulns = pkg_entry.get("vulnerabilities", [])

            for v in vulns:
                v_id = v.get("id", "VULN")
                aliases = v.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), v_id)

                # Extract fixed version from events
                fixed_versions: list[str] = []
                for aff in v.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for evt in rng.get("events", []):
                            if "fixed" in evt:
                                fixed_versions.append(evt["fixed"])

                fix_str = ", ".join(fixed_versions) if fixed_versions else "latest"
                summary = v.get("summary") or f"Vulnerability {cve_id} in {pkg_name}"

                finding = Finding(
                    type=FindingType.DEPENDENCY,
                    severity=Severity.HIGH,
                    source_tool="osv-scanner",
                    rule_id=cve_id,
                    file=manifest_rel_path,
                    line=None,
                    code_snippet=f"{pkg_name}=={pkg_version}",
                    explanation=f"Package `{pkg_name}` ({pkg_version}) is affected by `{cve_id}`. Fixed in: `{fix_str}`. {summary}",
                    title=f"Vulnerable Dependency: {pkg_name} ({cve_id})",
                    fix_suggestion=f"Upgrade `{pkg_name}` to version {fix_str}",
                )
                findings.append(finding)

    return findings
