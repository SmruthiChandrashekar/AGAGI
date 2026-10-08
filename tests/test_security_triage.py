"""
tests/test_security_triage.py
-----------------------------
Unit tests for Week 4:
  - Scanner execution and JSON normalization (Bandit, Semgrep, Gitleaks)
  - Finding deduplication
  - Dependency scanning (pip-audit / OSV)
  - LLM triage (context extraction, prompt injection defense, false positive filtering)
  - LangGraph review flow with parallel security & dependency nodes
  - Reporter agent grouping and critical finding blocker verdict
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agents.dependency_agent import run_dependency_agent
from agents.reporter_agent import run_reporter_agent
from agents.security_agent import run_security_agent
from agents.triage_agent import (
    FindingTriageOutput,
    compute_file_hash,
    extract_code_context,
    run_triage_agent,
    triage_single_finding,
)
from core.orchestrator import run_review
from core.state import (
    ChangeSet,
    Finding,
    FindingType,
    PipelineStage,
    ReviewVerdict,
    Severity,
    make_initial_state,
)
from tools.bandit_runner import parse_bandit_json, run_bandit
from tools.deduplicator import deduplicate_findings
from tools.gitleaks_runner import parse_gitleaks_json, scan_secrets_builtin
from tools.osv_scanner import is_dependency_manifest, parse_pip_audit_json, run_dependency_scan
from tools.semgrep_runner import parse_semgrep_json, run_semgrep


def test_bandit_parser_normalization():
    raw_bandit = json.dumps({
        "results": [
            {
                "test_id": "B301",
                "test_name": "pickle",
                "issue_severity": "HIGH",
                "issue_cwe": {"id": 502, "link": "https://cwe.mitre.org/502"},
                "filename": "calc.py",
                "line_number": 42,
                "line_range": [42, 43],
                "code": "pickle.loads(payload)",
                "issue_text": "Pickle and modules that wrap it can be unsafe when used with untrusted data.",
            }
        ]
    })
    findings = parse_bandit_json(raw_bandit)
    assert len(findings) == 1
    f = findings[0]
    assert f.source_tool == "bandit"
    assert f.rule_id == "bandit.B301"
    assert f.severity == Severity.HIGH
    assert f.file == "calc.py"
    assert f.line == 42
    assert f.cwe == "CWE-502"
    assert "pickle.loads" in f.code_snippet
    assert "unsafe" in f.explanation


def test_semgrep_parser_normalization():
    raw_semgrep = json.dumps({
        "results": [
            {
                "check_id": "python.lang.security.insecure-hash.insecure-hash-algorithm-md5",
                "path": "app/auth.py",
                "start": {"line": 15, "col": 1},
                "end": {"line": 15, "col": 20},
                "extra": {
                    "severity": "WARNING",
                    "message": "Detected MD5 hash algorithm which is cryptographically broken.",
                    "metadata": {"cwe": ["CWE-327: Use of a Broken Cryptographic Algorithm"]},
                    "lines": "hashlib.md5(pwd.encode()).hexdigest()",
                },
            }
        ]
    })
    findings = parse_semgrep_json(raw_semgrep)
    assert len(findings) == 1
    f = findings[0]
    assert f.source_tool == "semgrep"
    assert f.severity == Severity.MEDIUM
    assert f.file == "app/auth.py"
    assert f.line == 15
    assert f.cwe == "CWE-327"
    assert "hashlib.md5" in f.code_snippet
    assert "broken" in f.explanation


def test_gitleaks_and_secrets_detection(tmp_path: Path):
    secret_file = tmp_path / "creds.py"
    secret_file.write_text(
        'AWS_KEY = "AKIA1234567890ABCDEF"\n'
        'GITHUB_TOKEN = "ghp_123456789012345678901234567890123456"\n',
        encoding="utf-8",
    )
    findings = scan_secrets_builtin(tmp_path, ["creds.py"])
    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    assert "gitleaks.aws-access-token" in rule_ids
    assert "gitleaks.github-pat" in rule_ids
    assert all(f.severity == Severity.CRITICAL for f in findings)
    assert all(f.cwe == "CWE-798" for f in findings)


def test_deduplicate_overlapping_findings():
    f1 = Finding(
        source_tool="bandit",
        rule_id="bandit.B502",
        file="calc.py",
        line=20,
        severity=Severity.HIGH,
        cwe="CWE-502",
        explanation="Deserialization issue",
        code_snippet="pickle.loads(x)",
    )
    f2 = Finding(
        source_tool="semgrep",
        rule_id="semgrep.pickle-avoid",
        file="calc.py",
        line=21,  # nearby line
        severity=Severity.MEDIUM,
        explanation="Avoid pickle deserialization",
        code_snippet="pickle.loads(x)",
    )
    f3 = Finding(
        source_tool="semgrep",
        rule_id="semgrep.sql-injection",
        file="db.py",
        line=99,
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        explanation="SQL injection",
    )

    deduped = deduplicate_findings([f1, f2, f3])
    assert len(deduped) == 2
    merged = next(f for f in deduped if f.file == "calc.py")
    assert "bandit" in merged.source_tool and "semgrep" in merged.source_tool
    assert merged.severity == Severity.HIGH  # preserved higher severity
    assert merged.cwe == "CWE-502"


def test_dependency_scan_manifest_detection_and_parsing(tmp_path: Path):
    assert is_dependency_manifest("requirements.txt") is True
    assert is_dependency_manifest("sub/Pipfile.lock") is True
    assert is_dependency_manifest("calc.py") is False

    raw_pip_audit = json.dumps({
        "dependencies": [
            {
                "name": "insecure-pkg",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "PYSEC-2023-1",
                        "aliases": ["CVE-2023-9999"],
                        "fix_versions": ["1.0.1"],
                        "description": "Remote Code Execution via insecure parsing.",
                    }
                ],
            }
        ]
    })
    findings = parse_pip_audit_json(raw_pip_audit, "requirements.txt")
    assert len(findings) == 1
    f = findings[0]
    assert f.type == FindingType.DEPENDENCY
    assert f.rule_id == "CVE-2023-9999"
    assert "insecure-pkg" in f.title
    assert "1.0.1" in f.explanation
    assert "Upgrade `insecure-pkg` to version 1.0.1" in (f.fix_suggestion or "")


def test_triage_context_extraction_and_file_hash(tmp_path: Path):
    code_file = tmp_path / "math_ops.py"
    lines = [f"def func_{i}(): pass" for i in range(1, 31)]
    lines[14] = "x = eval(untrusted_input)"  # line 15
    code_file.write_text("\n".join(lines), encoding="utf-8")

    fhash = compute_file_hash(code_file)
    assert len(fhash) == 16

    context = extract_code_context(tmp_path, "math_ops.py", line_no=15, context_window=5)
    assert ">>>   15 | x = eval(untrusted_input)" in context
    assert "func_10" in context
    assert "func_20" in context


def test_triage_llm_false_positive_filter(tmp_path: Path):
    code_file = tmp_path / "utils.py"
    code_file.write_text("def test_dummy():\n    mock_key = 'AKIA0000000000000000'\n", encoding="utf-8")

    finding = Finding(
        source_tool="gitleaks",
        rule_id="gitleaks.aws-key",
        file="utils.py",
        line=2,
        severity=Severity.CRITICAL,
        code_snippet="mock_key = 'AKIA0000000000000000'",
        explanation="AWS key detected",
    )

    # Mock LLM classifying as false positive
    mock_triage_output = FindingTriageOutput(
        is_real=False,
        severity=Severity.LOW,
        explanation="This is a test mock fixture key with dummy values, not a real leaked production secret.",
        suggested_fix="No action needed or use env var fixture.",
    )

    with patch("agents.triage_agent.chat_structured", return_value=mock_triage_output):
        res = triage_single_finding(tmp_path, finding)
        assert res.is_real is False
        assert "mock fixture" in res.explanation


def test_triage_agent_run_filters_false_positives(tmp_path: Path):
    real_finding = Finding(
        id="FINDING-REAL",
        source_tool="bandit",
        rule_id="bandit.B608",
        file="db.py",
        line=10,
        severity=Severity.HIGH,
        code_snippet="cursor.execute('SELECT * FROM users WHERE id = ' + uid)",
        explanation="SQL injection via string concatenation",
    )
    fp_finding = Finding(
        id="FINDING-FP",
        source_tool="semgrep",
        rule_id="semgrep.test-eval",
        file="tests.py",
        line=5,
        severity=Severity.MEDIUM,
        code_snippet="eval('1 + 1')",
        explanation="Use of eval",
    )

    # Mock triage responses
    def mock_chat_structured(messages, schema, **kwargs):
        user_content = messages[-1]["content"]
        if "bandit.B608" in user_content:
            return FindingTriageOutput(
                is_real=True,
                severity=Severity.CRITICAL,
                explanation="Direct concatenation of user input into raw SQL query permits full database compromise.",
                suggested_fix="Use parameterized queries with placeholders.",
            )
        else:
            return FindingTriageOutput(
                is_real=False,
                severity=Severity.LOW,
                explanation="Constant expression inside test file is not exploitable.",
                suggested_fix="None.",
            )

    state = {
        "changeset": ChangeSet(repo_path=tmp_path, base_ref="main", head_ref="feat"),
        "security_findings": [real_finding, fp_finding],
        "dependency_findings": [],
    }

    with patch("agents.triage_agent.chat_structured", side_effect=mock_chat_structured):
        out = run_triage_agent(state)
        confirmed = out["findings"]
        assert len(confirmed) == 1
        assert confirmed[0].id == "FINDING-REAL"
        assert confirmed[0].severity == Severity.CRITICAL
        assert "parameterized" in confirmed[0].fix_suggestion


def test_reporter_blocks_on_confirmed_critical_finding():
    critical_finding = Finding(
        source_tool="bandit",
        rule_id="bandit.B608",
        file="app.py",
        line=12,
        severity=Severity.CRITICAL,
        code_snippet="eval(user_input)",
        explanation="Critical remote code execution vulnerability.",
        fix_suggestion="Remove eval",
        is_false_positive=False,
    )

    state = {
        "changeset": ChangeSet(repo_path=Path.cwd(), base_ref="main", head_ref="feat"),
        "merge_outcome": "passed",
        "affected_files": ["app.py"],
        "blast_radius_score": 0.2,
        "findings": [critical_finding],
    }

    res = run_reporter_agent(state)
    assert res["verdict"] == ReviewVerdict.BLOCKED
    assert res["risk_score"] >= 9.5
    assert "CRITICAL FINDINGS [MERGE BLOCKERS]" in res["report_markdown"]
    assert "Critical remote code execution" in res["report_markdown"]
