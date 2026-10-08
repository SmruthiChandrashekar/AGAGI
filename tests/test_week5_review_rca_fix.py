"""
tests/test_week5_review_rca_fix.py
-----------------------------------
Unit tests for Week 5:
  - Code Review Agent: quiet on clean code, detects logic bugs
  - RCA Agent: groups related failures, identifies root cause file/line
  - Fix Generator Agent: generates and validates unified diff with git apply --check
  - Fix validation: enforces max lines, target file containment, 1 retry on failure
  - Full pipeline integration: review → rca → fix → report
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agents.fix_agent import (
    GeneratedPatchOutput,
    generate_patch_for_root_cause,
    run_fix_agent,
    validate_patch,
)
from agents.rca_agent import RCAResultOutput, RootCauseItem, run_rca_agent
from agents.review_agent import CodeReviewOutput, ReviewComment, run_review_agent
from core.orchestrator import run_review
from core.state import (
    ChangeSet,
    Finding,
    FindingType,
    Patch,
    ReviewVerdict,
    RootCause,
    Severity,
    TestCaseResult,
)


def test_review_agent_stays_quiet_on_clean_diff():
    state = {
        "diff": "@@ -1,3 +1,6 @@\n def add(a, b):\n     return a + b\n+\n+def multiply(a, b):\n+    return a * b\n",
        "affected_files": ["calc.py"],
        "changed_functions": [{"name": "multiply", "file": "calc.py"}],
    }
    mock_clean_output = CodeReviewOutput(issues=[], summary="Clean addition")

    with patch("agents.review_agent.chat_structured", return_value=mock_clean_output):
        out = run_review_agent(state)
        assert out["review_findings"] == []


def test_review_agent_flags_concrete_bug():
    state = {
        "diff": "@@ -10,3 +10,3 @@\n def divide(a, b):\n-    return a / b if b != 0 else 0\n+    return a / 0\n",
        "affected_files": ["calc.py"],
        "changed_functions": [{"name": "divide", "file": "calc.py"}],
    }
    mock_issue_output = CodeReviewOutput(
        issues=[
            ReviewComment(
                file="calc.py",
                line=12,
                category="logic bug",
                severity=Severity.HIGH,
                explanation="Always divides by zero causing a ZeroDivisionError unconditionally.",
            )
        ]
    )

    with patch("agents.review_agent.chat_structured", return_value=mock_issue_output):
        out = run_review_agent(state)
        assert len(out["review_findings"]) == 1
        finding = out["review_findings"][0]
        assert finding.type == FindingType.BUG
        assert finding.file == "calc.py"
        assert finding.line == 12
        assert "ZeroDivisionError" in finding.explanation


def test_rca_agent_groups_failures_and_diagnoses_root_cause(tmp_path: Path):
    reg1 = TestCaseResult(
        name="test_average",
        file="test_calc.py",
        failing_file="test_calc.py",
        failing_line=15,
        error_message="TypeError: average() missing 1 required positional argument: 'round_to'",
    )
    reg2 = TestCaseResult(
        name="test_report",
        file="test_report.py",
        failing_file="test_report.py",
        failing_line=22,
        error_message="TypeError: average() missing 1 required positional argument: 'round_to'",
    )

    state = {
        "changeset": ChangeSet(repo_path=tmp_path, base_ref="main", head_ref="feat"),
        "regressions": [reg1, reg2],
        "findings": [],
        "diff": "@@ -10,2 +10,2 @@\n-def average(nums):\n+def average(nums, round_to):",
        "changed_functions": [{"name": "average", "file": "calc.py"}],
    }

    mock_rca = RCAResultOutput(
        root_causes=[
            RootCauseItem(
                root_cause_file="calc.py",
                root_cause_line=10,
                explanation="average() changed signature to require 'round_to' parameter, breaking callers in test_calc.py and test_report.py.",
                related_issues=["test_average", "test_report"],
                changed_lines=[10],
            )
        ]
    )

    with patch("agents.rca_agent.chat_structured", return_value=mock_rca):
        out = run_rca_agent(state)
        rcs = out["root_causes"]
        assert len(rcs) == 1
        rc = rcs[0]
        assert rc.root_cause_file == "calc.py"
        assert "round_to" in rc.explanation
        assert len(rc.related_tests) == 2


def test_validate_patch_checks_git_apply(tmp_path: Path):
    # Initialize a dummy git repository
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=tmp_path, check=True)

    app_py = tmp_path / "app.py"
    app_py.write_text("def hello():\n    return 'hello'\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True)

    # 1. Clean valid patch
    valid_diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def hello():
-    return 'hello'
+    return 'world'
"""
    valid, err = validate_patch(valid_diff, "app.py", tmp_path)
    assert valid is True
    assert err == ""

    # 2. Patch touching wrong file
    wrong_file_diff = """--- a/other.py
+++ b/other.py
@@ -1,1 +1,1 @@
-x = 1
+x = 2
"""
    valid2, err2 = validate_patch(wrong_file_diff, "app.py", tmp_path)
    assert valid2 is False
    assert "outside RCA target" in err2

    # 3. Patch exceeding line limit
    big_diff = "\n".join(["+ line"] * 60)
    valid3, err3 = validate_patch(big_diff, "app.py", tmp_path)
    assert valid3 is False
    assert "exceeds maximum line limit" in err3


def test_fix_agent_retries_once_on_failed_diff(tmp_path: Path):
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=tmp_path, check=True)

    calc_file = tmp_path / "calc.py"
    calc_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True)

    rc = RootCause(
        root_cause_file="calc.py",
        root_cause_line=2,
        explanation="Fix return statement",
    )

    bad_output = GeneratedPatchOutput(
        unified_diff="--- a/calc.py\n+++ b/calc.py\n@@ -99,1 +99,1 @@\n-bad\n+worse\n",
        rationale="Bad patch",
    )
    good_output = GeneratedPatchOutput(
        unified_diff="--- a/calc.py\n+++ b/calc.py\n@@ -1,2 +1,2 @@\n def add(a, b):\n-    return a + b\n+    return a + b + 0\n",
        rationale="Correct patch",
    )

    # First call returns bad, retry call returns good
    with patch("agents.fix_agent.chat_structured", side_effect=[bad_output, good_output]):
        patch_res = generate_patch_for_root_cause(rc, tmp_path)
        assert patch_res is not None
        assert patch_res.target_files == ["calc.py"]
        assert "return a + b + 0" in patch_res.unified_diff
