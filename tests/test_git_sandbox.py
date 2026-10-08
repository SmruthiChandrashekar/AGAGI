"""Tests for Day 4 Git operations, project detector, and sandbox tooling."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from tools.docker_runner import DockerRunResult, is_docker_available
from tools.git_ops import (
    _parse_conflict_hunks,
    cleanup_worktree,
    create_worktree,
    get_diff,
    list_changed_files,
    simulate_merge,
)
from tools.project_detector import detect_project


def test_project_detector_python() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("[tool.poetry]\nname = 'test'\n", encoding="utf-8")
        info = detect_project(root)
        assert info.primary_language == "python"
        assert info.build_system == "poetry"
        assert "poetry run pytest" in (info.test_command or "")
        assert "pyproject.toml" in info.manifest_files


def test_project_detector_node() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "package.json").write_text('{"scripts": {"test": "jest"}}', encoding="utf-8")
        info = detect_project(root)
        assert "javascript" in info.all_languages
        assert info.build_system == "npm"
        assert info.test_command == "npm test"


def test_git_ops_isolated_repo() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)

        # Initialize test git repository
        subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=repo,
            check=True,
            capture_output=True,
        )

        # Commit 1 on main
        file_a = repo / "hello.py"
        file_a.write_text("print('hello')", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True
        )

        # Branch feature
        subprocess.run(
            ["git", "checkout", "-b", "feature"], cwd=repo, check=True, capture_output=True
        )
        file_a.write_text("print('hello world')", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "update"], cwd=repo, check=True, capture_output=True)

        # Switch back to main
        subprocess.run(
            ["git", "checkout", "main"], cwd=repo, check=True, capture_output=True
        )

        # Test diff and changed files
        diff = get_diff(repo, "main", "feature")
        assert "hello world" in diff

        files = list_changed_files(repo, "main", "feature")
        assert "hello.py" in files

        # Test worktree creation and cleanup
        wt = create_worktree(repo, "feature")
        assert (wt / "hello.py").exists()
        cleanup_worktree(repo, wt)
        assert not wt.exists()

        # Test merge simulation clean merge
        merge_res = simulate_merge(repo, "main", "feature")
        assert merge_res.success is True
        assert not merge_res.has_conflict


def test_conflict_hunk_parser() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        conflict_file = Path(tmpdir) / "app.py"
        conflict_file.write_text(
            "<<<<<<< HEAD\n"
            "x = 10\n"
            "=======\n"
            "x = 20\n"
            ">>>>>>> feature/branch\n",
            encoding="utf-8",
        )
        hunks = _parse_conflict_hunks(conflict_file, "app.py")
        assert len(hunks) == 1
        assert hunks[0].file == "app.py"
        assert hunks[0].base_content.strip() == "x = 10"
        assert hunks[0].incoming_content.strip() == "x = 20"


def test_docker_runner_result_model() -> None:
    res = DockerRunResult(
        exit_code=0,
        stdout="passed",
        stderr="",
        timed_out=False,
        duration_seconds=1.2,
    )
    assert res.exit_code == 0
    assert not res.timed_out
    assert isinstance(is_docker_available(), bool)


def test_parse_diff_changed_lines() -> None:
    from tools.git_ops import parse_diff_changed_lines

    sample_diff = (
        "diff --git a/calc.py b/calc.py\n"
        "--- a/calc.py\n"
        "+++ b/calc.py\n"
        "@@ -10,3 +10,4 @@ def add(a, b):\n"
        " return a + b\n"
        "+def multiply(a, b):\n"
        "+    return a * b\n"
    )
    lines_map = parse_diff_changed_lines(sample_diff)
    assert "calc.py" in lines_map
    assert 11 in lines_map["calc.py"] or 12 in lines_map["calc.py"]


def test_sandbox_runner_invalid_workspace() -> None:
    import pytest
    from tools.docker_runner import run_in_sandbox

    with pytest.raises(FileNotFoundError):
        run_in_sandbox("echo hello", Path("/non/existent/path/xyz"))


def test_junit_xml_parser_structured() -> None:
    from tools.junit_parser import parse_junit_xml

    sample_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites>\n'
        '  <testsuite name="pytest" tests="2">\n'
        '    <testcase classname="test_calc.TestCalc" name="test_add" file="test_calc.py" time="0.01" />\n'
        '    <testcase classname="test_calc.TestCalc" name="test_avg" file="test_calc.py" time="0.02">\n'
        '      <failure message="AssertionError: 1 != 2">\n'
        'test_calc.py:25: AssertionError\n'
        '      </failure>\n'
        '    </testcase>\n'
        '  </testsuite>\n'
        '</testsuites>\n'
    )
    cases = parse_junit_xml(sample_xml)
    assert len(cases) == 2
    assert cases[0].status == "passed"
    assert cases[1].status == "failed"
    assert cases[1].failing_file == "test_calc.py"
    assert cases[1].failing_line == 25
    assert cases[1].error_message == "AssertionError: 1 != 2"


def test_baseline_pre_existing_failures_not_blamed() -> None:
    from core.state import ChangeSet
    from core.orchestrator import run_review

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, check=True)

        # Baseline commit on main with pre-existing failing test
        (repo / "calc.py").write_text("def add(a, b): return a + b\n", encoding="utf-8")
        (repo / "test_calc.py").write_text(
            "import unittest\n"
            "from calc import add\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_add(self): self.assertEqual(add(1, 2), 3)\n"
            "    def test_fail_on_main(self): self.assertEqual(1, 2)\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", "init main with bad test"], cwd=repo, check=True)

        # Feature branch adds new feature without touching or causing bad test
        subprocess.run(["git", "checkout", "-b", "feature"], cwd=repo, check=True)
        (repo / "calc.py").write_text("def add(a, b): return a + b\ndef sub(a, b): return a - b\n", encoding="utf-8")
        (repo / "test_calc.py").write_text(
            "import unittest\n"
            "from calc import add, sub\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_add(self): self.assertEqual(add(1, 2), 3)\n"
            "    def test_sub(self): self.assertEqual(sub(3, 1), 2)\n"
            "    def test_fail_on_main(self): self.assertEqual(1, 2)\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "add sub"], cwd=repo, check=True)
        subprocess.run(["git", "checkout", "main"], cwd=repo, check=True)

        cs = ChangeSet(repo_path=repo, base_ref="main", head_ref="feature")
        res = run_review(cs)
        sim = res.get("simulation_result")

        assert sim is not None
        assert sim.status == "passed"
        assert len(sim.regressions) == 0
        assert len(sim.pre_existing_failures) == 1
        assert sim.pre_existing_failures[0].name == "test_fail_on_main"
