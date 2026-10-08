"""
tools/build_calc_demo.py
-------------------------
Builder script for the calc-demo repository.
Creates / updates the repository with all 5 canonical branches:
  1. main: base implementation (calc.py, report.py, test_calc.py, test_report.py)
  2. clean-merge: adds multiply() and test_multiply(). Merges cleanly and passes tests.
  3. breaks-test: changes average(nums) to average(nums, round_to). Merges cleanly but fails test suite.
  4. conflict: conflicting edits on calc.py against main, triggering a merge conflict.
  5. build-error: syntax error in calc.py, triggering build/compilation failure during test collection.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git"] + args,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=True,
    )


def build_calc_demo(target_dir: Path | str) -> Path:
    repo_path = Path(target_dir).resolve()
    repo_path.mkdir(parents=True, exist_ok=True)

    # 1. Initialize git if not already a repo
    if not (repo_path / ".git").exists():
        _run_git(["init", "-b", "main"], cwd=repo_path)
        _run_git(["config", "user.name", "Agentic Reviewer"], cwd=repo_path)
        _run_git(["config", "user.email", "dev@agentic-reviewer.local"], cwd=repo_path)

    # Base files
    calc_py = '''"""Basic arithmetic functions."""


def add(a, b):
    return a + b


def subtract(a, b):
    return a - b


def average(nums):
    if not nums:
        return 0
    return sum(nums) / len(nums)
'''

    report_py = '''"""Report generator using calculator functions."""

from calc import add, subtract, average


def generate_report(numbers):
    total = sum(numbers)
    avg = average(numbers)
    return {
        "count": len(numbers),
        "total": total,
        "average": avg,
    }


if __name__ == "__main__":
    sample = [10, 20, 30, 40]
    print(generate_report(sample))
'''

    test_calc_py = '''import unittest
from calc import add, subtract, average


class TestCalc(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(-1, 1), 0)

    def test_subtract(self):
        self.assertEqual(subtract(5, 3), 2)
        self.assertEqual(subtract(0, 4), -4)

    def test_average(self):
        self.assertEqual(average([1, 2, 3, 4, 5]), 3.0)
        self.assertEqual(average([10, 20]), 15.0)
        self.assertEqual(average([]), 0)


if __name__ == "__main__":
    unittest.main()
'''

    test_report_py = '''import unittest
from report import generate_report


class TestReport(unittest.TestCase):
    def test_generate_report(self):
        res = generate_report([10, 20, 30])
        self.assertEqual(res["count"], 3)
        self.assertEqual(res["total"], 60)
        self.assertEqual(res["average"], 20.0)


if __name__ == "__main__":
    unittest.main()
'''

    gitignore = '''__pycache__/
*.pyc
.pytest_cache/
'''

    # Ensure main branch exists
    try:
        _run_git(["checkout", "-B", "main"], cwd=repo_path)
    except Exception:
        pass

    (repo_path / "calc.py").write_text(calc_py, encoding="utf-8")
    (repo_path / "report.py").write_text(report_py, encoding="utf-8")
    (repo_path / "test_calc.py").write_text(test_calc_py, encoding="utf-8")
    (repo_path / "test_report.py").write_text(test_report_py, encoding="utf-8")
    (repo_path / ".gitignore").write_text(gitignore, encoding="utf-8")

    _run_git(["add", "."], cwd=repo_path)
    try:
        _run_git(["commit", "-m", "Initial commit: basic calculator and report"], cwd=repo_path)
    except subprocess.CalledProcessError:
        pass  # Already committed

    base_commit = _run_git(["rev-parse", "HEAD"], cwd=repo_path).stdout.strip()

    # ── 2. clean-merge branch ────────────────────────────────────────────────
    _run_git(["checkout", "-B", "clean-merge", base_commit], cwd=repo_path)
    clean_calc = '''"""Basic arithmetic functions."""


def add(a, b):
    return a + b


def subtract(a, b):
    return a - b


def multiply(a, b):
    """Multiply two numbers."""
    return a * b


def average(nums):
    if not nums:
        return 0
    return sum(nums) / len(nums)
'''
    clean_test = '''import unittest
from calc import add, subtract, multiply, average


class TestCalc(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(-1, 1), 0)

    def test_subtract(self):
        self.assertEqual(subtract(5, 3), 2)
        self.assertEqual(subtract(0, 4), -4)

    def test_multiply(self):
        self.assertEqual(multiply(3, 4), 12)
        self.assertEqual(multiply(-2, 3), -6)

    def test_average(self):
        self.assertEqual(average([1, 2, 3, 4, 5]), 3.0)
        self.assertEqual(average([10, 20]), 15.0)
        self.assertEqual(average([]), 0)


if __name__ == "__main__":
    unittest.main()
'''
    (repo_path / "calc.py").write_text(clean_calc, encoding="utf-8")
    (repo_path / "test_calc.py").write_text(clean_test, encoding="utf-8")
    _run_git(["add", "."], cwd=repo_path)
    try:
        _run_git(["commit", "-m", "feat: add multiply() function and tests"], cwd=repo_path)
    except subprocess.CalledProcessError:
        pass

    # ── 3. breaks-test branch ────────────────────────────────────────────────
    _run_git(["checkout", "-B", "breaks-test", base_commit], cwd=repo_path)
    breaks_calc = '''"""Basic arithmetic functions."""


def add(a, b):
    return a + b


def subtract(a, b):
    return a - b


def average(nums, round_to):
    """Calculate rounded average."""
    if not nums:
        return 0
    return round(sum(nums) / len(nums), round_to)
'''
    (repo_path / "calc.py").write_text(breaks_calc, encoding="utf-8")
    _run_git(["add", "."], cwd=repo_path)
    try:
        _run_git(["commit", "-m", "feat: change average(nums) signature to require round_to"], cwd=repo_path)
    except subprocess.CalledProcessError:
        pass

    # ── 4. conflict branch ──────────────────────────────────────────────────
    _run_git(["checkout", "-B", "conflict", base_commit], cwd=repo_path)
    conflict_calc = '''"""Basic arithmetic functions with alternate changes."""


def add(a, b):
    # Altered implementation from conflict branch
    return int(a) + int(b)


def subtract(a, b):
    return int(a) - int(b)


def average(nums):
    if not nums:
        return 0
    return sum(nums) / len(nums)
'''
    (repo_path / "calc.py").write_text(conflict_calc, encoding="utf-8")
    _run_git(["add", "."], cwd=repo_path)
    try:
        _run_git(["commit", "-m", "feat: convert arguments to int in calc.py"], cwd=repo_path)
    except subprocess.CalledProcessError:
        pass

    # Switch back to main and add a conflicting commit to line 4-8 in calc.py
    _run_git(["checkout", "main"], cwd=repo_path)
    main_conflicting_calc = '''"""Basic arithmetic functions with docstrings."""


def add(a, b):
    """Add two numbers strictly as floats."""
    return float(a) + float(b)


def subtract(a, b):
    """Subtract two numbers strictly as floats."""
    return float(a) - float(b)


def average(nums):
    if not nums:
        return 0
    return sum(nums) / len(nums)
'''
    (repo_path / "calc.py").write_text(main_conflicting_calc, encoding="utf-8")
    _run_git(["add", "."], cwd=repo_path)
    try:
        _run_git(["commit", "-m", "docs: update add and subtract implementations on main"], cwd=repo_path)
    except subprocess.CalledProcessError:
        pass

    # ── 5. build-error branch (branched from current main so it merges cleanly but fails syntax check) ──
    _run_git(["checkout", "-B", "build-error", "main"], cwd=repo_path)
    build_err_calc = (repo_path / "calc.py").read_text(encoding="utf-8") + "\n\ndef broken():\n    return +++  # Syntax error\n"
    (repo_path / "calc.py").write_text(build_err_calc, encoding="utf-8")
    _run_git(["add", "."], cwd=repo_path)
    try:
        _run_git(["commit", "-m", "fix: introduced syntax error in calc.py"], cwd=repo_path)
    except subprocess.CalledProcessError:
        pass

    _run_git(["checkout", "main"], cwd=repo_path)

    return repo_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build or reset the calc-demo test repository.")
    parser.add_argument(
        "--target",
        "-t",
        default=r"C:\Users\LENOVO\Desktop\calculator",
        help="Path where calc-demo repo should be built",
    )
    args = parser.parse_args()
    path = build_calc_demo(args.target)
    print(f"Successfully configured calc-demo repository at: {path}")
