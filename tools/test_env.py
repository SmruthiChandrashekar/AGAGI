"""
tools/test_env.py
-----------------
Decides WHICH Python runs a target project's tests.

Order of choice:
  1. AGAGI_TARGET_PYTHON environment variable (explicit path to a python)
  2. the project's own virtual environment (.venv / venv / env)
  3. AGAGI's own Python
A candidate is only used if it can actually import pytest.

Other overrides:
  AGAGI_TEST_COMMAND  - replaces the auto-detected test command entirely
  AGAGI_TEST_TIMEOUT  - seconds allowed per test run (default 45)
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from core.logging import get_logger

logger = get_logger(__name__)

DEFAULT_TEST_TIMEOUT = 45
_VENV_NAMES = (".venv", "venv", "env")


def _venv_python(venv: Path) -> Path | None:
    for rel in ("Scripts/python.exe", "bin/python"):
        p = venv / rel
        if p.is_file():
            return p
    return None


def _has_pytest(python: str) -> bool:
    try:
        proc = subprocess.run(
            [python, "-c", "import pytest"],
            capture_output=True, timeout=30, check=False,
        )
        return proc.returncode == 0
    except Exception:
        return False


def resolve_test_python(repo_path: Path | str | None) -> str:
    """Return the python executable to run the target project's tests with."""
    candidates: list[str] = []
    explicit = os.environ.get("AGAGI_TARGET_PYTHON", "").strip()
    if explicit:
        candidates.append(explicit)
    if repo_path:
        for name in _VENV_NAMES:
            py = _venv_python(Path(repo_path) / name)
            if py:
                candidates.append(str(py))
    for cand in candidates:
        if _has_pytest(cand):
            logger.info("test_python_selected", python=cand)
            return cand
        logger.warning("test_python_lacks_pytest", python=cand)
    return sys.executable


def get_test_command_override() -> str | None:
    cmd = os.environ.get("AGAGI_TEST_COMMAND", "").strip()
    return cmd or None


def get_test_timeout(default: int = DEFAULT_TEST_TIMEOUT) -> int:
    try:
        return max(5, int(os.environ.get("AGAGI_TEST_TIMEOUT", default)))
    except ValueError:
        return default
