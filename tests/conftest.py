"""
tests/conftest.py
-----------------
Shared pytest fixtures available to every test module.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.state import ChangeSet


@pytest.fixture()
def sample_changeset(tmp_path: Path) -> ChangeSet:
    """A minimal ChangeSet pointing at a temp directory."""
    return ChangeSet(repo_path=tmp_path, base_ref="main", head_ref="HEAD")
