"""Tests for UI backend server and endpoints."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from ui.server import app

client = TestClient(app)


def test_ui_index_endpoint() -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Agentic Reviewer" in resp.text
    assert "Review" in resp.text


def test_ui_status_endpoint() -> None:
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SYSTEM_READY"
    assert "primary_model" in data


def test_ui_local_branches() -> None:
    resp = client.get("/api/local/branches")
    assert resp.status_code == 200
    data = resp.json()
    assert "branches" in data


def test_ui_run_review_endpoint() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)

        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

        subprocess.run(["git", "checkout", "-b", "feat"], cwd=repo, check=True, capture_output=True)
        (repo / "app.py").write_text("x = 2\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "change"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "checkout", "main"], cwd=repo, check=True, capture_output=True)

        resp = client.post(
            "/api/review/run",
            json={"repo_path": str(repo), "base_ref": "main", "head_ref": "feat"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["merge_outcome"] in ["passed", "all passed", "conflict", "install error", "build error", "test failure", "tests failed", "timeout"]
        assert "app.py" in data["affected_files"]
