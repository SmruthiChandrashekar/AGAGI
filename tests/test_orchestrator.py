"""Tests for Day 5 Orchestrator & Agents: ingest -> impact -> merge_simulation -> report."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from core.orchestrator import run_review
from core.state import ChangeSet, PipelineStage, ReviewVerdict


def test_orchestrator_pipeline_flow() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)

        # Initialize git repo
        subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)

        # Initial commit
        (repo / "calc.py").write_text("def add(a, b): return a + b\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

        # Feature branch with a change
        subprocess.run(["git", "checkout", "-b", "feature"], cwd=repo, check=True, capture_output=True)
        (repo / "calc.py").write_text("def add(a, b): return a + b\ndef sub(a, b): return a - b\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "add sub"], cwd=repo, check=True, capture_output=True)

        subprocess.run(["git", "checkout", "main"], cwd=repo, check=True, capture_output=True)

        changeset = ChangeSet(repo_path=repo, base_ref="main", head_ref="feature")
        final_state = run_review(changeset)

        assert final_state["stage"] == PipelineStage.DONE
        assert "calc.py" in final_state["affected_files"]
        assert final_state["merge_outcome"] in ["passed", "all passed", "conflict", "install error", "build error", "test failure", "tests failed", "timeout"]
        assert final_state["verdict"] in [ReviewVerdict.SAFE, ReviewVerdict.NEEDS_CHANGES, ReviewVerdict.BLOCKED]
        assert final_state["report_markdown"] is not None
        assert "# AGENTIC REVIEW REPORT" in final_state["report_markdown"]
