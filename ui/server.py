"""
ui/server.py
------------
FastAPI backend for the Phosphor HUD Agentic Code Reviewer.
Provides endpoints for GitHub repository & PR exploration,
local git repository management, and running the Day 5 pipeline:
  ingest → impact → merge_simulation → report
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from core.config import settings
from core.logging import get_logger
from core.orchestrator import run_review
from core.state import ChangeSet

logger = get_logger(__name__)

app = FastAPI(
    title="Agentic Reviewer - Phosphor HUD",
    description="Cyberpunk Terminal UI for Autonomous Code Review and Vulnerability Detection",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UI_DIR = Path(__file__).parent


# ── Request / Response Models ────────────────────────────────────────────────


class GitHubAuthRequest(BaseModel):
    token: str = Field(description="GitHub Personal Access Token (classic or fine-grained)")


class GitHubPullsRequest(BaseModel):
    token: str
    repo_full_name: str  # e.g. "octocat/Hello-World"


class ReviewRunRequest(BaseModel):
    repo_path: str = Field(default=".", description="Local repository path or cloned path")
    base_ref: str = Field(default="main", description="Target base branch")
    head_ref: str = Field(default="HEAD", description="Source/PR branch")
    pr_number: int | None = None
    pr_title: str | None = None


class GitHubPRReviewRequest(BaseModel):
    token: str
    repo_full_name: str
    pr_number: int


class CodeSearchRequest(BaseModel):
    query: str
    repo_path: str = Field(default=".", description="Path to repository")


# ── Endpoints ────────────────────────────────────────────────────────────────


@app.get("/")
def serve_index() -> FileResponse:
    """Serve the single-page Phosphor HUD application."""
    index_path = UI_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(index_path)


@app.get("/api/status")
def get_system_status() -> dict[str, Any]:
    """Return backend health, current repo info, and LLM configuration."""
    local_repo = Path(".").resolve()
    current_branch = "unknown"
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=local_repo,
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode == 0:
            current_branch = proc.stdout.strip()
    except Exception:
        pass

    return {
        "status": "SYSTEM_READY",
        "app_env": settings.app_env,
        "primary_model": settings.primary_model,
        "fast_model": settings.fast_model,
        "fallback_model": settings.fallback_model,
        "has_gemini_key": bool(settings.gemini_api_key),
        "has_groq_key": bool(settings.groq_api_key),
        "current_repo_path": str(local_repo),
        "current_branch": current_branch,
    }


@app.get("/api/local/branches")
def get_local_branches(repo_path: str = ".") -> dict[str, Any]:
    """List local branches for the workspace repository or custom repo path."""
    try:
        target = Path(repo_path).resolve()
        proc = subprocess.run(
            ["git", "branch", "--list"],
            cwd=str(target),
            text=True,
            capture_output=True,
            check=False,
        )
        branches: list[str] = []
        current = "main"
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                clean = line.strip()
                if clean.startswith("*"):
                    current = clean[1:].strip()
                    branches.append(current)
                elif clean:
                    branches.append(clean)
        return {"branches": branches or ["main"], "current": current, "repo_path": str(target)}
    except Exception as exc:
        return {"branches": ["main"], "current": "main", "error": str(exc)}


@app.post("/api/github/repos")
def list_github_repos(payload: GitHubAuthRequest) -> dict[str, Any]:
    """List authenticated user's repositories using GitHub PAT."""
    token = payload.token.strip()
    if not token:
        raise HTTPException(status_code=400, detail="GitHub Token required.")

    try:
        from github import Auth, Github

        auth = Auth.Token(token)
        gh = Github(auth=auth)
        user = gh.get_user()
        repos = user.get_repos(sort="updated", direction="desc")

        repo_list = []
        for r in repos[:30]:  # Top 30 recent repos
            repo_list.append(
                {
                    "id": r.id,
                    "name": r.name,
                    "full_name": r.full_name,
                    "private": r.private,
                    "default_branch": r.default_branch,
                    "open_issues_count": r.open_issues_count,
                    "description": r.description or "",
                    "html_url": r.html_url,
                }
            )
        return {"user": user.login, "repos": repo_list}
    except Exception as exc:
        logger.error("github_repos_fetch_error", error=str(exc))
        raise HTTPException(status_code=400, detail=f"GitHub API Error: {exc}") from exc


@app.post("/api/github/pulls")
def list_github_pulls(payload: GitHubPullsRequest) -> dict[str, Any]:
    """List pull requests for a chosen repository (safely handles empty lists)."""
    try:
        from github import Auth, Github

        auth = Auth.Token(payload.token.strip())
        gh = Github(auth=auth)
        repo = gh.get_repo(payload.repo_full_name)

        # First try open PRs
        pulls = repo.get_pulls(state="open", sort="created", direction="desc")
        pr_list: list[dict[str, Any]] = []

        try:
            for pr in pulls:
                pr_list.append(
                    {
                        "number": pr.number,
                        "title": pr.title or f"PR #{pr.number}",
                        "author": pr.user.login if pr.user else "unknown",
                        "base_ref": pr.base.ref if pr.base else "main",
                        "head_ref": pr.head.ref if pr.head else "HEAD",
                        "head_sha": (pr.head.sha[:7] if pr.head and pr.head.sha else ""),
                        "created_at": pr.created_at.isoformat() if pr.created_at else "",
                        "changed_files": getattr(pr, "changed_files", 0) or 0,
                        "html_url": pr.html_url or "",
                        "state": pr.state or "open",
                    }
                )
                if len(pr_list) >= 20:
                    break
        except (IndexError, StopIteration):
            pass

        # If no open PRs, load recent closed/merged PRs so user can still test
        if not pr_list:
            all_pulls = repo.get_pulls(state="all", sort="created", direction="desc")
            try:
                for pr in all_pulls:
                    pr_list.append(
                        {
                            "number": pr.number,
                            "title": pr.title or f"PR #{pr.number}",
                            "author": pr.user.login if pr.user else "unknown",
                            "base_ref": pr.base.ref if pr.base else "main",
                            "head_ref": pr.head.ref if pr.head else "HEAD",
                            "head_sha": (pr.head.sha[:7] if pr.head and pr.head.sha else ""),
                            "created_at": pr.created_at.isoformat() if pr.created_at else "",
                            "changed_files": getattr(pr, "changed_files", 0) or 0,
                            "html_url": pr.html_url or "",
                            "state": pr.state or "closed",
                        }
                    )
                    if len(pr_list) >= 20:
                        break
            except (IndexError, StopIteration):
                pass

        return {"repo": payload.repo_full_name, "pulls": pr_list}
    except Exception as exc:
        logger.error("github_pulls_fetch_error", error=str(exc))
        raise HTTPException(status_code=400, detail=f"Failed to fetch PRs: {exc}") from exc


@app.post("/api/review/run")
def trigger_review(payload: ReviewRunRequest) -> dict[str, Any]:
    """
    Execute the Day 5 pipeline:
      ingest → impact → merge_simulation → report
    """
    repo = Path(payload.repo_path).resolve()
    if not (repo / ".git").exists():
        raise HTTPException(status_code=400, detail=f"Not a git repository: {repo}")

    cs = ChangeSet(
        repo_path=repo,
        base_ref=payload.base_ref,
        head_ref=payload.head_ref,
        pr_number=payload.pr_number,
        pr_title=payload.pr_title,
    )

    try:
        result_state = run_review(cs)
        return {
            "success": True,
            "stage": result_state.get("stage"),
            "verdict": result_state.get("verdict"),
            "risk_score": result_state.get("risk_score"),
            "merge_outcome": result_state.get("merge_outcome"),
            "blast_radius_score": result_state.get("blast_radius_score"),
            "affected_files": result_state.get("affected_files", []),
            "affected_tests": result_state.get("affected_tests", []),
            "changed_functions": [
                (cf.get("name") if isinstance(cf, dict) else str(cf))
                for cf in (result_state.get("changed_functions") or [])
            ],
            "risk_hint": result_state.get("risk_hint"),
            "graph_summary": result_state.get("graph_summary", {}),
            "regressions": [
                (r.model_dump() if hasattr(r, "model_dump") else r)
                for r in (result_state.get("regressions") or [])
            ],
            "pre_existing_failures": [
                (p.model_dump() if hasattr(p, "model_dump") else p)
                for p in (result_state.get("pre_existing_failures") or [])
            ],
            "conflicted_files": result_state.get("conflicted_files", []),
            "conflict_hunks": result_state.get("conflict_hunks", []),
            "findings": [
                (f.model_dump() if hasattr(f, "model_dump") else f)
                for f in (result_state.get("findings") or [])
            ],
            "diff_preview": (result_state.get("diff") or "")[:5000],
            "test_results": result_state.get("test_results", {}),
            "report_markdown": result_state.get("report_markdown"),
            "report_json": result_state.get("report_json"),
        }
    except Exception as exc:
        logger.error("review_pipeline_error", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Pipeline error: {exc}") from exc


@app.post("/api/indexer/search")
def search_code_chunks(payload: CodeSearchRequest) -> dict[str, Any]:
    """Retrieve relevant code chunks matching a natural language or keyword query."""
    try:
        from indexer.embeddings import retrieve

        repo = Path(payload.repo_path).resolve()
        chunks = retrieve(payload.query, repo, top_k=5)
        return {"query": payload.query, "chunks": [c.to_dict() for c in chunks]}
    except Exception as exc:
        logger.error("code_search_error", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Search failed: {exc}") from exc


@app.post("/api/github/review-pr")
def review_remote_pr(payload: GitHubPRReviewRequest) -> dict[str, Any]:
    """
    Fetch a remote GitHub PR into an isolated workspace and run the review pipeline.
    """
    try:
        from github import Auth, Github

        auth = Auth.Token(payload.token.strip())
        gh = Github(auth=auth)
        repo = gh.get_repo(payload.repo_full_name)
        pr = repo.get_pull(payload.pr_number)

        # Clone or fetch PR in a temporary directory
        temp_dir = Path(tempfile.mkdtemp(prefix="gh_pr_"))

        # Clone target repository
        clone_url = pr.base.repo.clone_url.replace(
            "https://", f"https://x-access-token:{payload.token.strip()}@"
        )
        subprocess.run(
            ["git", "clone", "--depth", "50", clone_url, str(temp_dir)],
            check=True,
            capture_output=True,
        )

        # Fetch PR head ref
        subprocess.run(
            ["git", "fetch", "origin", f"pull/{pr.number}/head:pr_{pr.number}"],
            cwd=temp_dir,
            check=True,
            capture_output=True,
        )

        cs = ChangeSet(
            repo_path=temp_dir,
            base_ref=pr.base.ref,
            head_ref=f"pr_{pr.number}",
            pr_number=pr.number,
            pr_title=pr.title,
            pr_author=pr.user.login,
        )

        result_state = run_review(cs)
        return {
            "success": True,
            "pr_number": pr.number,
            "pr_title": pr.title,
            "author": pr.user.login,
            "stage": result_state.get("stage"),
            "verdict": result_state.get("verdict"),
            "risk_score": result_state.get("risk_score"),
            "merge_outcome": result_state.get("merge_outcome"),
            "blast_radius_score": result_state.get("blast_radius_score"),
            "affected_files": result_state.get("affected_files", []),
            "affected_tests": result_state.get("affected_tests", []),
            "changed_functions": [
                (cf.get("name") if isinstance(cf, dict) else str(cf))
                for cf in (result_state.get("changed_functions") or [])
            ],
            "risk_hint": result_state.get("risk_hint"),
            "graph_summary": result_state.get("graph_summary", {}),
            "regressions": [
                (r.model_dump() if hasattr(r, "model_dump") else r)
                for r in (result_state.get("regressions") or [])
            ],
            "pre_existing_failures": [
                (p.model_dump() if hasattr(p, "model_dump") else p)
                for p in (result_state.get("pre_existing_failures") or [])
            ],
            "findings": [
                (f.model_dump() if hasattr(f, "model_dump") else f)
                for f in (result_state.get("findings") or [])
            ],
            "conflicted_files": result_state.get("conflicted_files", []),
            "conflict_hunks": result_state.get("conflict_hunks", []),
            "diff_preview": (result_state.get("diff") or "")[:5000],
            "test_results": result_state.get("test_results", {}),
            "report_markdown": result_state.get("report_markdown"),
        }
    except Exception as exc:
        logger.error("remote_pr_review_error", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Remote review error: {exc}") from exc


def start_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Launch the Uvicorn web server."""
    import uvicorn

    uvicorn.run("ui.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    start_server()
