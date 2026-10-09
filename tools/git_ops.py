"""
tools/git_ops.py
----------------
Git operations for diff inspection, worktree lifecycle management,
and merge conflict detection in isolated worktrees.
"""

from __future__ import annotations

import contextlib
import re
import shutil
import subprocess
import tempfile
from collections.abc import Generator
from pathlib import Path

from pydantic import BaseModel, Field

from core.logging import get_logger

logger = get_logger(__name__)


class ConflictHunk(BaseModel):
    """A single conflict region parsed from a conflicted file."""

    file: str
    base_content: str = Field(description="Content from the target / base branch (HEAD)")
    incoming_content: str = Field(description="Content from the branch being merged in")
    raw_hunk: str = Field(description="Full text containing <<<<<<<, =======, >>>>>>> markers")
    start_line: int | None = None


class MergeSimulationResult(BaseModel):
    """Detailed outcome of a merge attempt in an isolated worktree."""

    success: bool
    has_conflict: bool = False
    conflicted_files: list[str] = Field(default_factory=list)
    conflict_hunks: list[ConflictHunk] = Field(default_factory=list)
    worktree_path: str | None = None
    output: str = ""


# ── Low-Level Git Command Runner ─────────────────────────────────────────────


def _run_git(
    cmd: list[str],
    cwd: Path | str,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Execute a git command in the given repository path."""
    cwd_path = Path(cwd).resolve()
    proc = subprocess.run(
        ["git", *cmd],
        cwd=str(cwd_path),
        text=True,
        capture_output=capture_output,
        check=False,
    )
    if check and proc.returncode != 0:
        err_msg = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"Git command failed: {' '.join(cmd)}\nError: {err_msg}")
    return proc


# ── Diff & Changes ────────────────────────────────────────────────────────────


def get_diff(repo_path: Path | str, base_ref: str, head_ref: str) -> str:
    """
    Compute unified diff between base_ref and head_ref.
    Prefers triple-dot diff (merge base) to isolate branch changes.
    """
    res = _run_git(["diff", f"{base_ref}...{head_ref}"], cwd=repo_path, check=False)
    if res.returncode == 0:
        return res.stdout

    # Fallback to two-dot diff if triple-dot fails
    res_two = _run_git(["diff", base_ref, head_ref], cwd=repo_path, check=True)
    return res_two.stdout


def list_changed_files(repo_path: Path | str, base_ref: str, head_ref: str) -> list[str]:
    """Return list of files modified, added, or deleted between refs."""
    res = _run_git(
        ["diff", "--name-only", f"{base_ref}...{head_ref}"],
        cwd=repo_path,
        check=False,
    )
    if res.returncode != 0:
        res = _run_git(["diff", "--name-only", base_ref, head_ref], cwd=repo_path, check=True)
    return [line.strip() for line in res.stdout.splitlines() if line.strip()]


def parse_diff_changed_lines(diff_text: str) -> dict[str, list[int]]:
    """
    Parse a unified diff and return a mapping of filename -> list of changed line numbers.
    Tracks line numbers from hunk headers @@ -old_start,old_len +new_start,new_len @@.
    """
    changed: dict[str, list[int]] = {}
    current_file: str | None = None
    new_line = 0

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            changed.setdefault(current_file, [])
        elif line.startswith("--- "):
            continue
        elif line.startswith("@@ ") and current_file:
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if match:
                new_line = int(match.group(1))
        elif current_file and (line.startswith("+") and not line.startswith("+++")):
            changed[current_file].append(new_line)
            new_line += 1
        elif current_file and not line.startswith("-"):
            new_line += 1

    return changed


# ── Worktree Management ───────────────────────────────────────────────────────


def create_worktree(
    repo_path: Path | str,
    commit_or_ref: str,
    target_dir: Path | str | None = None,
) -> Path:
    """
    Create an isolated worktree at target_dir (or a temporary path) checked out
    at the specified commit or ref (detached HEAD).
    """
    repo = Path(repo_path).resolve()
    if target_dir is None:
        target = Path(tempfile.mkdtemp(prefix="worktree_"))
    else:
        target = Path(target_dir).resolve()
        target.mkdir(parents=True, exist_ok=True)

    # Detached worktree avoids 'branch already checked out' errors
    _run_git(["worktree", "add", "--detach", str(target), commit_or_ref], cwd=repo, check=True)
    logger.debug("worktree_created", path=str(target), ref=commit_or_ref)
    return target


def cleanup_worktree(repo_path: Path | str, worktree_path: Path | str) -> None:
    """Safely remove a worktree and prune metadata."""
    repo = Path(repo_path).resolve()
    wt = Path(worktree_path).resolve()
    try:
        _run_git(["worktree", "remove", "--force", str(wt)], cwd=repo, check=False)
    except Exception as exc:
        logger.warning("worktree_remove_failed", path=str(wt), error=str(exc))

    _run_git(["worktree", "prune"], cwd=repo, check=False)

    if wt.exists():
        with contextlib.suppress(Exception):
            shutil.rmtree(wt, ignore_errors=True)
    logger.debug("worktree_cleaned", path=str(wt))


@contextlib.contextmanager
def temp_worktree(
    repo_path: Path | str,
    commit_or_ref: str,
) -> Generator[Path, None, None]:
    """Context manager yielding a temporary worktree, ensuring automatic cleanup."""
    wt = create_worktree(repo_path, commit_or_ref)
    try:
        yield wt
    finally:
        cleanup_worktree(repo_path, wt)


# ── Merge Simulation & Conflict Parser ────────────────────────────────────────

_CONFLICT_REGEX = re.compile(
    r"<<<<<<<\s*(?:HEAD|[^\n]+)\n(.*?)\n=======\n(.*?)\n>>>>>>>\s*[^\n]+",
    re.DOTALL,
)


def _parse_conflict_hunks(file_path: Path, relative_name: str) -> list[ConflictHunk]:
    """Parse merge conflict markers from a file."""
    if not file_path.is_file():
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    hunks: list[ConflictHunk] = []
    for match in _CONFLICT_REGEX.finditer(text):
        base_side = match.group(1)
        incoming_side = match.group(2)
        raw = match.group(0)
        hunks.append(
            ConflictHunk(
                file=relative_name,
                base_content=base_side,
                incoming_content=incoming_side,
                raw_hunk=raw,
            )
        )
    return hunks


def simulate_merge(
    repo_path: Path | str,
    base_ref: str,
    head_ref: str,
) -> MergeSimulationResult:
    """
    Simulate merging head_ref into base_ref in a fresh isolated worktree.
    Does NOT affect the working directory or main branches.
    Returns conflicted files and conflict hunks if conflicts occur.
    """
    repo = Path(repo_path).resolve()
    wt_dir = Path(tempfile.mkdtemp(prefix="merge_sim_"))

    try:
        create_worktree(repo, base_ref, target_dir=wt_dir)
        # Attempt merge without committing
        merge_res = _run_git(
            ["merge", "--no-commit", "--no-ff", head_ref],
            cwd=wt_dir,
            check=False,
        )

        if merge_res.returncode == 0:
            # Clean merge
            return MergeSimulationResult(
                success=True,
                has_conflict=False,
                conflicted_files=[],
                conflict_hunks=[],
                worktree_path=str(wt_dir),
                output=merge_res.stdout,
            )

        # Merge failed or had conflicts
        # Detect unmerged files
        diff_res = _run_git(
            ["diff", "--name-only", "--diff-filter=U"],
            cwd=wt_dir,
            check=False,
        )
        conflicted_files = [f.strip() for f in diff_res.stdout.splitlines() if f.strip()]

        # Parse conflict hunks for each file
        all_hunks: list[ConflictHunk] = []
        for cfile in conflicted_files:
            hunks = _parse_conflict_hunks(wt_dir / cfile, cfile)
            all_hunks.extend(hunks)

        # Abort the merge in the temporary worktree
        _run_git(["merge", "--abort"], cwd=wt_dir, check=False)

        return MergeSimulationResult(
            success=False,
            has_conflict=len(conflicted_files) > 0,
            conflicted_files=conflicted_files,
            conflict_hunks=all_hunks,
            worktree_path=str(wt_dir),
            output=merge_res.stderr or merge_res.stdout,
        )

    finally:
        cleanup_worktree(repo, wt_dir)


# ── Merged Workspaces (Week 6) ────────────────────────────────────────────────
#
# Agents must look at the code that would exist AFTER the merge, not at whatever
# branch the user's own folder currently has checked out. These helpers build a
# throwaway worktree of base_ref with head_ref merged in.

_MERGE_IDENTITY = [
    "-c",
    "user.name=Agentic Reviewer",
    "-c",
    "user.email=agentic-reviewer@localhost",
]


def create_merged_worktree(repo_path: Path | str, base_ref: str, head_ref: str) -> Path:
    """
    Create a temporary worktree at base_ref with head_ref merged in (merge committed).
    Raises RuntimeError if the merge does not apply cleanly; nothing is left behind.
    """
    repo = Path(repo_path).resolve()
    wt = create_worktree(repo, base_ref)
    res = _run_git(
        [*_MERGE_IDENTITY, "merge", "--no-ff", "--no-edit", head_ref],
        cwd=wt,
        check=False,
    )
    if res.returncode != 0:
        _run_git(["merge", "--abort"], cwd=wt, check=False)
        cleanup_worktree(repo, wt)
        err = (res.stderr or res.stdout or "").strip()
        raise RuntimeError(f"Merging {head_ref} into {base_ref} failed: {err[:500]}")
    logger.debug("merged_worktree_created", path=str(wt), base=base_ref, head=head_ref)
    return wt


@contextlib.contextmanager
def review_workspace(
    repo_path: Path | str,
    base_ref: str,
    head_ref: str,
) -> Generator[Path, None, None]:
    """
    Yield a directory holding the code under review, cleaned up afterwards.

    Preference order:
      1. base_ref with head_ref merged in (what would land after merging)
      2. head_ref alone (when the merge conflicts)
      3. the repository folder itself (last resort, never deleted)
    """
    repo = Path(repo_path).resolve()
    wt: Path | None = None
    try:
        try:
            wt = create_merged_worktree(repo, base_ref, head_ref)
        except Exception as exc:
            logger.info("review_workspace_merge_unavailable", error=str(exc)[:200])
            try:
                wt = create_worktree(repo, head_ref)
            except Exception as exc2:
                logger.warning("review_workspace_fallback_to_repo", error=str(exc2)[:200])
                wt = None
        yield wt if wt is not None else repo
    finally:
        if wt is not None:
            cleanup_worktree(repo, wt)


def apply_patch(worktree: Path | str, unified_diff: str, check_only: bool = False) -> tuple[bool, str]:
    """
    Apply (or with check_only, just test) a unified diff inside a worktree.
    Uses --recount because model-written hunk headers often miscount lines.
    Returns (ok, error_message).
    """
    text = unified_diff if unified_diff.endswith("\n") else unified_diff + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".patch", delete=False, encoding="utf-8", newline="\n"
    ) as tmp:
        tmp.write(text)
        patch_file = Path(tmp.name)
    try:
        args = ["apply", "--recount", "--ignore-whitespace", "--whitespace=nowarn"]
        if check_only:
            args.append("--check")
        res = _run_git([*args, str(patch_file)], cwd=worktree, check=False)
        if res.returncode == 0:
            return True, ""
        return False, (res.stderr or res.stdout or "git apply failed").strip()
    finally:
        with contextlib.suppress(Exception):
            patch_file.unlink(missing_ok=True)
