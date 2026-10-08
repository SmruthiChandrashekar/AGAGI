"""
agents/fix_agent.py
--------------------
Fix Generator Agent:
  - Takes RCA diagnoses and file contents
  - Generates minimal unified diff patches
  - Validates every patch using 'git apply --check', file containment, and line limits
  - Retries once with feedback on validation failure
  - Leaves real working trees untouched (patches are proposed, not applied)
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from core.llm import chat_structured
from core.logging import get_logger
from core.state import Patch, ReviewState, RootCause

logger = get_logger(__name__)

MAX_PATCH_LINES = 50


class GeneratedPatchOutput(BaseModel):
    """Structured LLM patch output."""

    unified_diff: str = Field(description="Syntactically valid unified diff starting with --- a/ and +++ b/")
    rationale: str = Field(description="Short rationale explaining how the patch fixes the issue")


def validate_patch(patch_diff: str, target_file: str, repo_path: Path) -> tuple[bool, str]:
    """
    Validate that the patch:
      1. Is within the maximum line limit
      2. Touches only the designated RCA target file
      3. Applies cleanly with 'git apply --check'
    """
    clean_diff = patch_diff.strip()
    if not clean_diff:
        return False, "Patch diff is empty"

    lines = clean_diff.splitlines()
    if len(lines) > MAX_PATCH_LINES:
        return False, f"Patch exceeds maximum line limit ({len(lines)} > {MAX_PATCH_LINES} lines)"

    # Check touched files
    touched_files: list[str] = []
    for line in lines:
        if line.startswith("--- a/") or line.startswith("+++ b/"):
            fname = line[6:].strip()
            touched_files.append(fname)

    target_name = Path(target_file).name.lower()
    for tf in touched_files:
        if Path(tf).name.lower() != target_name:
            return False, f"Patch touches file '{tf}' outside RCA target '{target_file}'"

    # Normalize patch header if missing trailing newline
    if not clean_diff.endswith("\n"):
        clean_diff += "\n"

    # Validate with git apply --check
    with tempfile.NamedTemporaryFile(mode="w", suffix=".patch", delete=False, encoding="utf-8") as tmp:
        tmp.write(clean_diff)
        patch_file = Path(tmp.name)

    try:
        proc = subprocess.run(
            ["git", "apply", "--check", "--ignore-whitespace", str(patch_file)],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            return True, ""
        error_msg = (proc.stderr or proc.stdout or "git apply check failed").strip()
        return False, error_msg
    except Exception as exc:
        return False, str(exc)
    finally:
        try:
            patch_file.unlink(missing_ok=True)
        except Exception:
            pass


def _extract_diff_block(raw_text: str) -> str:
    """Extract unified diff from markdown code fences if wrapped."""
    text = raw_text.strip()
    if "```diff" in text:
        m = re.search(r"```diff\s*(.*?)\s*```", text, re.DOTALL)
        if m:
            return m.group(1).strip()
    elif "```" in text:
        m = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL)
        if m:
            return m.group(1).strip()
    return text


def generate_patch_for_root_cause(
    rc: RootCause,
    repo_path: Path,
) -> Patch | None:
    """
    Generate and validate a unified diff patch for a single RootCause.
    Includes 1 automatic retry on validation failure.
    """
    target_rel = rc.root_cause_file
    target_file = repo_path / target_rel
    if not target_file.is_file():
        # Search by file name in repo
        candidates = list(repo_path.rglob(Path(target_rel).name))
        candidates = [c for c in candidates if ".git" not in c.parts and ".venv" not in c.parts]
        if candidates:
            target_file = candidates[0]
            target_rel = str(target_file.relative_to(repo_path))
        else:
            logger.warning("fix_agent_target_file_not_found", target=target_rel)
            return None

    try:
        file_content = target_file.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.warning("fix_agent_read_error", file=str(target_file), error=str(exc))
        return None

    # Line numbered file context for LLM precision
    numbered_lines = [f"{i:4d} | {l}" for i, l in enumerate(file_content.splitlines(), start=1)]
    file_context = "\n".join(numbered_lines[:150])  # Cap context for prompt tokens

    system_prompt = (
        "You are an expert Automated Patch Generation Engineer.\n"
        "Your task is to generate a minimal, syntactically correct unified diff patch that fixes the specified root cause.\n\n"
        "STRICT UNIFIED DIFF RULES:\n"
        "1. The diff MUST start with:\n"
        f"--- a/{target_rel}\n"
        f"+++ b/{target_rel}\n"
        "@@ -start,count +start,count @@\n"
        "2. The patch must apply cleanly via 'git apply'. Match the EXACT indentation, spaces, and context lines of the original file.\n"
        "3. Touch ONLY the minimum lines required to fix the bug or vulnerability.\n"
        "4. Do NOT include markdown fences in the unified_diff string field."
    )

    user_prompt = (
        f"TARGET FILE: {target_rel}\n"
        f"TARGET LINE: {rc.root_cause_line or 'See diagnosis'}\n"
        f"ROOT CAUSE DIAGNOSIS:\n{rc.explanation}\n\n"
        f"CURRENT FILE CONTENTS:\n```\n{file_context}\n```\n\n"
        "Generate a minimal unified diff patch and a concise rationale."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    # Attempt 1
    try:
        res = chat_structured(
            messages=messages,
            schema=GeneratedPatchOutput,
            use_fast=False,
            temperature=0.1,
        )
        diff_text = _extract_diff_block(res.unified_diff)
        valid, err = validate_patch(diff_text, target_rel, repo_path)
        if valid:
            logger.info("fix_agent_patch_validated_attempt_1", file=target_rel)
            return Patch(
                unified_diff=diff_text,
                rationale=res.rationale,
                target_files=[target_rel],
                finding_id=rc.finding_id or rc.id,
            )

        # Retry once with validation feedback
        logger.warning("fix_agent_patch_retry", error=err, file=target_rel)
        retry_prompt = (
            f"The previous patch failed 'git apply --check' with error:\n{err}\n\n"
            f"Original Failed Diff:\n```diff\n{diff_text}\n```\n\n"
            "Please fix the line numbers, exact context lines, and indentation so the patch applies cleanly."
        )
        messages.append({"role": "assistant", "content": res.unified_diff})
        messages.append({"role": "user", "content": retry_prompt})

        res_retry = chat_structured(
            messages=messages,
            schema=GeneratedPatchOutput,
            use_fast=False,
            temperature=0.1,
        )
        retry_diff = _extract_diff_block(res_retry.unified_diff)
        valid2, err2 = validate_patch(retry_diff, target_rel, repo_path)
        if valid2:
            logger.info("fix_agent_patch_validated_attempt_2", file=target_rel)
            return Patch(
                unified_diff=retry_diff,
                rationale=res_retry.rationale,
                target_files=[target_rel],
                finding_id=rc.finding_id or rc.id,
            )
        else:
            logger.warning("fix_agent_patch_failed_after_retry", error=err2, file=target_rel)
            return None

    except Exception as exc:
        logger.warning("fix_agent_generation_error", error=str(exc))
        return None


def run_fix_agent(state: ReviewState) -> dict[str, Any]:
    """
    Generate minimal, verified unified diff patches for each diagnosed RootCause.
    """
    logger.info("stage_start", stage="fix_agent")

    cs = state.get("changeset")
    repo_path = Path(cs.repo_path).resolve() if cs else Path.cwd()

    root_causes: list[RootCause] = state.get("root_causes") or []
    if not root_causes:
        logger.info("fix_agent_skipped_no_root_causes")
        return {"patches": [], "patch_proposals": []}

    accepted_patches: list[Patch] = []

    for rc in root_causes[:5]:  # Cap at top 5 issues per PR
        patch = generate_patch_for_root_cause(rc, repo_path)
        if patch:
            accepted_patches.append(patch)

    logger.info(
        "fix_agent_complete",
        root_causes_count=len(root_causes),
        patches_accepted=len(accepted_patches),
    )

    return {
        "patches": accepted_patches,
        "patch_proposals": accepted_patches,
    }
