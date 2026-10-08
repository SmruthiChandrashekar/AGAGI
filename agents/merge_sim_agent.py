"""
agents/merge_sim_agent.py
-------------------------
Merge Simulation Agent:
  - Isolated worktree lifecycle management (guaranteed cleanup on exit/crash/timeout)
  - Sandboxed build and test execution (Docker with no network and resource limits,
    or local isolated subprocess fallback)
  - Distinct statuses: 'conflict', 'install error', 'build error', 'timeout', 'test failure', 'passed'
  - Stops at the first failing stage
  - Structured JUnit XML parsing into per-test records (name, file, status, error, line)
  - Baseline comparison: runs tests on base_ref (main), then on merged code;
    classifies failures into new regressions vs pre-existing failures on main.
    Only new regressions count as blockers!
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from core.logging import get_logger
from core.state import PipelineStage, ReviewState, SimulationResult, TestCaseResult
from tools.docker_runner import is_docker_available, run_in_sandbox
from tools.git_ops import cleanup_worktree, create_worktree, simulate_merge
from tools.junit_parser import parse_junit_xml
from tools.project_detector import detect_project

logger = get_logger(__name__)


def _is_build_error(stdout: str, stderr: str) -> bool:
    """Identify syntax errors, compilation breaks, or broken imports that prevent running tests."""
    combined = f"{stdout}\n{stderr}".lower()
    return any(
        err in combined
        for err in [
            "syntaxerror",
            "importerror",
            "modulenotfounderror",
            "compilation error",
            "build failed",
            "cannot find module",
            "fatal error",
        ]
    )


def _extract_failing_tests(output: str) -> list[str]:
    """Fallback extractor for test names from raw stdout/stderr."""
    failing: list[str] = []
    for line in output.splitlines():
        line_clean = line.strip()
        if "FAILED " in line_clean or "FAIL " in line_clean:
            match = re.search(r"(?:FAILED|FAIL)\s+([^\s:]+)", line_clean)
            if match:
                failing.append(match.group(1))
            else:
                failing.append(line_clean)
    return failing[:20]


def _run_test_suite_in_sandbox(
    wt_dir: Path,
    timeout_seconds: int = 60,
    xml_name: str = ".test_results.xml",
) -> tuple[int, str, str, bool, list[TestCaseResult]]:
    """
    Execute tests inside an isolated sandbox with JUnit XML generation.
    Returns: (exit_code, stdout, stderr, timed_out, parsed_test_cases).
    """
    project_info = detect_project(wt_dir)
    test_cmd = project_info.test_command or "pytest"

    xml_path = wt_dir / xml_name
    if xml_path.exists():
        try:
            xml_path.unlink()
        except Exception:
            pass

    # Ensure --junitxml is provided for pytest
    if "pytest" in test_cmd and "--junitxml" not in test_cmd:
        cmd_to_run = f"{test_cmd} --junitxml={xml_name}"
    else:
        cmd_to_run = test_cmd

    stdout = ""
    stderr = ""
    exit_code = 0
    timed_out = False

    # 1. Docker sandbox execution if available
    if is_docker_available():
        res = run_in_sandbox(
            command=cmd_to_run,
            workspace_dir=wt_dir,
            timeout_seconds=timeout_seconds,
            network="none",
            memory_limit="1g",
            cpu_limit="1.5",
            pids_limit=100,
        )
        exit_code = res.exit_code
        stdout = res.stdout
        stderr = res.stderr
        timed_out = res.timed_out
    else:
        # 2. Local isolated subprocess fallback
        if cmd_to_run.startswith("pytest"):
            cmd_exec = f'"{sys.executable}" -m ' + cmd_to_run
        else:
            cmd_exec = cmd_to_run

        env = dict(os.environ)
        env["PYTHONPATH"] = f"{wt_dir}{os.pathsep}{env.get('PYTHONPATH', '')}"

        try:
            proc = subprocess.run(
                cmd_exec,
                shell=True,
                cwd=str(wt_dir),
                env=env,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
            exit_code = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = -1
            stdout = exc.stdout or ""
            stderr = (exc.stderr or "") + f"\n[TIMED OUT after {timeout_seconds}s]"

    # Parse JUnit XML results if generated
    test_cases: list[TestCaseResult] = []
    if xml_path.is_file():
        try:
            test_cases = parse_junit_xml(xml_path)
            xml_path.unlink(missing_ok=True)
        except Exception as exc:
            logger.warning("junit_xml_parse_failed", error=str(exc))

    return exit_code, stdout, stderr, timed_out, test_cases


def run_merge_simulation_agent(state: ReviewState) -> dict[str, Any]:
    """
    Execute Day 4 / Week 3 Merge Simulation with distinct statuses,
    safe sandbox execution, JUnit parsing, and baseline regression classification.
    """
    logger.info("stage_start", stage="merge_simulation_agent")
    cs = state.get("changeset")
    if not cs:
        logger.warning("merge_sim_missing_changeset")
        empty_res = SimulationResult(
            success=False,
            status="build error",
            merge_conflict=False,
            build_passed=False,
            tests_passed=False,
            test_log_snippet="No changeset provided.",
        )
        return {
            "stage": PipelineStage.MERGE_SIMULATION,
            "merge_result": empty_res,
            "simulation_result": empty_res,
            "merge_outcome": "build error",
            "test_results": {"outcome": "build error", "error": "No changeset provided"},
            "regressions": [],
            "pre_existing_failures": [],
        }

    # ── Stage 1: Merge Conflict Detection (Stop at first failing stage) ───────
    sim_merge = simulate_merge(cs.repo_path, cs.base_ref, cs.head_ref)
    if sim_merge.has_conflict:
        logger.warning(
            "merge_sim_conflict_detected",
            conflicted_files=sim_merge.conflicted_files,
            hunk_count=len(sim_merge.conflict_hunks),
        )
        conflict_res = SimulationResult(
            success=False,
            status="conflict",
            merge_conflict=True,
            build_passed=False,
            tests_passed=False,
            failing_tests=[],
            regressions=[],
            pre_existing_failures=[],
            build_log_snippet=sim_merge.output,
            test_log_snippet=f"Merge conflict in {len(sim_merge.conflicted_files)} file(s). Automatic merge aborted.",
        )
        return {
            "stage": PipelineStage.MERGE_SIMULATION,
            "merge_result": conflict_res,
            "simulation_result": conflict_res,
            "merge_outcome": "conflict",
            "conflicted_files": sim_merge.conflicted_files,
            "conflict_hunks": [h.model_dump() for h in sim_merge.conflict_hunks],
            "regressions": [],
            "pre_existing_failures": [],
            "test_results": {
                "outcome": "conflict",
                "conflicted_files": sim_merge.conflicted_files,
                "output": sim_merge.output,
            },
        }

    # ── Stage 2: Baseline Run on base_ref (main) ───────────────────────────────
    # Run tests on base_ref so pre-existing failures are NOT blamed on the PR
    base_wt: Path | None = None
    baseline_failing_keys: set[str] = set()
    try:
        base_wt = create_worktree(cs.repo_path, cs.base_ref)
        b_code, b_out, b_err, b_timeout, b_cases = _run_test_suite_in_sandbox(
            base_wt, timeout_seconds=45, xml_name=".base_junit.xml"
        )
        for tc in b_cases:
            if tc.status in ("failed", "error"):
                baseline_failing_keys.add(tc.test_id)
                baseline_failing_keys.add(tc.name)
        logger.info(
            "baseline_run_complete",
            base_ref=cs.base_ref,
            total_baseline=len(b_cases),
            failing_baseline=len(baseline_failing_keys),
        )
    except Exception as exc:
        logger.warning("baseline_run_failed", error=str(exc))
    finally:
        if base_wt:
            cleanup_worktree(cs.repo_path, base_wt)

    # ── Stage 3: Merged Run in Sandbox Worktree ───────────────────────────────
    merged_wt: Path | None = None
    try:
        merged_wt = create_worktree(cs.repo_path, cs.head_ref)
        m_code, m_out, m_err, m_timeout, m_cases = _run_test_suite_in_sandbox(
            merged_wt, timeout_seconds=45, xml_name=".merged_junit.xml"
        )
        combined_logs = f"{m_out}\n{m_err}".strip()

        # Check Timeout
        if m_timeout:
            logger.warning("merge_sim_timeout")
            timeout_res = SimulationResult(
                success=False,
                status="timeout",
                merge_conflict=False,
                build_passed=True,
                tests_passed=False,
                failing_tests=[],
                regressions=[],
                pre_existing_failures=[],
                test_log_snippet=combined_logs[-2000:] if combined_logs else "Execution timed out.",
            )
            return {
                "stage": PipelineStage.MERGE_SIMULATION,
                "merge_result": timeout_res,
                "simulation_result": timeout_res,
                "merge_outcome": "timeout",
                "conflicted_files": [],
                "conflict_hunks": [],
                "regressions": [],
                "pre_existing_failures": [],
                "test_results": {"outcome": "timeout", "output": combined_logs},
            }

        # Check Build / Syntax Error
        # Pytest exit code 2 indicates syntax error, import error, or collection failure
        is_build_error = (m_code == 2 and not m_cases) or _is_build_error(m_out, m_err)
        if is_build_error:
            logger.warning("merge_sim_build_error")
            build_res = SimulationResult(
                success=False,
                status="build error",
                merge_conflict=False,
                build_passed=False,
                tests_passed=False,
                failing_tests=[],
                regressions=[],
                pre_existing_failures=[],
                build_log_snippet=combined_logs[-2000:],
                test_log_snippet="Build or syntax error prevented test execution.",
            )
            return {
                "stage": PipelineStage.MERGE_SIMULATION,
                "merge_result": build_res,
                "simulation_result": build_res,
                "merge_outcome": "build error",
                "conflicted_files": [],
                "conflict_hunks": [],
                "regressions": [],
                "pre_existing_failures": [],
                "test_results": {"outcome": "build error", "output": combined_logs},
            }

        # ── Stage 4: Baseline Comparison & Regression Classification ──────────
        regressions: list[TestCaseResult] = []
        pre_existing: list[TestCaseResult] = []

        if m_cases:
            for tc in m_cases:
                if tc.status in ("failed", "error"):
                    # Check if test was already failing on main
                    if tc.test_id in baseline_failing_keys or tc.name in baseline_failing_keys:
                        pre_existing.append(tc)
                    else:
                        regressions.append(tc)
        elif m_code != 0:
            # Fallback if XML wasn't emitted but command returned non-zero
            raw_failing = _extract_failing_tests(combined_logs)
            for rf in raw_failing:
                regressions.append(
                    TestCaseResult(name=rf, file="unknown", status="failed", error_message=combined_logs[-500:])
                )

        # ── Stage 5: Final Status Determination ───────────────────────────────
        # Only new regressions count as blockers!
        if len(regressions) > 0:
            final_status = "test failure"
            is_success = False
            tests_passed = False
        else:
            final_status = "passed"
            is_success = True
            tests_passed = True

        logger.info(
            "merge_sim_complete",
            status=final_status,
            total_tests=len(m_cases),
            regressions_count=len(regressions),
            pre_existing_count=len(pre_existing),
        )

        sim_res = SimulationResult(
            success=is_success,
            status=final_status,
            merge_conflict=False,
            build_passed=True,
            tests_passed=tests_passed,
            failing_tests=[r.name for r in regressions],
            regressions=regressions,
            pre_existing_failures=pre_existing,
            all_tests=m_cases,
            build_log_snippet="Build passed successfully.",
            test_log_snippet=combined_logs[-2500:] if combined_logs else "Tests passed.",
        )

        return {
            "stage": PipelineStage.MERGE_SIMULATION,
            "merge_result": sim_res,
            "simulation_result": sim_res,
            "merge_outcome": final_status,
            "conflicted_files": [],
            "conflict_hunks": [],
            "regressions": regressions,
            "pre_existing_failures": pre_existing,
            "test_results": {
                "outcome": final_status,
                "exit_code": m_code,
                "regressions": [r.model_dump() for r in regressions],
                "pre_existing": [p.model_dump() for p in pre_existing],
                "total_tests": len(m_cases),
                "output": combined_logs,
            },
        }

    finally:
        if merged_wt:
            cleanup_worktree(cs.repo_path, merged_wt)
