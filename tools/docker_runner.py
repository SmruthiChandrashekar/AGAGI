"""
tools/docker_runner.py
----------------------
Executes untrusted build and test commands in an isolated Docker sandbox
with strictly disabled networking, capped memory/CPU limits, and timeouts.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from pydantic import BaseModel

from core.logging import get_logger

logger = get_logger(__name__)


class DockerRunResult(BaseModel):
    """Execution output from a sandboxed container run."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_seconds: float = 0.0
    container_id: str | None = None


def is_docker_available() -> bool:
    """Check if the docker command-line tool and daemon are accessible."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def run_in_sandbox(
    command: list[str] | str,
    workspace_dir: Path | str,
    image: str = "agentic-reviewer/sandbox-python:latest",
    *,
    timeout_seconds: int = 120,
    network: str = "none",
    memory_limit: str = "1g",
    cpu_limit: str = "1.5",
    pids_limit: int = 100,
    env_vars: dict[str, str] | None = None,
) -> DockerRunResult:
    """
    Run an arbitrary build/test command inside an isolated Docker container.

    Security & containment rules:
      - --network none: no outbound/inbound network access
      - --memory: hard RAM cap to prevent OOM DOS
      - --cpus: limit CPU quota
      - --pids-limit: prevent fork bombs
      - --security-opt no-new-privileges: prevent privilege escalation
      - -v workspace:/workspace:rw: mount only the target repo worktree
    """
    import uuid

    workspace = Path(workspace_dir).resolve()
    if not workspace.exists():
        raise FileNotFoundError(f"Workspace directory not found: {workspace}")

    cmd_args: list[str] = (
        ["/bin/sh", "-c", command] if isinstance(command, str) else list(command)
    )

    container_name = f"sandbox_{uuid.uuid4().hex[:12]}"
    docker_cmd: list[str] = [
        "docker",
        "run",
        "--rm",
        f"--name={container_name}",
        f"--network={network}",
        f"--memory={memory_limit}",
        f"--cpus={cpu_limit}",
        f"--pids-limit={pids_limit}",
        "--security-opt",
        "no-new-privileges",
        "-v",
        f"{workspace}:/workspace:rw",
        "-w",
        "/workspace",
    ]

    if env_vars:
        for k, v in env_vars.items():
            docker_cmd.extend(["-e", f"{k}={v}"])

    docker_cmd.append(image)
    docker_cmd.extend(cmd_args)

    logger.debug(
        "docker_sandbox_starting",
        image=image,
        network=network,
        timeout=timeout_seconds,
        workspace=str(workspace),
        container=container_name,
    )

    start_time = time.monotonic()

    try:
        proc = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration = time.monotonic() - start_time
        return DockerRunResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
            duration_seconds=round(duration, 2),
            container_id=container_name,
        )

    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start_time
        logger.warning("docker_sandbox_timeout", duration=duration, limit=timeout_seconds, container=container_name)
        # Always clean up the container on timeout
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, check=False)
        stdout_text = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr_text = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return DockerRunResult(
            exit_code=-1,
            stdout=stdout_text,
            stderr=stderr_text + f"\n[TIMED OUT after {timeout_seconds}s]",
            timed_out=True,
            duration_seconds=round(duration, 2),
            container_id=container_name,
        )
    finally:
        # Guarantee container removal even on unexpected crashes
        try:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, check=False)
        except Exception:
            pass
