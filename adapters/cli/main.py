"""
adapters/cli/main.py
--------------------
Typer-based CLI entry point.

Usage:
    agentreview review --repo . --base main --head feature/my-branch
    agentreview review --repo . --patch changes.patch
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.state import ChangeSet

app = typer.Typer(
    name="agentreview",
    help="Agentic autonomous code review and vulnerability detection.",
    add_completion=False,
)
console = Console()


def _banner() -> None:
    console.print(
        Panel(
            Text("🤖 Agentic Reviewer", justify="center", style="bold cyan"),
            subtitle="[dim]autonomous code review + vulnerability detection[/dim]",
            border_style="cyan",
        )
    )


@app.command()
def review(
    repo: Path = typer.Option(
        Path("."),
        "--repo",
        "-r",
        help="Path to the git repository to review.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    base: str = typer.Option(
        "main",
        "--base",
        "-b",
        help="Base git ref (branch, tag, or SHA).",
    ),
    head: str = typer.Option(
        "HEAD",
        "--head",
        "-H",
        help="Head git ref to review against base.",
    ),
    patch: Optional[Path] = typer.Option(
        None,
        "--patch",
        "-p",
        help="Path to a .patch file (alternative to --base / --head).",
        exists=False,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the Markdown report to this file.",
    ),
    approve: bool = typer.Option(
        False,
        "--approve/--no-approve",
        help="Open the Streamlit approval dashboard automatically.",
    ),
) -> None:
    """Run the full agentic review pipeline on a local repository."""
    _banner()

    if patch is not None:
        console.print(f"[yellow]Patch mode:[/yellow] {patch}")
        typer.echo("Patch-file mode is not yet implemented.", err=True)
        raise typer.Exit(code=1)

    changeset = ChangeSet(repo_path=repo, base_ref=base, head_ref=head)
    console.print(f"[green]Repository:[/green] {changeset.repo_path}")
    console.print(f"[green]Base:[/green]       {changeset.base_ref}")
    console.print(f"[green]Head:[/green]       {changeset.head_ref}")
    console.print()

    # Lazy import so the CLI starts fast even if heavy deps are slow to load.
    from core.orchestrator import run_review  # noqa: PLC0415

    result = run_review(changeset)

    if output:
        output.write_text(result.get("report_markdown") or "", encoding="utf-8")
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        console.print(result.get("report_markdown") or "[dim]No report generated.[/dim]")


@app.command()
def version() -> None:
    """Print the installed version."""
    from importlib.metadata import version as _v, PackageNotFoundError  # noqa: PLC0415

    try:
        v = _v("agentic-reviewer")
    except PackageNotFoundError:
        v = "dev"
    console.print(f"agentic-reviewer [bold cyan]{v}[/bold cyan]")


if __name__ == "__main__":
    app()
