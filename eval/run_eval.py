"""
eval/run_eval.py
----------------
Scores AGAGI on known scenarios (the calculator demo branches).

For every scenario it runs the review in approval mode, approves every proposed
patch (like a human saying yes), lets the Verifier re-run tests and scanners, and
records what happened. At the end it prints a table and saves:
  eval/results/eval_results.json   (raw numbers)
  eval/results/eval_report.md      (a table you can paste into slides)

Usage (from the project folder, venv active):
  python -m eval.run_eval
  python -m eval.run_eval --repo C:\\projects\\calculator
  python -m eval.run_eval --only breaks-test unsafe-eval
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from collections.abc import Iterator
from typing import Any

from core.orchestrator import resume_review, start_review
from core.state import ApprovalDecision, ApprovalStatus, ChangeSet
from tools.build_calc_demo import build_calc_demo, default_demo_path

RESULTS_DIR = Path(__file__).parent / "results"
MAX_APPROVAL_ROUNDS = 4  # first fix + up to 3 retries
_AI_AGENT_MODULES = ("agents.review_agent", "agents.triage_agent", "agents.rca_agent", "agents.fix_agent")


@dataclass
class Scenario:
    branch: str
    description: str
    # Verdicts that count as correct (as plain strings).
    ok_verdicts: tuple[str, ...]
    # File where the problem really is. None means "nothing should be reported".
    bug_file: str | None = None
    # Should the tool propose a fix for it?
    expects_patch: bool = False
    # Words that should appear in a finding/root cause for it to count as the right issue.
    keywords: tuple[str, ...] = ()


SCENARIOS: list[Scenario] = [
    Scenario(
        "clean-merge",
        "A good change: new multiply() with tests. Should pass quietly.",
        ok_verdicts=("safe",),
    ),
    Scenario(
        "breaks-test",
        "average() gained a required argument; callers and tests now break.",
        ok_verdicts=("needs_changes",),
        bug_file="calc.py",
        expects_patch=True,
        keywords=("average", "round_to"),
    ),
    Scenario(
        "conflict",
        "Both branches edit the same lines. Merge must be stopped.",
        ok_verdicts=("blocked",),
    ),
    Scenario(
        "build-error",
        "A syntax error was added to calc.py.",
        ok_verdicts=("needs_changes", "blocked"),
        bug_file="calc.py",
        expects_patch=True,
        keywords=("broken", "syntax"),
    ),
    Scenario(
        "unsafe-eval",
        "calc.py now calls eval() on user input (code injection).",
        ok_verdicts=("needs_changes", "blocked"),
        bug_file="calc.py",
        expects_patch=True,
        keywords=("eval",),
    ),
    Scenario(
        "hardcoded-secret",
        "An AWS access key is typed directly into calc.py.",
        ok_verdicts=("needs_changes", "blocked"),
        bug_file="calc.py",
        expects_patch=True,
        keywords=("secret", "key", "credential", "aws"),
    ),
]


@dataclass
class Outcome:
    branch: str
    verdict: str = ""
    verdict_ok: bool = False
    reported_issues: int = 0  # findings + review comments that were not false positives
    found_bug: bool | None = None  # None when the scenario has no bug to find
    false_alarm: bool = False  # clean scenario but the tool still reported issues
    root_cause_files: list[str] = field(default_factory=list)
    root_cause_ok: bool | None = None
    patches_proposed: int = 0
    patch_ok: bool | None = None  # None when no patch was expected
    verified: bool | None = None  # None when nothing was approved
    attempts: int = 0
    escalated: bool = False
    llm_failures: int = 0  # AI calls that failed (quota, network, bad key)
    seconds: float = 0.0
    error: str = ""


def _val(x: Any) -> str:
    """Enum or string → lowercase string."""
    return str(getattr(x, "value", x) or "").lower()


def _text_of(item: Any) -> str:
    """Flatten a finding / root cause (model or dict) into searchable lowercase text."""
    data = item.model_dump() if hasattr(item, "model_dump") else dict(item)
    return " ".join(str(v) for v in data.values() if v is not None).lower()


def _file_of(item: Any, *names: str) -> str:
    data = item.model_dump() if hasattr(item, "model_dump") else dict(item)
    for n in names:
        if data.get(n):
            return str(data[n]).replace("\\", "/")
    return ""


@contextlib.contextmanager
def _count_llm_failures() -> Iterator[dict[str, int]]:
    """Count AI calls that fail while a scenario runs, so quota problems are never hidden."""
    counter = {"n": 0}
    originals: list[tuple[Any, Any]] = []

    def wrap(orig: Any) -> Any:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return orig(*args, **kwargs)
            except Exception:
                counter["n"] += 1
                raise

        return wrapper

    for name in _AI_AGENT_MODULES:
        mod = importlib.import_module(name)
        orig = getattr(mod, "chat_structured", None)
        if orig is not None:
            setattr(mod, "chat_structured", wrap(orig))
            originals.append((mod, orig))
    try:
        yield counter
    finally:
        for mod, orig in originals:
            setattr(mod, "chat_structured", orig)


def _approve_everything(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Keep saying 'yes' to every proposed patch until the run finishes."""
    rounds = 0
    while snapshot.get("paused") and rounds < MAX_APPROVAL_ROUNDS:
        pending = snapshot.get("pending_approval") or {}
        indices = [p["index"] for p in pending.get("patches", [])]
        decision = ApprovalDecision(
            status=ApprovalStatus.APPROVED,
            approved_patch_indices=indices,
            reviewed_by="eval-harness",
        )
        snapshot = resume_review(snapshot["thread_id"], decision)
        rounds += 1
    return snapshot


def run_scenario(repo: Path, sc: Scenario) -> Outcome:
    out = Outcome(branch=sc.branch)
    start = time.time()
    try:
        cs = ChangeSet(repo_path=repo, base_ref="main", head_ref=sc.branch)
        with _count_llm_failures() as failures:
            try:
                snap = _approve_everything(start_review(cs))
            finally:
                out.llm_failures = failures["n"]
        s = snap.get("state") or {}

        out.verdict = _val(s.get("verdict"))
        out.verdict_ok = out.verdict in sc.ok_verdicts

        findings = [f for f in (s.get("findings") or []) if not getattr(f, "is_false_positive", False)]
        review = list(s.get("review_findings") or [])
        root_causes = list(s.get("root_causes") or [])
        patches = list(s.get("patches") or [])
        out.reported_issues = len(findings) + len(review)
        out.patches_proposed = len(patches)
        out.root_cause_files = sorted({_file_of(rc, "root_cause_file") for rc in root_causes} - {""})

        if sc.bug_file is None:
            out.false_alarm = sc.branch == "clean-merge" and out.reported_issues > 0
        else:
            evidence = [_text_of(x) for x in findings + review + root_causes]
            out.found_bug = any(any(k in e for k in sc.keywords) for e in evidence) or any(
                sc.bug_file in _file_of(x, "file", "file_path", "root_cause_file") for x in findings + review
            )
            out.root_cause_ok = any(f.endswith(sc.bug_file) for f in out.root_cause_files) or any(
                _file_of(f, "file", "file_path").endswith(sc.bug_file) for f in findings
            )
            if sc.expects_patch:
                out.patch_ok = any(
                    any(t.endswith(sc.bug_file) for t in (getattr(p, "target_files", None) or []))
                    for p in patches
                )

        history = list(s.get("verification_history") or [])
        out.attempts = len(history)
        out.escalated = bool(s.get("escalated"))
        if history:
            out.verified = bool(history[-1].get("verified"))
    except Exception as exc:  # keep going so one bad scenario doesn't hide the others
        out.error = f"{type(exc).__name__}: {exc}"[:300]
    out.seconds = round(time.time() - start, 1)
    return out


def _mark(v: bool | None) -> str:
    return "n/a" if v is None else ("yes" if v else "NO")


def _pct(num: int, den: int) -> str:
    return "n/a" if den == 0 else f"{round(100 * num / den)}% ({num}/{den})"


def summarize(outcomes: list[Outcome]) -> dict[str, str]:
    bug = [o for o in outcomes if o.found_bug is not None]
    patchable = [o for o in outcomes if o.patch_ok is not None]
    approved = [o for o in outcomes if o.verified is not None and o.patch_ok is not None]
    ai_hit = [o for o in outcomes if o.llm_failures > 0]
    clean = [o for o in outcomes if o.branch == "clean-merge"]
    return {
        "Correct verdicts": _pct(sum(o.verdict_ok for o in outcomes), len(outcomes)),
        "Real issues detected": _pct(sum(bool(o.found_bug) for o in bug), len(bug)),
        "Root cause in the right file": _pct(sum(bool(o.root_cause_ok) for o in bug), len(bug)),
        "Fix proposed for the right file": _pct(sum(bool(o.patch_ok) for o in patchable), len(patchable)),
        "Approved fixes that verified": _pct(sum(bool(o.verified) for o in approved), len(approved)),
        "False alarms on clean change": _pct(sum(o.false_alarm for o in clean), len(clean)),
        "Scenarios where AI calls failed": f"{len(ai_hit)}/{len(outcomes)}",
        "Average seconds per review": f"{round(sum(o.seconds for o in outcomes) / max(len(outcomes), 1), 1)}s",
    }


def render_markdown(outcomes: list[Outcome], summary: dict[str, str]) -> str:
    lines = [
        "# AGAGI Evaluation Report",
        "",
        "## Summary",
        "",
        "| Metric | Result |",
        "|---|---|",
        *[f"| {k} | {v} |" for k, v in summary.items()],
        "",
        "## Per scenario",
        "",
        "| Branch | Verdict | Verdict OK | Issue found | Root cause OK | Patches | Verified | Tries | AI errors | Time |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for o in outcomes:
        lines.append(
            f"| {o.branch} | {o.verdict or 'ERROR'} | {_mark(o.verdict_ok)} | {_mark(o.found_bug)} | "
            f"{_mark(o.root_cause_ok)} | {o.patches_proposed} | {_mark(o.verified)} | {o.attempts} | {o.llm_failures} | {o.seconds}s |"
        )
    ai_hit = [o for o in outcomes if o.llm_failures > 0]
    if ai_hit:
        names = ", ".join(o.branch for o in ai_hit)
        lines[2:2] = [
            f"> **Warning:** AI calls failed in: {names}. Those scenarios fell back to simple rules, so "
            "their numbers are NOT representative. Usual cause: the free daily AI quota ran out. "
            "Add a second provider key (GROQ_API_KEY) or re-run after the quota resets.",
            "",
        ]
    errors = [o for o in outcomes if o.error]
    if errors:
        lines += ["", "## Errors", ""] + [f"- **{o.branch}**: {o.error}" for o in errors]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate AGAGI on the calculator demo.")
    parser.add_argument("--repo", type=Path, default=None, help="Calculator demo folder")
    parser.add_argument("--only", nargs="*", default=None, help="Run only these branches")
    args = parser.parse_args()

    repo = build_calc_demo(args.repo or default_demo_path())
    chosen = [s for s in SCENARIOS if not args.only or s.branch in args.only]

    outcomes: list[Outcome] = []
    for i, sc in enumerate(chosen, 1):
        print(f"[{i}/{len(chosen)}] {sc.branch}: {sc.description}", flush=True)
        o = run_scenario(repo, sc)
        print(f"      verdict={o.verdict or 'ERROR'} verified={_mark(o.verified)} time={o.seconds}s {o.error}", flush=True)
        outcomes.append(o)

    summary = summarize(outcomes)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "eval_results.json").write_text(
        json.dumps({"summary": summary, "scenarios": [asdict(o) for o in outcomes]}, indent=2),
        encoding="utf-8",
    )
    report = render_markdown(outcomes, summary)
    (RESULTS_DIR / "eval_report.md").write_text(report, encoding="utf-8")

    print("\n" + report)
    print(f"Saved to {RESULTS_DIR}")


if __name__ == "__main__":
    main()
