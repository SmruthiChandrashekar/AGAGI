# Agentic Code Reviewer & Security Triage (AGAGI)

> Autonomous code review, merge simulation, blast radius analysis, vulnerability scanning, and LLM-powered triage built with LangGraph and LiteLLM.

---

## 🚀 Quick Start for Setup

### 1. Clone the Repository
```bash
git clone https://github.com/SmruthiChandrashekar/AGAGI.git
cd AGAGI
```

### 2. Create and Activate Virtual Environment (Python 3.11 recommended)
```bash
# Windows (PowerShell / CMD)
python -m venv .venv
.\.venv\Scripts\activate

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -e ".[dev]"
```

### 4. Configure Environment (.env)
```bash
# Windows
copy .env.example .env

# macOS / Linux
cp .env.example .env
```
Open `.env` and add your free LLM API key(s):
- `GEMINI_API_KEY` ([Get free key at Google AI Studio](https://aistudio.google.com/apikey))
- `GROQ_API_KEY` ([Get free key at Groq Console](https://console.groq.com/keys))

Then check the key and model names actually work:
```bash
python -m tools.check_llm
```
If no provider shows `[OK]`, the agents fall back to simple built-in rules: root causes are weaker and no fixes can be written. Retired model names from old `.env` files (for example `gemini-1.5-flash-latest`, `llama3-8b-8192`) are upgraded automatically.

> Never put a real key in `.env.example`. It is committed to the repo; `.env` is not.

---

## 🖥️ Running the Web Dashboard

Start the review server:
```bash
python -m ui.server
```
Then open your browser and navigate to:
👉 **[http://127.0.0.1:8080](http://127.0.0.1:8080)**

From the dashboard you can:
1. **Local Mode**: Select a local repository and choose which branch to review against `main`.
2. **GitHub Mode**: Paste a GitHub Personal Access Token (PAT), select any of your GitHub repositories, and review open/closed pull requests live!
3. **Interactive Tabs**: Inspect Impact Analysis (call graph & blast radius), Security & Triage (Semgrep/Bandit/Gitleaks/OSV), Test Logs (JUnit regressions vs pre-existing), Git Diff, and the full Markdown Review Report.

---

## 🧪 Testing with the Built-in Demo Repo (`calc-demo`)

You can generate the complete multi-branch calculator testbed repository in one command:
```bash
python tools/build_calc_demo.py
```
This builds a `calculator` folder next to the project folder (pass `--target <path>` to choose another place) with these test branches:
- `clean-merge`: Clean addition of `multiply()` function (verdict: **SAFE**).
- `breaks-test`: Modifies `average(nums)` signature, merges cleanly but introduces test regressions (verdict: **NEEDS_CHANGES**).
- `conflict`: Modifies same lines on `main` and branch (verdict: **BLOCKED**).
- `build-error`: Introduces a Python syntax error (verdict: **NEEDS_CHANGES**).
- `unsafe-eval`: Adds a function that calls `eval()` (security finding).
- `hardcoded-secret`: Adds a hardcoded AWS-style key (security finding).
- `main`: Baseline branch with isolated baseline tests.

---

## ✅ Week 6: Human Approval, Verification & Retry Loop

Open **[http://127.0.0.1:8080/approve](http://127.0.0.1:8080/approve)** (or click **Patch Approval** on the dashboard).

1. The review runs and **pauses** whenever fixes are proposed. Nothing is applied without your approval.
2. Tick the patches you approve, then **Approve selected** (or **Reject all**).
3. The **Verifier** applies only the approved patches to a throwaway copy of the merged code (base + branch), then re-runs the full test suite and the security scanners. Your own files are never changed.
4. If the fix fails verification, the failure is fed back to root-cause analysis and a new fix is proposed for approval, up to `MAX_FIX_ITERATIONS` attempts (default 3). After that the review is **escalated** to a human.
5. Every approval, rejection, verification and escalation is recorded in `data/audit.db` (view one run at `/api/review/<thread_id>/audit`).

The main dashboard's **Run Review** never pauses and never applies anything; it behaves exactly as in Week 5.

Paused reviews are kept in memory, so restarting the server forgets any review that is waiting for approval.

---

## 🛠️ CLI Review Tool (Mode B)

You can also run reviews directly from your terminal:
```bash
# Review a local repository branch
python -m adapters.cli.main review --repo /path/to/repo --base main --head feature-branch

# Or via installed console script
agentreview review --repo /path/to/repo --base main --head feature-branch --output report.md
```

---

## 🧪 Running the Test Suite

Run the full pytest suite (40 tests across all modules):
```bash
pytest
```

---

## 🏗️ Architecture & Pipeline Flow

The review orchestrator runs as a LangGraph DAG:
```
  [Ingest ChangeSet]
          │
          ▼
  [Impact Analysis & Graph]  ── (Tree-sitter AST, caller graph, blast radius score)
          │
          ▼
  [Merge Simulation]         ── (Isolated Docker sandbox / worktree, isolates pre-existing main failures)
          ├───► [Security Agent]     ── (Semgrep, Gitleaks, Bandit on changed files, deduplication)
          │             │
          └───► [Dependency Agent]   ── (pip-audit / OSV-Scanner on changed manifest files)
                        │
                        ▼
               [LLM Triage Agent]    ── (Filters false positives, untrusted code guardrails, auto-retry schema)
                        │
                        ▼
               [Reporter Agent]      ── (Computes verdict: SAFE, NEEDS_CHANGES, BLOCKED; emits report)
```
# AGAGI: Agentic Code Reviewer & Security Triage

AGAGI reviews a code change (a branch or pull request) the way a careful senior engineer would. It merges the change in a safe copy, runs the tests, scans for security problems, works out what else the change could break, explains the root cause of any problem, writes a fix, **waits for a human to approve it**, and then proves the fix works before reporting.

**Key idea:** tools decide the facts, the AI only explains and proposes. Tests and scanners (Semgrep, Bandit, Gitleaks, pip-audit/OSV) say what is wrong. The AI is used for four jobs only: triage, code review, root-cause analysis and writing fixes. Nothing is changed in your files without your approval.

Team: Smruthi Chandrashekar (ENG23AM0281), Sarthak Ramachandra (ENG23AM0185), Claudia Raj (ENG23AM0095).

---

## 1. What it does

| Stage | What happens |
|---|---|
| Ingest | Reads the branch/PR: changed files and diff |
| Impact | Builds a map of functions/callers and scores the "blast radius" of the change |
| Merge simulation | Merges the branch into a throwaway copy, runs the tests there and on `main`, and separates **new** failures from ones that already existed |
| Security + Dependency | Semgrep, Bandit, Gitleaks on changed files; pip-audit/OSV on dependency files |
| Triage (AI) | Removes false alarms from the scanner results |
| Review (AI) | Flags concrete bugs in the diff, and stays quiet on clean code |
| Root cause (AI) | Explains why a test or build failed, naming the file and line |
| Fix (AI) | Writes a patch (unified diff) and checks it with `git apply` |
| Approval | **Pauses.** A human picks which patches to approve |
| Verify | Applies only the approved patches in a throwaway copy, re-runs tests and scanners. If it fails, the failure is fed back and a new fix is tried (max 3 attempts), then escalated to a human |
| Report | Verdict `SAFE`, `NEEDS_CHANGES` or `BLOCKED`, with a Markdown report and an audit trail |

10 agents in total. Only Triage, Review, Root-cause and Fix use an AI model.

---

## 2. Setup (Windows, PowerShell)

You need **Python 3.11** (3.14 does not work yet because some libraries are not available for it) and **Git**.

```powershell
git clone https://github.com/SmruthiChandrashekar/AGAGI.git
cd AGAGI
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
```

### Install Semgrep (separately)

Semgrep conflicts with some of our other libraries, so it is installed on its own with pipx and not through `pip install -e`:

```powershell
pip install pipx
pipx install semgrep
pipx ensurepath
```

Close and reopen PowerShell afterwards. If Semgrep is missing, AGAGI still runs, but you get fewer security findings.

### Add your AI keys

```powershell
copy .env.example .env
```

Open `.env` and fill in:

- `GEMINI_API_KEY`: free at https://aistudio.google.com/apikey (about 20 requests per day per model on the free plan)
- `GROQ_API_KEY`: free at https://console.groq.com/keys (used as the backup when Gemini runs out)

Check that they work:

```powershell
python -m tools.check_llm
```

You want `[OK]` next to at least one provider. Without a working key, AGAGI falls back to simple built-in rules: root causes are weaker and no fixes are written.

> Never put a real key in `.env.example`. That file is committed to GitHub. `.env` is not.

Default models (change in `.env` if needed): `PRIMARY_MODEL=gemini/gemini-3.5-flash`, `FAST_MODEL=groq/openai/gpt-oss-20b`. The Ollama fallback model is optional and not required.

---

## 3. Run the demo

### Build the sample project

```powershell
python tools/build_calc_demo.py --target C:\projects\calculator
```

This creates a small calculator repo with these branches:

| Branch | What it does | Expected verdict |
|---|---|---|
| `clean-merge` | Adds a harmless `multiply()` | SAFE |
| `breaks-test` | Changes `average()` and breaks a test | NEEDS_CHANGES (fix proposed) |
| `conflict` | Edits the same lines as `main` | BLOCKED (human must resolve) |
| `build-error` | Contains a Python syntax error | NEEDS_CHANGES (cause found) |
| `unsafe-eval` | Calls `eval()` on input | NEEDS_CHANGES (fix proposed) |
| `hardcoded-secret` | Contains a hard-coded key | NEEDS_CHANGES (secret flagged) |

### Start the dashboard

```powershell
python -m ui.server
```

Open http://127.0.0.1:8080.

- **Main dashboard:** pick a repo and branch, press Run Review, and read the tabs (impact, security, test logs, diff, full report). This view never changes anything.
- **Patch Approval page:** http://127.0.0.1:8080/approve. The review pauses when fixes are proposed. Tick the patches you accept, then press Approve. The Verifier tests them and shows **Verified** or tries again.
- **Download the fix:** once a fix is verified, a **Download verified fix (.patch)** button appears. Apply it to your real project with:

```powershell
git apply agagi-fix.patch
```

Every approval, rejection, verification and escalation is recorded in `data/audit.db` (one run: `/api/review/<id>/audit`).

---

## 4. Using it on a real project

AGAGI runs the target project's tests using the project's **own Python environment**, so its libraries are available.

1. In the project, create a virtual environment named `.venv` (or `venv` / `env`), install the project's requirements, and install `pytest` into it.
2. Point AGAGI at the project from the dashboard.

AGAGI picks the Python in this order, and only uses one that can import `pytest`: the `AGAGI_TARGET_PYTHON` variable, then the project's `.venv` / `venv` / `env`, then AGAGI's own Python.

Optional settings (PowerShell, set before starting the server):

```powershell
$env:AGAGI_TARGET_PYTHON = "C:\path\to\project\.venv\Scripts\python.exe"
$env:AGAGI_TEST_COMMAND  = "pytest -x tests/unit"   # replaces the detected test command
$env:AGAGI_TEST_TIMEOUT  = "180"                    # seconds per test run (default 45)
```

If Docker is installed, tests run in a locked-down container (no network, memory and CPU limits). Without Docker they run as a normal local process.

---

## 5. Tests and evaluation

Run the unit tests (62 tests):

```powershell
python -m pytest
```

Use `python -m pytest`, not `pytest` alone. Add `--no-cov` to skip the coverage report and finish faster.

Run the evaluation, which reviews every demo branch end to end with real AI and approves every fix:

```powershell
python -m eval.run_eval --repo C:\projects\calculator
```

It writes `eval/results/eval_results.json` and `eval/results/eval_report.md`.

**Our results on this 6-scenario suite:**

| Measure | Result |
|---|---|
| Correct verdict | 6 of 6 |
| Real issues found, root cause named, fix written and verified | 4 of 4 |
| False alarms on clean code | 0 |
| AI call failures | 0 |
| Average time per review | about 47 seconds |

These numbers are for our own test suite. They show the pipeline works end to end, and are not a claim of general accuracy on all code.

---

## 6. Project layout

```
adapters/    CLI and (planned) GitHub App entry points
agents/      the 10 agents (merge simulation, security, review, RCA, fix, verifier, reporter, ...)
core/        orchestrator (LangGraph pipeline), shared state, AI client, audit log, config
indexer/     code parsing and call graph (Python)
tools/       wrappers for git, Docker, Semgrep, Bandit, Gitleaks, pip-audit, test environment
ui/          FastAPI server, dashboard, approval page
eval/        evaluation harness and saved results
tests/       unit tests
```

Pipeline order:

```
ingest -> impact -> merge simulation -> [security || dependency] -> triage
       -> review -> root cause -> fix -> approval (human) -> verify -> report
                                   ^                          |
                                   +---- retry (max 3) -------+
```

---

## 7. Known limitations

- Code-structure analysis (call graph, blast radius) works for **Python only**. Other languages can still be tested and scanned.
- Reviews waiting for approval are kept in memory. Restarting the server forgets them.
- Approving a fix does not edit your project. You download the verified patch and apply it yourself.
- The GitHub App (automatic review of pull requests via webhook) is not built yet. The CLI (`agentreview`) has not been tested end to end.
- The free AI plans have daily request limits. When Gemini runs out, AGAGI uses Groq. If both run out, it falls back to simple rules.
- Code diffs are sent to the AI provider for triage, review and fixing. Do not use real keys or private code you are not allowed to share.
