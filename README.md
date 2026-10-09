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
