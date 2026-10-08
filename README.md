# Agentic Reviewer

> Autonomous code review and vulnerability detection powered by LangGraph + LiteLLM.

## Quick Start

```bash
# 1. Create and activate a virtualenv (Python 3.11)
py -3.11 -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

# 2. Install all dependencies
pip install -e ".[dev]"

# 3. Copy the env template and fill in your keys
copy .env.example .env          # Windows
# cp .env.example .env          # macOS / Linux

# 4. Install pre-commit hooks
pre-commit install

# 5. Run the smoke tests
pytest
```

## CLI Usage (Mode B – Standalone)

```bash
# Review a local branch against main
agentreview review --repo . --base main --head feature/my-branch

# Write the report to a file
agentreview review --repo . --base main --head HEAD --output report.md
```

## API Keys (free tier)

| Key | Where to get it |
|---|---|
| `GEMINI_API_KEY` | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) |
| `GROQ_API_KEY`   | [console.groq.com/keys](https://console.groq.com/keys) |

Set them in your `.env` file (copy from `.env.example`).

## Project Structure

```
agentic-reviewer/
├── core/           # state schema, orchestrator graph, config, LLM wrapper
├── agents/         # one module per agent (Week 2+)
├── tools/          # semgrep, docker runner, git ops, scanners (Week 3+)
├── indexer/        # tree-sitter, dependency graph, embeddings (Week 2)
├── adapters/
│   ├── cli/        # Typer CLI  ← working now
│   └── github_app/ # FastAPI webhook (Week 7)
├── ui/             # Streamlit approval dashboard (Week 6)
├── eval/           # benchmark scripts (Week 8)
├── docker/         # sandbox images (Week 3)
└── tests/          # pytest suite
```

## Development Commands

```bash
pytest                  # run tests with coverage
ruff check .            # lint
ruff format .           # format
mypy .                  # type-check
pre-commit run --all-files   # run all hooks manually
```
