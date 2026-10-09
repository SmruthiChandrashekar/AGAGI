"""
tools/check_llm.py
------------------
Quick check that your AI key and model names actually work.

    python -m tools.check_llm

Prints one line per provider: ok, skipped (no key), or failed (with the reason).
If every provider fails or is skipped, the review agents cannot use the AI and
fall back to simple built-in rules, which give much weaker root causes and no patches.
"""

from __future__ import annotations

from core.config import settings
from core.llm import smoke_test_providers


def main() -> int:
    print(f"Primary model : {settings.primary_model}")
    print(f"Fast model    : {settings.fast_model}")
    print(f"Fallback model: {settings.fallback_model}")
    print()
    results = smoke_test_providers()
    any_ok = False
    for name, info in results.items():
        status = info.get("status")
        if status == "ok":
            any_ok = True
            print(f"[OK]      {name:<7} {info['model']}  -> replied {info.get('response', '')!r}")
        elif status == "skipped":
            print(f"[SKIPPED] {name:<7} {info['model']}  ({info.get('reason')})")
        else:
            err = str(info.get("error", ""))[:300]
            print(f"[FAILED]  {name:<7} {info['model']}  {err}")
    print()
    if any_ok:
        print("At least one provider works. The agents can use the AI.")
        return 0
    print("No provider works. Put a real key in .env (GEMINI_API_KEY=...) and run this again.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
