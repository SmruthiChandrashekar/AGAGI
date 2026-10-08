"""Tests for Day 3 LLM layer: caching, structured outputs, fallback, rate limiting."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from pydantic import BaseModel

from core.llm import LLMCache, RateLimiter, chat_structured, smoke_test_providers


class MockFinding(BaseModel):
    title: str
    severity: str
    line: int


def test_sqlite_llm_cache() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "cache.db"
        cache = LLMCache(db_path=db_path)
        messages = [{"role": "user", "content": "hello world"}]
        h = cache.compute_hash("gemini/flash", messages, 0.2)

        # Cache miss
        assert cache.get(h) is None

        # Cache set
        cache.set(h, "gemini/flash", messages, "Hello there!", 10, 5)

        # Cache hit
        assert cache.get(h) == "Hello there!"

        # Clear
        cache.clear()
        assert cache.get(h) is None


def test_rate_limiter_accounting() -> None:
    limiter = RateLimiter(min_call_interval_seconds=0.01)
    limiter.reset_stats()
    limiter.record_usage(100, 50)
    limiter.record_usage(200, 80)
    stats = limiter.get_stats()
    assert stats["total_calls"] == 2
    assert stats["total_prompt_tokens"] == 300
    assert stats["total_completion_tokens"] == 130


@patch("core.llm.chat")
def test_chat_structured_success(mock_chat: MagicMock) -> None:
    mock_chat.return_value = '{"title": "SQL Injection", "severity": "high", "line": 42}'
    messages = [{"role": "user", "content": "Analyze code"}]

    res = chat_structured(messages, MockFinding, use_cache=False)
    assert res.title == "SQL Injection"
    assert res.severity == "high"
    assert res.line == 42


@patch("core.llm.chat")
def test_chat_structured_retry_on_initial_failure(mock_chat: MagicMock) -> None:
    # First response is invalid JSON, second response is valid
    mock_chat.side_effect = [
        "not json at all",
        '{"title": "Fixed Issue", "severity": "medium", "line": 10}',
    ]
    messages = [{"role": "user", "content": "Analyze code"}]

    res = chat_structured(messages, MockFinding, use_cache=False)
    assert res.title == "Fixed Issue"
    assert res.severity == "medium"
    assert mock_chat.call_count == 2


@patch("litellm.completion")
def test_smoke_test_providers_structure(mock_comp: MagicMock) -> None:
    mock_resp = MagicMock()
    mock_resp.choices = [MagicMock(message=MagicMock(content="PONG"))]
    mock_comp.return_value = mock_resp

    results = smoke_test_providers()
    assert "gemini" in results
    assert "groq" in results
    assert "ollama" in results
