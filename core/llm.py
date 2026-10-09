"""
core/llm.py
-----------
LiteLLM wrapper with:
  - Provider fallback chain: Gemini -> Groq -> Ollama
  - Free-tier rate-limit protection: call queue and exponential backoff
  - SQLite prompt-hash response caching
  - Token and latency tracking
  - Structured output helper with Pydantic validation and auto-retry
  - Provider smoke testing
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

import litellm
from pydantic import BaseModel, ValidationError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from core.config import settings
from core.exceptions import LLMError
from core.logging import get_logger

logger = get_logger(__name__)

# Type variable for structured output models
T = TypeVar("T", bound=BaseModel)

# Silence verbose LiteLLM logging
litellm.suppress_debug_info = True


# ── Rate Limiter & Token Accounting ──────────────────────────────────────────


class RateLimiter:
    """Thread-safe rate limiter and token counter for free-tier protection."""

    def __init__(self, min_call_interval_seconds: float = 0.5) -> None:
        self.min_interval = min_call_interval_seconds
        self._last_call_time = 0.0
        self._lock = threading.Lock()
        self.total_calls = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0

    def acquire(self) -> None:
        """Enforce minimum spacing between LLM calls to respect free RPM."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last_call_time = time.monotonic()

    def record_usage(self, prompt_tokens: int, completion_tokens: int) -> None:
        """Track cumulative token usage."""
        with self._lock:
            self.total_calls += 1
            self.total_prompt_tokens += prompt_tokens
            self.total_completion_tokens += completion_tokens

    def get_stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "total_calls": self.total_calls,
                "total_prompt_tokens": self.total_prompt_tokens,
                "total_completion_tokens": self.total_completion_tokens,
            }

    def reset_stats(self) -> None:
        with self._lock:
            self.total_calls = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0


rate_limiter = RateLimiter()


# ── SQLite Response Cache ────────────────────────────────────────────────────


class LLMCache:
    """
    SQLite response cache keyed by SHA-256(model + messages + temperature).
    Prevents redundant LLM calls and saves free-tier tokens across pipeline runs.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is None:
            data_dir = settings.data_dir
            data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = data_dir / "llm_cache.db"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS llm_cache (
                        prompt_hash TEXT PRIMARY KEY,
                        model TEXT NOT NULL,
                        messages_json TEXT NOT NULL,
                        response_text TEXT NOT NULL,
                        prompt_tokens INTEGER DEFAULT 0,
                        completion_tokens INTEGER DEFAULT 0,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    @staticmethod
    def compute_hash(model: str, messages: list[dict[str, str]], temperature: float) -> str:
        payload = json.dumps(
            {"model": model, "messages": messages, "temperature": temperature},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(self, prompt_hash: str) -> str | None:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT response_text FROM llm_cache WHERE prompt_hash = ?",
                    (prompt_hash,),
                )
                row = cur.fetchone()
                return row[0] if row else None
            finally:
                conn.close()

    def set(
        self,
        prompt_hash: str,
        model: str,
        messages: list[dict[str, str]],
        response_text: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO llm_cache
                    (prompt_hash, model, messages_json, response_text, prompt_tokens, completion_tokens, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        prompt_hash,
                        model,
                        json.dumps(messages, sort_keys=True),
                        response_text,
                        prompt_tokens,
                        completion_tokens,
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def clear(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("DELETE FROM llm_cache")
                conn.commit()
            finally:
                conn.close()


llm_cache = LLMCache()


# ── LiteLLM Wrapper & Fallback ───────────────────────────────────────────────

_RETRY_EXCEPTIONS = (
    litellm.RateLimitError,
    litellm.APIConnectionError,
    litellm.Timeout,
    litellm.InternalServerError,
)


def _has_real_key(value: str) -> bool:
    """True when an API key is set and is not the template placeholder."""
    v = (value or "").strip()
    return bool(v) and not v.lower().startswith("your_")


def provider_available(model: str) -> bool:
    """Skip hosted providers whose API key is missing, so calls don't waste time failing."""
    if model.startswith("gemini/"):
        return _has_real_key(settings.gemini_api_key)
    if model.startswith("groq/"):
        return _has_real_key(settings.groq_api_key)
    return True


def _prepare_call_kwargs(model: str, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Inject required credentials/endpoints depending on provider."""
    call_kwargs = dict(kwargs)
    if model.startswith("gemini/") and settings.gemini_api_key:
        call_kwargs.setdefault("api_key", settings.gemini_api_key)
    elif model.startswith("groq/") and settings.groq_api_key:
        call_kwargs.setdefault("api_key", settings.groq_api_key)
    elif model.startswith("ollama/"):
        call_kwargs.setdefault("api_base", settings.ollama_base_url)
    return call_kwargs


@retry(
    retry=retry_if_exception_type(_RETRY_EXCEPTIONS),
    wait=wait_exponential(multiplier=1, min=2, max=30),
    stop=stop_after_attempt(3),
    reraise=True,
)
def _call_with_retry(
    model: str, messages: list[dict[str, str]], **kwargs: Any
) -> litellm.ModelResponse:
    rate_limiter.acquire()
    call_kwargs = _prepare_call_kwargs(model, kwargs)
    return litellm.completion(model=model, messages=messages, **call_kwargs)  # type: ignore[return-value]


def chat(
    messages: list[dict[str, str]],
    *,
    use_fast: bool = False,
    temperature: float = 0.2,
    max_tokens: int = 4096,
    use_cache: bool = True,
    **kwargs: Any,
) -> str:
    """
    Send a chat completion request with:
      1. SQLite prompt-hash cache lookup
      2. Fallback chain: Gemini -> Groq -> Ollama
      3. Rate limiting and usage tracking
    """
    # Build provider fallback chain
    fallback_chain = (
        [settings.fast_model, settings.primary_model, settings.fallback_model]
        if use_fast
        else [settings.primary_model, settings.fast_model, settings.fallback_model]
    )

    # De-duplicate while preserving order
    models: list[str] = []
    for m in fallback_chain:
        if m and m not in models:
            models.append(m)

    last_error: Exception | None = None

    for model in models:
        if not provider_available(model):
            logger.debug("llm_provider_skipped_no_key", model=model)
            continue
        prompt_hash = llm_cache.compute_hash(model, messages, temperature)
        if use_cache:
            cached = llm_cache.get(prompt_hash)
            if cached is not None:
                logger.debug("llm_cache_hit", model=model, prompt_hash=prompt_hash[:10])
                return cached

        try:
            start_time = time.monotonic()
            resp = _call_with_retry(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs,
            )
            elapsed = time.monotonic() - start_time
            content = resp.choices[0].message.content or ""

            # Token tracking
            usage = getattr(resp, "usage", None)
            p_tok = getattr(usage, "prompt_tokens", 0) if usage else 0
            c_tok = getattr(usage, "completion_tokens", 0) if usage else 0
            rate_limiter.record_usage(p_tok, c_tok)

            logger.info(
                "llm_call_success",
                model=model,
                elapsed_s=round(elapsed, 2),
                prompt_tokens=p_tok,
                completion_tokens=c_tok,
            )

            if use_cache:
                llm_cache.set(
                    prompt_hash=prompt_hash,
                    model=model,
                    messages=messages,
                    response_text=content,
                    prompt_tokens=p_tok,
                    completion_tokens=c_tok,
                )

            return content

        except Exception as exc:
            logger.warning("llm_provider_attempt_failed", model=model, error=str(exc))
            last_error = exc

    raise LLMError(f"All LLM fallback providers failed. Last error: {last_error}") from last_error


def _strip_markdown_json_fences(text: str) -> str:
    """Extract raw JSON string from Markdown code fences if present."""
    text = text.strip()
    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1 :]
        if text.endswith("```"):
            text = text[:-3]
    return text.strip()


def chat_json(
    messages: list[dict[str, str]],
    *,
    use_fast: bool = False,
    temperature: float = 0.1,
    max_tokens: int = 4096,
    use_cache: bool = True,
    **kwargs: Any,
) -> dict[str, Any]:
    """Execute chat completion and parse response as a dictionary."""
    raw = chat(
        messages,
        use_fast=use_fast,
        temperature=temperature,
        max_tokens=max_tokens,
        use_cache=use_cache,
        **kwargs,
    )
    cleaned = _strip_markdown_json_fences(raw)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise LLMError(f"LLM returned invalid JSON: {cleaned[:300]}") from exc


def chat_structured(
    messages: list[dict[str, str]],
    schema: type[T],
    *,
    use_fast: bool = False,
    temperature: float = 0.1,
    max_tokens: int = 4096,
    use_cache: bool = True,
    **kwargs: Any,
) -> T:
    """
    Structured output helper:
      1. Appends JSON schema instructions to messages
      2. Validates output against Pydantic schema
      3. Performs 1 automatic retry on validation failure with feedback
    """
    json_schema_str = json.dumps(schema.model_json_schema(), indent=2)
    schema_instruction = (
        f"\nYou must return ONLY a single valid JSON object that strictly conforms "
        f"to this JSON schema:\n{json_schema_str}\n"
        f"Do not include markdown fences, comments, or extra conversational text."
    )

    augmented_messages = [dict(m) for m in messages]
    # Append instructions to the last user message or add as a system directive
    if augmented_messages and augmented_messages[-1].get("role") == "user":
        augmented_messages[-1]["content"] += "\n" + schema_instruction
    else:
        augmented_messages.append({"role": "user", "content": schema_instruction})

    # Attempt 1
    raw_response = chat(
        augmented_messages,
        use_fast=use_fast,
        temperature=temperature,
        max_tokens=max_tokens,
        use_cache=use_cache,
        **kwargs,
    )
    cleaned = _strip_markdown_json_fences(raw_response)

    try:
        parsed_dict = json.loads(cleaned)
        return schema.model_validate(parsed_dict)
    except (json.JSONDecodeError, ValidationError) as err:
        logger.warning(
            "structured_output_validation_failed_retrying",
            error=str(err),
            schema=schema.__name__,
        )

        # Retry with feedback: auto-retry 1
        correction_messages = list(augmented_messages)
        correction_messages.append({"role": "assistant", "content": raw_response})
        correction_messages.append(
            {
                "role": "user",
                "content": (
                    f"Your response failed validation with error:\n{err}\n\n"
                    f"Please output ONLY the corrected JSON object matching the schema."
                ),
            }
        )

        retry_response = chat(
            correction_messages,
            use_fast=use_fast,
            temperature=0.0,
            max_tokens=max_tokens,
            use_cache=False,  # Don't cache broken retry state
            **kwargs,
        )
        cleaned_retry = _strip_markdown_json_fences(retry_response)
        try:
            parsed_retry_dict = json.loads(cleaned_retry)
            return schema.model_validate(parsed_retry_dict)
        except Exception as retry_err:
            raise LLMError(
                f"Failed to produce valid structured output for {schema.__name__} after retry: {retry_err}"
            ) from retry_err


def smoke_test_providers() -> dict[str, dict[str, Any]]:
    """
    Smoke test: executes a test prompt through Gemini, Groq, and Ollama.
    Returns status report dictionary.
    """
    providers = {
        "gemini": {
            "model": settings.primary_model,
            "has_key": _has_real_key(settings.gemini_api_key),
        },
        "groq": {
            "model": settings.fast_model,
            "has_key": _has_real_key(settings.groq_api_key),
        },
        "ollama": {
            "model": settings.fallback_model,
            "has_key": True,  # local
        },
    }

    test_messages = [{"role": "user", "content": "Return the word 'PONG'."}]
    results: dict[str, dict[str, Any]] = {}

    for name, info in providers.items():
        model = str(info["model"])
        if not info["has_key"]:
            results[name] = {
                "status": "skipped",
                "reason": "Missing API key in environment or .env",
                "model": model,
            }
            continue

        try:
            call_kwargs = _prepare_call_kwargs(model, {})
            resp = litellm.completion(
                model=model,
                messages=test_messages,
                max_tokens=10,
                timeout=10,
                **call_kwargs,
            )
            content = resp.choices[0].message.content or ""
            results[name] = {
                "status": "ok",
                "model": model,
                "response": content.strip(),
            }
        except Exception as exc:
            results[name] = {
                "status": "failed",
                "model": model,
                "error": str(exc),
            }

    return results
