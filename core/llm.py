"""
core/llm.py
-----------
LiteLLM wrapper with:
  - Automatic routing: primary model -> fast model -> fallback
  - Rate-limit-aware retry with exponential backoff (tenacity)
  - Per-call token usage logging
  - Structured output helpers (JSON mode)
"""
from __future__ import annotations

import json
from typing import Any

import litellm
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

# Tell LiteLLM about our keys up front so we do not have to pass them per call.
litellm.api_key = settings.gemini_api_key or settings.groq_api_key  # type: ignore[assignment]


_RETRY_EXCEPTIONS = (
    litellm.RateLimitError,
    litellm.APIConnectionError,
    litellm.Timeout,
)


def _log_usage(response: litellm.ModelResponse, model: str) -> None:
    usage = getattr(response, "usage", None)
    if usage:
        logger.info(
            "llm_call_complete",
            model=model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
        )


@retry(
    retry=retry_if_exception_type(_RETRY_EXCEPTIONS),
    wait=wait_exponential(multiplier=1, min=2, max=60),
    stop=stop_after_attempt(4),
    reraise=True,
)
def _call(model: str, messages: list[dict[str, str]], **kwargs: Any) -> litellm.ModelResponse:
    return litellm.completion(model=model, messages=messages, **kwargs)  # type: ignore[return-value]


def chat(
    messages: list[dict[str, str]],
    *,
    use_fast: bool = False,
    temperature: float = 0.2,
    max_tokens: int = 4096,
    **kwargs: Any,
) -> str:
    """
    Send a chat completion request.

    Args:
        messages:   OpenAI-style message list.
        use_fast:   If True, use the fast/cheap model instead of primary.
        temperature: Sampling temperature.
        max_tokens:  Maximum tokens to generate.

    Returns:
        The assistant message content as a plain string.
    """
    model_order = (
        [settings.fast_model, settings.primary_model, settings.fallback_model]
        if use_fast
        else [settings.primary_model, settings.fast_model, settings.fallback_model]
    )

    last_exc: Exception | None = None
    for model in model_order:
        try:
            resp = _call(model, messages, temperature=temperature, max_tokens=max_tokens, **kwargs)
            _log_usage(resp, model)
            return resp.choices[0].message.content or ""
        except Exception as exc:  # noqa: BLE001
            logger.warning("llm_model_failed", model=model, error=str(exc))
            last_exc = exc

    raise LLMError(f"All LLM models failed. Last error: {last_exc}") from last_exc


def chat_json(
    messages: list[dict[str, str]],
    *,
    use_fast: bool = False,
    temperature: float = 0.1,
    max_tokens: int = 4096,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Like ``chat`` but parses the response as JSON.
    Raises ``LLMError`` if parsing fails.
    """
    raw = chat(messages, use_fast=use_fast, temperature=temperature, max_tokens=max_tokens, **kwargs)
    # Strip markdown code fences if the model wrapped the JSON
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError(f"LLM returned non-JSON content: {raw[:200]}") from exc
