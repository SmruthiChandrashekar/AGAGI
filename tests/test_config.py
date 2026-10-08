"""Smoke tests for the config loader."""
from __future__ import annotations

from core.config import Settings


def test_settings_loads_defaults() -> None:
    """Settings must instantiate with all defaults without a .env file."""
    s = Settings()
    assert s.max_fix_iterations == 3
    assert s.webhook_port == 8080
    assert s.app_env.value == "development"


def test_primary_model_has_value() -> None:
    s = Settings()
    assert "/" in s.primary_model, "Model string must be in provider/model format"
