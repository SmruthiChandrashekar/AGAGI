"""
core/config.py
--------------
Centralised configuration loaded from environment variables / .env file.
All settings are validated by Pydantic Settings at import time so the app
fails fast if a required value is missing.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnv(StrEnum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# Model names the providers have shut down, mapped to current replacements.
# Older .env files copied from the template still contain the retired names,
# and every call to them fails, so they are upgraded automatically.
RETIRED_MODEL_REPLACEMENTS: dict[str, str] = {
    "gemini/gemini-1.5-flash-latest": "gemini/gemini-3.5-flash",
    "gemini/gemini-1.5-flash": "gemini/gemini-3.5-flash",
    "gemini/gemini-1.5-pro": "gemini/gemini-3.5-flash",
    "gemini/gemini-1.5-pro-latest": "gemini/gemini-3.5-flash",
    "gemini/gemini-2.0-flash": "gemini/gemini-3.5-flash",
    "gemini/gemini-2.0-flash-lite": "gemini/gemini-3.5-flash-lite",
    "groq/llama3-8b-8192": "groq/openai/gpt-oss-20b",
    "groq/llama3-70b-8192": "groq/openai/gpt-oss-120b",
    "groq/llama-3.1-8b-instant": "groq/openai/gpt-oss-20b",
    "groq/llama-3.3-70b-versatile": "groq/openai/gpt-oss-120b",
}


class Settings(BaseSettings):
    """
    Single source of truth for all runtime configuration.
    Values are read from environment variables first, then from the .env file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── LLM ──────────────────────────────────────────────────────────────────
    gemini_api_key: str = Field(default="", description="Google Gemini API key")
    groq_api_key: str = Field(default="", description="Groq API key")
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for local Ollama server",
    )

    primary_model: str = Field(
        default="gemini/gemini-3.5-flash",
        description="LiteLLM model string for complex tasks",
    )
    fast_model: str = Field(
        default="groq/openai/gpt-oss-20b",
        description="LiteLLM model string for cheap/fast tasks",
    )
    fallback_model: str = Field(
        default="ollama/qwen2.5-coder:7b",
        description="LiteLLM model string used when primary and fast fail",
    )

    # ── GitHub App (Mode A) ───────────────────────────────────────────────────
    github_app_id: str = Field(default="", description="GitHub App ID")
    github_app_private_key_path: Path = Field(
        default=Path("./secrets/github_app.pem"),
        description="Path to GitHub App private key (.pem)",
    )
    github_webhook_secret: str = Field(default="", description="GitHub webhook secret")
    github_app_installation_id: str = Field(
        default="", description="GitHub App installation ID"
    )

    # ── Semgrep ───────────────────────────────────────────────────────────────
    semgrep_app_token: str = Field(default="", description="Semgrep Cloud token (optional)")

    # ── Application ───────────────────────────────────────────────────────────
    app_env: AppEnv = Field(default=AppEnv.DEVELOPMENT, description="Runtime environment")
    log_level: LogLevel = Field(default=LogLevel.INFO, description="Logging verbosity")

    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/agentic_reviewer.db",
        description="Async SQLAlchemy database URL",
    )
    chroma_persist_dir: Path = Field(
        default=Path("./data/chroma"),
        description="ChromaDB persistence directory",
    )
    docker_socket: str = Field(
        default="unix:///var/run/docker.sock",
        description="Docker socket path for sandbox containers",
    )

    max_fix_iterations: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum fix-retry loops before escalating to human",
    )
    webhook_port: int = Field(default=8080, description="FastAPI webhook server port")
    dashboard_port: int = Field(default=8501, description="Streamlit dashboard port")

    # ── Derived helpers ───────────────────────────────────────────────────────
    @property
    def is_development(self) -> bool:
        return self.app_env == AppEnv.DEVELOPMENT

    @property
    def data_dir(self) -> Path:
        return Path("./data")

    @field_validator("primary_model", "fast_model", "fallback_model", mode="before")
    @classmethod
    def _upgrade_retired_models(cls, v: object) -> str:
        """Swap model names the providers have shut down for their current replacements."""
        name = str(v or "").strip()
        return RETIRED_MODEL_REPLACEMENTS.get(name, name)

    @field_validator("chroma_persist_dir", "github_app_private_key_path", mode="before")
    @classmethod
    def _coerce_path(cls, v: object) -> Path:
        return Path(str(v))


# Module-level singleton – import this everywhere instead of re-instantiating.
settings = Settings()
