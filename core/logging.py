"""
core/logging.py
---------------
Structured logging setup via structlog.
Call ``configure_logging()`` once at process startup (done automatically
by ``core/__init__.py``).
"""

from __future__ import annotations

import logging
import sys

import structlog

from core.config import settings


def configure_logging() -> None:
    """Configure structlog + stdlib logging."""
    log_level = settings.log_level.upper()

    # Wire stdlib logging into structlog so third-party libraries also get
    # structured output in development.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level, logging.INFO),
    )

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if settings.is_development:
        # Pretty-print in development
        processors: list[structlog.types.Processor] = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(),
        ]
    else:
        # JSON for staging/production (easy to ship to log aggregators)
        processors = [
            *shared_processors,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level, logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """Return a bound structlog logger for ``name``."""
    return structlog.get_logger(name)
