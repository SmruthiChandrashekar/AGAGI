"""
core/audit.py
-------------
Append-only audit log (SQLite) for human-in-the-loop decisions and fix verification.

Every approval, rejection, verification result and escalation is recorded with who
did it and when, so there is a permanent trail of what was allowed to change the code.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.config import settings
from core.logging import get_logger

logger = get_logger(__name__)


class AuditLog:
    """Thread-safe SQLite audit trail. Rows are only ever inserted, never updated."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = Path(db_path) if db_path else settings.data_dir / "audit.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    thread_id TEXT,
                    event TEXT NOT NULL,
                    actor TEXT,
                    repo TEXT,
                    head_ref TEXT,
                    details_json TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_thread ON audit_log(thread_id)")

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open, commit and always close (an unclosed connection locks the file on Windows)."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def record(
        self,
        event: str,
        *,
        thread_id: str | None = None,
        actor: str | None = None,
        repo: str | None = None,
        head_ref: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Append one event. Never raises: auditing must not break a review."""
        try:
            payload = json.dumps(details or {}, default=str)
            with self._lock, self._connect() as conn:
                conn.execute(
                    "INSERT INTO audit_log (created_at, thread_id, event, actor, repo, head_ref, details_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (datetime.now(UTC).isoformat(), thread_id, event, actor, repo, head_ref, payload),
                )
        except Exception as exc:
            logger.warning("audit_write_failed", event=event, error=str(exc))

    def events(self, thread_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Return events, newest first, optionally for one review run."""
        query = "SELECT * FROM audit_log"
        params: tuple[Any, ...] = ()
        if thread_id:
            query += " WHERE thread_id = ?"
            params = (thread_id,)
        query += " ORDER BY id DESC LIMIT ?"
        params = (*params, limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["details"] = json.loads(item.pop("details_json") or "{}")
            out.append(item)
        return out


audit_log = AuditLog()


def record_for_state(state: dict[str, Any], event: str, *, actor: str | None = None, **details: Any) -> None:
    """Convenience wrapper that fills repo/branch/thread from a ReviewState."""
    cs = state.get("changeset")
    audit_log.record(
        event,
        thread_id=state.get("thread_id"),
        actor=actor,
        repo=str(cs.repo_path) if cs else None,
        head_ref=cs.head_ref if cs else None,
        details=details,
    )
