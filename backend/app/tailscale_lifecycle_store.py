"""Durable, non-secret Tailscale lifecycle intent."""

from __future__ import annotations

import fcntl
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .sqlite_utils import sqlite_connection, sqlite_read_connection

_KEEP_ERROR = object()
_LIFECYCLE_LOCK = threading.RLock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class TailscaleLifecycle:
    operation_id: str
    connection_id: str
    external_id: str
    hostname: str
    phase: str
    last_error: str | None
    created_at: str
    updated_at: str


class TailscaleLifecycleStore:
    """Persist disconnect intent until runtime and registry agree."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with self._write_connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS tailscale_lifecycle (
                    operation_id TEXT PRIMARY KEY,
                    connection_id TEXT NOT NULL UNIQUE,
                    external_id TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    @contextmanager
    def _process_lock(self) -> Iterator[None]:
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @contextmanager
    def _write_connection(self) -> Iterator[sqlite3.Connection]:
        with _LIFECYCLE_LOCK:
            with self._process_lock():
                with sqlite_connection(self.path) as connection:
                    yield connection

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        with _LIFECYCLE_LOCK:
            with sqlite_read_connection(self.path) as connection:
                yield connection

    def create_disconnect(
        self,
        *,
        operation_id: str,
        connection_id: str,
        external_id: str,
        hostname: str,
    ) -> TailscaleLifecycle:
        now = _utc_now()
        try:
            with self._write_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO tailscale_lifecycle (
                        operation_id, connection_id, external_id, hostname,
                        phase, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'prepared', ?, ?)
                    """,
                    (operation_id, connection_id, external_id, hostname, now, now),
                )
        except sqlite3.IntegrityError:
            existing = self.get_for_connection(connection_id)
            if existing is None:
                raise
            if (existing.external_id, existing.hostname) != (external_id, hostname):
                raise ValueError("Tailscale lifecycle identity conflict")
            return existing
        result = self.get(operation_id)
        if result is None:  # pragma: no cover
            raise RuntimeError("Tailscale lifecycle intent was not persisted")
        return result

    def update(
        self,
        operation_id: str,
        *,
        phase: str,
        last_error: str | None | object = _KEEP_ERROR,
    ) -> TailscaleLifecycle:
        with self._write_connection() as connection:
            if last_error is _KEEP_ERROR:
                cursor = connection.execute(
                    "UPDATE tailscale_lifecycle SET phase = ?, updated_at = ? WHERE operation_id = ?",
                    (phase, _utc_now(), operation_id),
                )
            else:
                cursor = connection.execute(
                    "UPDATE tailscale_lifecycle SET phase = ?, last_error = ?, updated_at = ? WHERE operation_id = ?",
                    (phase, last_error, _utc_now(), operation_id),
                )
            if cursor.rowcount == 0:
                raise KeyError(operation_id)
        result = self.get(operation_id)
        if result is None:  # pragma: no cover
            raise KeyError(operation_id)
        return result

    def get(self, operation_id: str) -> TailscaleLifecycle | None:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM tailscale_lifecycle WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
        return self._record(row) if row is not None else None

    def list_pending(self) -> list[TailscaleLifecycle]:
        with self._read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM tailscale_lifecycle ORDER BY created_at, operation_id"
            ).fetchall()
        return [self._record(row) for row in rows]

    def get_for_connection(self, connection_id: str) -> TailscaleLifecycle | None:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM tailscale_lifecycle WHERE connection_id = ?",
                (connection_id,),
            ).fetchone()
        return self._record(row) if row is not None else None

    def delete(self, operation_id: str) -> bool:
        with self._write_connection() as connection:
            cursor = connection.execute(
                "DELETE FROM tailscale_lifecycle WHERE operation_id = ?",
                (operation_id,),
            )
        return cursor.rowcount > 0

    @staticmethod
    def _record(row: sqlite3.Row) -> TailscaleLifecycle:
        return TailscaleLifecycle(
            operation_id=str(row["operation_id"]),
            connection_id=str(row["connection_id"]),
            external_id=str(row["external_id"]),
            hostname=str(row["hostname"]),
            phase=str(row["phase"]),
            last_error=row["last_error"],
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )
