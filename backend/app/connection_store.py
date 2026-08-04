"""Provider-neutral persistence for externally managed connections and domains."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .sqlite_utils import sqlite_connection

_PROVIDER_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_CONNECTION_STATUSES = {
    "disconnected",
    "authorizing",
    "provisioning",
    "connected",
    "degraded",
    "error",
}
_DOMAIN_STATUSES = {"pending", "active", "error"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ConnectedDomain:
    hostname: str
    status: str
    external_id: str | None = None
    zone_id: str | None = None
    last_error: str | None = None


@dataclass(frozen=True)
class ProviderConnection:
    id: str
    provider: str
    external_id: str
    label: str
    status: str
    account_id: str | None
    public_metadata: dict[str, Any]
    last_error: str | None
    created_at: str
    updated_at: str
    domains: list[ConnectedDomain] = field(default_factory=list)


class ConnectionStore:
    """Store non-secret provider ownership and observed domain state."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with sqlite_connection(self.path) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS provider_connections (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    status TEXT NOT NULL,
                    account_id TEXT,
                    public_metadata TEXT NOT NULL DEFAULT '{}',
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(provider, external_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS connected_domains (
                    id TEXT PRIMARY KEY,
                    connection_id TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    status TEXT NOT NULL,
                    external_id TEXT,
                    zone_id TEXT,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(connection_id, hostname),
                    FOREIGN KEY(connection_id) REFERENCES provider_connections(id) ON DELETE CASCADE
                )
                """
            )

    @staticmethod
    def _validate_provider(provider: str) -> str:
        normalized = provider.strip().lower()
        if not _PROVIDER_PATTERN.fullmatch(normalized):
            raise ValueError("provider must be a lowercase identifier")
        return normalized

    @staticmethod
    def _validate_connection_status(status: str) -> str:
        normalized = status.strip().lower()
        if normalized not in _CONNECTION_STATUSES:
            raise ValueError(f"unsupported connection status: {status}")
        return normalized

    @staticmethod
    def _validate_domain_status(status: str) -> str:
        normalized = status.strip().lower()
        if normalized not in _DOMAIN_STATUSES:
            raise ValueError(f"unsupported domain status: {status}")
        return normalized

    def upsert_connection(
        self,
        *,
        provider: str,
        external_id: str,
        label: str,
        status: str,
        account_id: str | None = None,
        public_metadata: Mapping[str, Any] | None = None,
        last_error: str | None = None,
    ) -> ProviderConnection:
        provider = self._validate_provider(provider)
        status = self._validate_connection_status(status)
        external_id = external_id.strip()
        label = label.strip()
        if not external_id:
            raise ValueError("external_id is required")
        if not label:
            raise ValueError("label is required")
        metadata = dict(public_metadata or {})
        encoded_metadata = json.dumps(metadata, separators=(",", ":"), sort_keys=True)
        now = _utc_now()
        connection_id = str(uuid.uuid4())

        with sqlite_connection(self.path) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(
                """
                INSERT INTO provider_connections (
                    id, provider, external_id, label, status, account_id,
                    public_metadata, last_error, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider, external_id) DO UPDATE SET
                    label = excluded.label,
                    status = excluded.status,
                    account_id = excluded.account_id,
                    public_metadata = excluded.public_metadata,
                    last_error = excluded.last_error,
                    updated_at = excluded.updated_at
                """,
                (
                    connection_id,
                    provider,
                    external_id,
                    label,
                    status,
                    account_id,
                    encoded_metadata,
                    last_error,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT id FROM provider_connections WHERE provider = ? AND external_id = ?",
                (provider, external_id),
            ).fetchone()
        return self.get_connection(str(row["id"]))  # type: ignore[return-value]

    def replace_domains(self, connection_id: str, domains: Sequence[Mapping[str, Any]]) -> None:
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in domains:
            hostname = str(item.get("hostname", "")).strip().lower().rstrip(".")
            if not hostname:
                raise ValueError("hostname is required")
            if hostname in seen:
                raise ValueError(f"duplicate hostname: {hostname}")
            seen.add(hostname)
            normalized.append(
                {
                    "hostname": hostname,
                    "status": self._validate_domain_status(str(item.get("status", ""))),
                    "external_id": item.get("external_id"),
                    "zone_id": item.get("zone_id"),
                    "last_error": item.get("last_error"),
                }
            )

        now = _utc_now()
        with sqlite_connection(self.path) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            exists = connection.execute(
                "SELECT 1 FROM provider_connections WHERE id = ?", (connection_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(connection_id)
            connection.execute("DELETE FROM connected_domains WHERE connection_id = ?", (connection_id,))
            connection.executemany(
                """
                INSERT INTO connected_domains (
                    id, connection_id, hostname, status, external_id, zone_id,
                    last_error, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        str(uuid.uuid4()),
                        connection_id,
                        item["hostname"],
                        item["status"],
                        item["external_id"],
                        item["zone_id"],
                        item["last_error"],
                        now,
                        now,
                    )
                    for item in normalized
                ],
            )

    def get_connection(self, connection_id: str) -> ProviderConnection | None:
        with sqlite_connection(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM provider_connections WHERE id = ?", (connection_id,)
            ).fetchone()
            if row is None:
                return None
            domain_rows = connection.execute(
                """
                SELECT hostname, status, external_id, zone_id, last_error
                FROM connected_domains
                WHERE connection_id = ?
                ORDER BY hostname ASC
                """,
                (connection_id,),
            ).fetchall()
        return self._row_to_connection(row, domain_rows)

    def list_connections(self) -> list[ProviderConnection]:
        with sqlite_connection(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM provider_connections ORDER BY created_at ASC, id ASC"
            ).fetchall()
            domain_rows = connection.execute(
                """
                SELECT connection_id, hostname, status, external_id, zone_id, last_error
                FROM connected_domains
                ORDER BY hostname ASC
                """
            ).fetchall()
        by_connection: dict[str, list[Any]] = {}
        for row in domain_rows:
            by_connection.setdefault(str(row["connection_id"]), []).append(row)
        return [self._row_to_connection(row, by_connection.get(str(row["id"]), [])) for row in rows]

    def delete_connection(self, connection_id: str) -> bool:
        with sqlite_connection(self.path) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            cursor = connection.execute("DELETE FROM provider_connections WHERE id = ?", (connection_id,))
            return cursor.rowcount > 0

    @staticmethod
    def _row_to_connection(row: Any, domain_rows: Sequence[Any]) -> ProviderConnection:
        return ProviderConnection(
            id=str(row["id"]),
            provider=str(row["provider"]),
            external_id=str(row["external_id"]),
            label=str(row["label"]),
            status=str(row["status"]),
            account_id=row["account_id"],
            public_metadata=json.loads(str(row["public_metadata"])),
            last_error=row["last_error"],
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            domains=[
                ConnectedDomain(
                    hostname=str(item["hostname"]),
                    status=str(item["status"]),
                    external_id=item["external_id"],
                    zone_id=item["zone_id"],
                    last_error=item["last_error"],
                )
                for item in domain_rows
            ],
        )
