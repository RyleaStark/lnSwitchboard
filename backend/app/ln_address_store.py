"""SQLite-backed overrides for LNURL addresses."""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4
import json


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _encode_webhooks(values: Optional[List[str]]) -> Optional[str]:
    if not values:
        return None
    normalized: List[str] = []
    for value in values:
        if not value:
            continue
        trimmed = value.strip()
        if not trimmed or trimmed in normalized:
            continue
        normalized.append(trimmed)
    if not normalized:
        return None
    return json.dumps(normalized, separators=(",", ":"))


def _decode_webhooks(raw: Optional[str]) -> List[str]:
    if raw is None:
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        data = raw
    values: List[str] = []
    if isinstance(data, list):
        iterator = data
    elif isinstance(data, str):
        iterator = [data]
    else:
        iterator = []
    for entry in iterator:
        if not isinstance(entry, str):
            continue
        trimmed = entry.strip()
        if not trimmed or trimmed in values:
            continue
        values.append(trimmed)
    return values


@dataclass
class LNAddressRecord:
    id: str
    local_part: str
    domain: str
    min_sendable_sat: Optional[int]
    max_sendable_sat: Optional[int]
    metadata_description: Optional[str]
    success_message: Optional[str]
    webhook_urls: List[str]
    created_at: str
    updated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "local_part": self.local_part,
            "domain": self.domain,
            "min_sendable_sat": self.min_sendable_sat,
            "max_sendable_sat": self.max_sendable_sat,
            "metadata_description": self.metadata_description,
            "success_message": self.success_message,
            "webhook_urls": self.webhook_urls,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class AddressConflictError(ValueError):
    """Raised when duplicate local-part/domain combinations are inserted."""


class AddressNotFoundError(KeyError):
    """Raised when an address record cannot be located."""


class LNAddressStore:
    """Manages LNURL address overrides stored in SQLite."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ln_addresses (
                    id TEXT PRIMARY KEY,
                    local_part TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    min_sendable_sat INTEGER,
                    max_sendable_sat INTEGER,
                    metadata_description TEXT,
                    success_message TEXT,
                    webhook_url TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_ln_address_lookup ON ln_addresses(local_part, domain)"
            )
            self._ensure_columns(conn)

    def _ensure_columns(self, conn: sqlite3.Connection) -> None:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(ln_addresses)")}
        if "webhook_url" not in columns:
            conn.execute("ALTER TABLE ln_addresses ADD COLUMN webhook_url TEXT")

    def _normalize(self, value: str) -> str:
        return value.strip().lower()

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "local_part": row["local_part"],
            "domain": row["domain"],
            "min_sendable_sat": row["min_sendable_sat"],
            "max_sendable_sat": row["max_sendable_sat"],
            "metadata_description": row["metadata_description"],
            "success_message": row["success_message"],
            "webhook_urls": _decode_webhooks(row["webhook_url"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    async def list_addresses(self) -> List[Dict[str, Any]]:
        async with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, local_part, domain, min_sendable_sat, max_sendable_sat,
                           metadata_description, success_message, webhook_url, created_at, updated_at
                    FROM ln_addresses
                    ORDER BY domain, local_part
                    """
                ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    async def get_address(self, address_id: str) -> Dict[str, Any]:
        async with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT id, local_part, domain, min_sendable_sat, max_sendable_sat,
                           metadata_description, success_message, webhook_url, created_at, updated_at
                    FROM ln_addresses
                    WHERE id = ?
                    """,
                    (address_id,),
                ).fetchone()
        if row is None:
            raise AddressNotFoundError(address_id)
        return self._row_to_dict(row)

    async def get_by_identifier(self, *, local_part: str, domain: str) -> Optional[Dict[str, Any]]:
        normalized_local = self._normalize(local_part)
        normalized_domain = self._normalize(domain)
        async with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT id, local_part, domain, min_sendable_sat, max_sendable_sat,
                           metadata_description, success_message, webhook_url, created_at, updated_at
                    FROM ln_addresses
                    WHERE local_part = ? AND domain = ?
                    """,
                    (normalized_local, normalized_domain),
                ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    async def add_address(
        self,
        *,
        local_part: str,
        domain: str,
        min_sendable_sat: Optional[int],
        max_sendable_sat: Optional[int],
        metadata_description: Optional[str],
        success_message: Optional[str],
        webhook_urls: Optional[List[str]],
    ) -> Dict[str, Any]:
        async with self._lock:
            normalized_local = self._normalize(local_part)
            normalized_domain = self._normalize(domain)
            now_iso = _now_iso()
            encoded_webhooks = _encode_webhooks(webhook_urls)
            record = {
                "id": str(uuid4()),
                "local_part": normalized_local,
                "domain": normalized_domain,
                "min_sendable_sat": min_sendable_sat,
                "max_sendable_sat": max_sendable_sat,
                "metadata_description": metadata_description,
                "success_message": success_message,
                "webhook_url": encoded_webhooks,
                "webhook_urls": webhook_urls or [],
                "created_at": now_iso,
                "updated_at": now_iso,
            }
            try:
                with self._connect() as conn:
                    conn.execute(
                        """
                        INSERT INTO ln_addresses (
                            id, local_part, domain, min_sendable_sat, max_sendable_sat,
                            metadata_description, success_message, webhook_url, created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record["id"],
                            record["local_part"],
                            record["domain"],
                            record["min_sendable_sat"],
                            record["max_sendable_sat"],
                            record["metadata_description"],
                            record["success_message"],
                            record["webhook_url"],
                            record["created_at"],
                            record["updated_at"],
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise AddressConflictError("Address already exists for this domain") from exc
        return record

    async def update_address(
        self,
        address_id: str,
        *,
        local_part: str,
        domain: str,
        min_sendable_sat: Optional[int],
        max_sendable_sat: Optional[int],
        metadata_description: Optional[str],
        success_message: Optional[str],
        webhook_urls: Optional[List[str]],
    ) -> Dict[str, Any]:
        async with self._lock:
            normalized_local = self._normalize(local_part)
            normalized_domain = self._normalize(domain)
            now_iso = _now_iso()
            try:
                with self._connect() as conn:
                    updated = conn.execute(
                        """
                        UPDATE ln_addresses
                        SET local_part = ?,
                            domain = ?,
                            min_sendable_sat = ?,
                            max_sendable_sat = ?,
                            metadata_description = ?,
                            success_message = ?,
                            webhook_url = ?,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            normalized_local,
                            normalized_domain,
                            min_sendable_sat,
                            max_sendable_sat,
                            metadata_description,
                            success_message,
                            _encode_webhooks(webhook_urls),
                            now_iso,
                            address_id,
                        ),
                    )
                    if updated.rowcount == 0:
                        raise AddressNotFoundError(address_id)
            except sqlite3.IntegrityError as exc:
                raise AddressConflictError("Address already exists for this domain") from exc
        return await self.get_address(address_id)

    async def delete_address(self, address_id: str) -> None:
        async with self._lock:
            with self._connect() as conn:
                deleted = conn.execute(
                    "DELETE FROM ln_addresses WHERE id = ?",
                    (address_id,),
                )
                if deleted.rowcount == 0:
                    raise AddressNotFoundError(address_id)
