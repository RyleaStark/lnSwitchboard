"""SQLite-backed storage for NIP-05 identity mappings."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from copy import deepcopy
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

from .sqlite_utils import sqlite_connection


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


@dataclass
class NostrIdentityRecord:
    id: str
    local_part: str
    domain: str
    npub: str
    pubkey_hex: str
    relays: List[str]
    created_at: str
    updated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "local_part": self.local_part,
            "domain": self.domain,
            "npub": self.npub,
            "pubkey_hex": self.pubkey_hex,
            "relays": list(self.relays),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "NostrIdentityRecord":
        relays = payload.get("relays") or []
        if not isinstance(relays, list):
            relays = []
        safe_relays = [str(relay) for relay in relays if isinstance(relay, str)]
        return cls(
            id=str(payload.get("id") or uuid4()),
            local_part=str(payload.get("local_part", "")).lower(),
            domain=str(payload.get("domain", "")).lower(),
            npub=str(payload.get("npub", "")),
            pubkey_hex=str(payload.get("pubkey_hex", "")),
            relays=safe_relays,
            created_at=str(payload.get("created_at") or _now_iso()),
            updated_at=str(payload.get("updated_at") or _now_iso()),
        )


class IdentityConflictError(ValueError):
    """Raised when a duplicate NIP-05 mapping is detected."""


class IdentityNotFoundError(KeyError):
    """Raised when an identity record cannot be found."""


class IdentityDomainLimitError(ValueError):
    """Raised when a domain cannot safely add another public identity."""


MAX_IDENTITIES_PER_DOMAIN = 16


class NostrIdentityStore:
    """SQLite-backed identity registry with coarse locking."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> AbstractContextManager[sqlite3.Connection]:
        return sqlite_connection(self._path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nostr_identities (
                    id TEXT PRIMARY KEY,
                    local_part TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    npub TEXT NOT NULL,
                    pubkey_hex TEXT NOT NULL,
                    relays TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_nostr_identity_lookup ON nostr_identities(local_part, domain)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_nostr_identity_domain ON nostr_identities(domain)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_nostr_identity_public ON nostr_identities(domain, local_part)"
            )

    def _norm(self, value: str) -> str:
        return value.strip().lower()

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        relays_raw = row["relays"] or "[]"
        try:
            relays = json.loads(relays_raw)
        except json.JSONDecodeError:
            relays = []
        return {
            "id": row["id"],
            "local_part": row["local_part"],
            "domain": row["domain"],
            "npub": row["npub"],
            "pubkey_hex": row["pubkey_hex"],
            "relays": relays,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    async def list_identities(self) -> List[Dict[str, Any]]:
        async with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT id, local_part, domain, npub, pubkey_hex, relays, created_at, updated_at
                        FROM nostr_identities
                        ORDER BY domain, local_part
                        """
                    ).fetchall()
            except sqlite3.Error:
                return []
        records = [self._row_to_dict(row) for row in rows]
        return deepcopy(records)

    async def add_identity(
        self,
        *,
        local_part: str,
        domain: str,
        npub: str,
        pubkey_hex: str,
        relays: List[str],
    ) -> Dict[str, Any]:
        async with self._lock:
            normalized_local = self._norm(local_part)
            normalized_domain = self._norm(domain)
            now_iso = _now_iso()
            record = {
                "id": str(uuid4()),
                "local_part": normalized_local,
                "domain": normalized_domain,
                "npub": npub,
                "pubkey_hex": pubkey_hex,
                "relays": list(relays),
                "created_at": now_iso,
                "updated_at": now_iso,
            }
            try:
                with self._connect() as conn:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM nostr_identities WHERE domain = ?",
                        (normalized_domain,),
                    ).fetchone()[0]
                    if int(count) >= MAX_IDENTITIES_PER_DOMAIN:
                        raise IdentityDomainLimitError(
                            f"A domain may have at most {MAX_IDENTITIES_PER_DOMAIN} NIP-05 identities"
                        )
                    conn.execute(
                        """
                        INSERT INTO nostr_identities (
                            id, local_part, domain, npub, pubkey_hex, relays, created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record["id"],
                            record["local_part"],
                            record["domain"],
                            record["npub"],
                            record["pubkey_hex"],
                            json.dumps(record["relays"]),
                            record["created_at"],
                            record["updated_at"],
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise IdentityConflictError("NIP-05 mapping already exists for this domain and local-part") from exc
        return deepcopy(record)

    async def update_identity(
        self,
        identity_id: str,
        *,
        local_part: str,
        domain: str,
        npub: str,
        pubkey_hex: str,
        relays: List[str],
    ) -> Dict[str, Any]:
        async with self._lock:
            normalized_local = self._norm(local_part)
            normalized_domain = self._norm(domain)
            now_iso = _now_iso()
            try:
                with self._connect() as conn:
                    current = conn.execute(
                        "SELECT domain FROM nostr_identities WHERE id = ?", (identity_id,)
                    ).fetchone()
                    if current is None:
                        raise IdentityNotFoundError(identity_id)
                    if str(current[0]) != normalized_domain:
                        count = conn.execute(
                            "SELECT COUNT(*) FROM nostr_identities WHERE domain = ?",
                            (normalized_domain,),
                        ).fetchone()[0]
                        if int(count) >= MAX_IDENTITIES_PER_DOMAIN:
                            raise IdentityDomainLimitError(
                                f"A domain may have at most {MAX_IDENTITIES_PER_DOMAIN} NIP-05 identities"
                            )
                    result = conn.execute(
                        """
                        UPDATE nostr_identities
                        SET local_part = ?, domain = ?, npub = ?, pubkey_hex = ?, relays = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            normalized_local,
                            normalized_domain,
                            npub,
                            pubkey_hex,
                            json.dumps(list(relays)),
                            now_iso,
                            identity_id,
                        ),
                    )
                    if result.rowcount == 0:
                        raise IdentityNotFoundError(identity_id)
            except sqlite3.IntegrityError as exc:
                raise IdentityConflictError("NIP-05 mapping already exists for this domain and local-part") from exc
            try:
                with self._connect() as conn:
                    row = conn.execute(
                        """
                        SELECT id, local_part, domain, npub, pubkey_hex, relays, created_at, updated_at
                        FROM nostr_identities
                        WHERE id = ?
                        """,
                        (identity_id,),
                    ).fetchone()
            except sqlite3.Error as exc:  # pragma: no cover - defensive
                raise IdentityNotFoundError(identity_id) from exc
        if not row:
            raise IdentityNotFoundError(identity_id)
        return deepcopy(self._row_to_dict(row))

    async def delete_identity(self, identity_id: str) -> None:
        async with self._lock:
            try:
                with self._connect() as conn:
                    result = conn.execute("DELETE FROM nostr_identities WHERE id = ?", (identity_id,))
            except sqlite3.Error as exc:
                raise IdentityNotFoundError(identity_id) from exc
            if result.rowcount == 0:
                raise IdentityNotFoundError(identity_id)

    async def get_by_domain(self, domain: str) -> List[Dict[str, Any]]:
        normalized_domain = self._norm(domain)
        async with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT id, local_part, domain, npub, pubkey_hex, relays, created_at, updated_at
                        FROM nostr_identities
                        WHERE domain = ?
                        ORDER BY local_part
                        """,
                        (normalized_domain,),
                    ).fetchall()
            except sqlite3.Error:
                return []
        records = [self._row_to_dict(row) for row in rows]
        return deepcopy(records)

    async def get_public_by_domain(
        self, domain: str, *, local_part: str | None = None
    ) -> List[Dict[str, Any]]:
        """Read a bounded public projection, including legacy oversized rows safely."""

        normalized_domain = self._norm(domain)
        normalized_local = self._norm(local_part) if local_part is not None else None
        async with self._lock:
            try:
                with self._connect() as conn:
                    if normalized_local is None:
                        rows = conn.execute(
                            """
                            SELECT id,
                                   CASE WHEN length(CAST(local_part AS BLOB)) <= 64
                                        THEN local_part ELSE '' END AS local_part,
                                   CASE WHEN length(CAST(domain AS BLOB)) <= 253
                                        THEN domain ELSE '' END AS domain,
                                   CASE WHEN length(CAST(npub AS BLOB)) <= 128
                                        THEN npub ELSE '' END AS npub,
                                   CASE WHEN length(CAST(pubkey_hex AS BLOB)) = 64
                                        THEN pubkey_hex ELSE '' END AS pubkey_hex,
                                   CASE WHEN length(CAST(relays AS BLOB)) <= 16384
                                        THEN relays ELSE '[]' END AS relays,
                                   created_at, updated_at
                            FROM nostr_identities
                            WHERE domain = ?
                            ORDER BY local_part
                            LIMIT ?
                            """,
                            (normalized_domain, MAX_IDENTITIES_PER_DOMAIN),
                        ).fetchall()
                    else:
                        rows = conn.execute(
                            """
                            SELECT id,
                                   CASE WHEN length(CAST(local_part AS BLOB)) <= 64
                                        THEN local_part ELSE '' END AS local_part,
                                   CASE WHEN length(CAST(domain AS BLOB)) <= 253
                                        THEN domain ELSE '' END AS domain,
                                   CASE WHEN length(CAST(npub AS BLOB)) <= 128
                                        THEN npub ELSE '' END AS npub,
                                   CASE WHEN length(CAST(pubkey_hex AS BLOB)) = 64
                                        THEN pubkey_hex ELSE '' END AS pubkey_hex,
                                   CASE WHEN length(CAST(relays AS BLOB)) <= 16384
                                        THEN relays ELSE '[]' END AS relays,
                                   created_at, updated_at
                            FROM nostr_identities
                            WHERE domain = ? AND local_part = ?
                            LIMIT 1
                            """,
                            (normalized_domain, normalized_local),
                        ).fetchall()
            except sqlite3.Error:
                return []
        return deepcopy([self._row_to_dict(row) for row in rows])

    async def has_domain(self, domain: str) -> bool:
        normalized_domain = self._norm(domain)
        async with self._lock:
            try:
                with self._connect() as conn:
                    row = conn.execute(
                        "SELECT 1 FROM nostr_identities WHERE domain = ? LIMIT 1",
                        (normalized_domain,),
                    ).fetchone()
            except sqlite3.Error:
                return False
        return row is not None
