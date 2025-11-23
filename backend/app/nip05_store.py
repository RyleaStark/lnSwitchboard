"""SQLite-backed storage for NIP-05 identity mappings."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4


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


class NostrIdentityStore:
    """SQLite-backed identity registry with coarse locking."""

    def __init__(self, path: Path, *, legacy_json_path: Optional[Path] = None) -> None:
        self._path = path
        self._legacy_json_path = legacy_json_path
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._maybe_import_legacy()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

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

    def _maybe_import_legacy(self) -> None:
        legacy_path = self._legacy_json_path
        if not legacy_path or legacy_path == self._path or not legacy_path.exists():
            return
        try:
            with self._connect() as conn:
                row = conn.execute("SELECT 1 FROM nostr_identities LIMIT 1").fetchone()
                if row:
                    return
        except sqlite3.Error:
            return
        try:
            with legacy_path.open("r", encoding="utf-8") as fp:
                payload = json.load(fp)
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, list):
            return
        records = [NostrIdentityRecord.from_dict(item) for item in payload if isinstance(item, dict)]
        if not records:
            return
        try:
            with self._connect() as conn:
                conn.executemany(
                    """
                    INSERT INTO nostr_identities (
                        id, local_part, domain, npub, pubkey_hex, relays, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            record.id,
                            record.local_part,
                            record.domain,
                            record.npub,
                            record.pubkey_hex,
                            json.dumps(record.relays),
                            record.created_at,
                            record.updated_at,
                        )
                        for record in records
                    ],
                )
        except sqlite3.Error:
            return
        try:
            legacy_path.rename(legacy_path.with_suffix(f"{legacy_path.suffix or ''}.migrated"))
        except OSError:
            try:
                legacy_path.unlink()
            except OSError:
                pass

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
