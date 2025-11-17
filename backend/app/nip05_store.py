"""Simple JSON-backed storage for NIP-05 identity mappings."""

from __future__ import annotations

import asyncio
import json
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
    """File-backed identity registry with coarse locking."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._records: Dict[str, NostrIdentityRecord] = {}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as fp:
                payload = json.load(fp)
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, list):
            return
        for item in payload:
            if not isinstance(item, dict):
                continue
            record = NostrIdentityRecord.from_dict(item)
            self._records[record.id] = record

    def _persist_locked(self) -> None:
        data = [record.to_dict() for record in self._records.values()]
        tmp_path = self._path.with_suffix(".tmp")
        try:
            with tmp_path.open("w", encoding="utf-8") as fp:
                json.dump(data, fp, indent=2)
            tmp_path.replace(self._path)
        except OSError:
            # Persistence failures are non-fatal; keep in-memory state.
            return

    def _norm(self, value: str) -> str:
        return value.strip().lower()

    def _has_conflict(self, local_part: str, domain: str, *, exclude_id: Optional[str] = None) -> bool:
        for record_id, record in self._records.items():
            if exclude_id and record_id == exclude_id:
                continue
            if record.local_part == local_part and record.domain == domain:
                return True
        return False

    async def list_identities(self) -> List[Dict[str, Any]]:
        async with self._lock:
            records = sorted(
                (record.to_dict() for record in self._records.values()),
                key=lambda entry: (entry["domain"], entry["local_part"]),
            )
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
            if self._has_conflict(normalized_local, normalized_domain):
                raise IdentityConflictError("NIP-05 mapping already exists for this domain and local-part")
            record = NostrIdentityRecord(
                id=str(uuid4()),
                local_part=normalized_local,
                domain=normalized_domain,
                npub=npub,
                pubkey_hex=pubkey_hex,
                relays=list(relays),
                created_at=_now_iso(),
                updated_at=_now_iso(),
            )
            self._records[record.id] = record
            self._persist_locked()
            return deepcopy(record.to_dict())

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
            if identity_id not in self._records:
                raise IdentityNotFoundError(identity_id)
            normalized_local = self._norm(local_part)
            normalized_domain = self._norm(domain)
            if self._has_conflict(normalized_local, normalized_domain, exclude_id=identity_id):
                raise IdentityConflictError("NIP-05 mapping already exists for this domain and local-part")
            record = self._records[identity_id]
            record.local_part = normalized_local
            record.domain = normalized_domain
            record.npub = npub
            record.pubkey_hex = pubkey_hex
            record.relays = list(relays)
            record.updated_at = _now_iso()
            self._persist_locked()
            return deepcopy(record.to_dict())

    async def delete_identity(self, identity_id: str) -> None:
        async with self._lock:
            if identity_id not in self._records:
                raise IdentityNotFoundError(identity_id)
            del self._records[identity_id]
            self._persist_locked()

    async def get_by_domain(self, domain: str) -> List[Dict[str, Any]]:
        normalized_domain = self._norm(domain)
        async with self._lock:
            results = [
                record.to_dict()
                for record in self._records.values()
                if record.domain == normalized_domain
            ]
        return deepcopy(results)
