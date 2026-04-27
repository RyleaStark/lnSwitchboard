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
import hashlib


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


def _endpoint_id(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def _normalize_endpoint(entry: Any) -> Optional[Dict[str, Any]]:
    if isinstance(entry, str):
        url = entry.strip()
        if not url:
            return None
        return {
            "id": _endpoint_id(url),
            "url": url,
            "label": "",
            "secret_configured": False,
            "secret": None,
            "filters": {},
        }
    if not isinstance(entry, dict):
        return None
    url = str(entry.get("url") or "").strip()
    if not url:
        return None
    endpoint_id = str(entry.get("id") or _endpoint_id(url)).strip() or _endpoint_id(url)
    filters = entry.get("filters")
    if not isinstance(filters, dict):
        filters = {}
    secret = entry.get("secret")
    if not isinstance(secret, str) or not secret.strip():
        secret = None
    return {
        "id": endpoint_id,
        "url": url,
        "label": str(entry.get("label") or "").strip(),
        "secret": secret,
        "secret_configured": bool(secret or entry.get("secret_configured")),
        "filters": filters,
    }


def _encode_webhook_endpoints(endpoints: Optional[List[Dict[str, Any]]], fallback_urls: Optional[List[str]]) -> Optional[str]:
    normalized: List[Dict[str, Any]] = []
    candidates: List[Any] = list(endpoints or [])
    if not candidates:
        candidates = list(fallback_urls or [])
    seen: set[str] = set()
    for candidate in candidates:
        endpoint = _normalize_endpoint(candidate)
        if not endpoint or endpoint["url"] in seen:
            continue
        seen.add(endpoint["url"])
        stored = dict(endpoint)
        stored.pop("secret_configured", None)
        normalized.append(stored)
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


def _decode_webhook_endpoints(raw: Optional[str]) -> List[Dict[str, Any]]:
    if raw is None:
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        data = raw
    if isinstance(data, list):
        iterator = data
    elif isinstance(data, str):
        iterator = [data]
    else:
        iterator = []
    endpoints: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for entry in iterator:
        endpoint = _normalize_endpoint(entry)
        if not endpoint or endpoint["url"] in seen:
            continue
        seen.add(endpoint["url"])
        endpoints.append(endpoint)
    return endpoints


def _public_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    public = dict(endpoint)
    public.pop("secret", None)
    public["secret_configured"] = bool(endpoint.get("secret") or endpoint.get("secret_configured"))
    return public


def _encode_payer_data(value: Optional[Dict[str, bool]]) -> Optional[str]:
    if not value:
        return None
    return json.dumps(value, separators=(",", ":"))


def _decode_payer_data(raw: Optional[str]) -> Dict[str, bool]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): bool(value) for key, value in data.items()}


@dataclass
class LNAddressRecord:
    id: str
    local_part: str
    domain: str
    routing_mode: str
    forward_to: Optional[str]
    min_sendable_sat: Optional[int]
    max_sendable_sat: Optional[int]
    metadata_description: Optional[str]
    success_message: Optional[str]
    webhook_urls: List[str]
    webhook_endpoints: List[Dict[str, Any]]
    payer_data: Dict[str, bool]
    created_at: str
    updated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "local_part": self.local_part,
            "domain": self.domain,
            "routing_mode": self.routing_mode,
            "forward_to": self.forward_to,
            "min_sendable_sat": self.min_sendable_sat,
            "max_sendable_sat": self.max_sendable_sat,
            "metadata_description": self.metadata_description,
            "success_message": self.success_message,
            "webhook_urls": self.webhook_urls,
            "webhook_endpoints": self.webhook_endpoints,
            "payer_data": self.payer_data,
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
                    routing_mode TEXT NOT NULL DEFAULT 'local',
                    forward_to TEXT,
                    min_sendable_sat INTEGER,
                    max_sendable_sat INTEGER,
                    metadata_description TEXT,
                    success_message TEXT,
                    webhook_url TEXT,
                    payer_data TEXT,
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
        if "routing_mode" not in columns:
            conn.execute("ALTER TABLE ln_addresses ADD COLUMN routing_mode TEXT NOT NULL DEFAULT 'local'")
        if "forward_to" not in columns:
            conn.execute("ALTER TABLE ln_addresses ADD COLUMN forward_to TEXT")
        if "payer_data" not in columns:
            conn.execute("ALTER TABLE ln_addresses ADD COLUMN payer_data TEXT")

    def _normalize(self, value: str) -> str:
        return value.strip().lower()

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        endpoints = _decode_webhook_endpoints(row["webhook_url"])
        return {
            "id": row["id"],
            "local_part": row["local_part"],
            "domain": row["domain"],
            "routing_mode": row["routing_mode"] or "local",
            "forward_to": row["forward_to"],
            "min_sendable_sat": row["min_sendable_sat"],
            "max_sendable_sat": row["max_sendable_sat"],
            "metadata_description": row["metadata_description"],
            "success_message": row["success_message"],
            "webhook_urls": [endpoint["url"] for endpoint in endpoints],
            "webhook_endpoints": endpoints,
            "payer_data": _decode_payer_data(row["payer_data"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    async def list_addresses(self) -> List[Dict[str, Any]]:
        async with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, local_part, domain, routing_mode, forward_to, min_sendable_sat, max_sendable_sat,
                           metadata_description, success_message, webhook_url, payer_data, created_at, updated_at
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
                    SELECT id, local_part, domain, routing_mode, forward_to, min_sendable_sat, max_sendable_sat,
                           metadata_description, success_message, webhook_url, payer_data, created_at, updated_at
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
                    SELECT id, local_part, domain, routing_mode, forward_to, min_sendable_sat, max_sendable_sat,
                           metadata_description, success_message, webhook_url, payer_data, created_at, updated_at
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
        webhook_endpoints: Optional[List[Dict[str, Any]]] = None,
        payer_data: Optional[Dict[str, bool]] = None,
        routing_mode: str = "local",
        forward_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        async with self._lock:
            normalized_local = self._normalize(local_part)
            normalized_domain = self._normalize(domain)
            normalized_mode = self._normalize(routing_mode or "local")
            normalized_forward_to = self._normalize(forward_to) if forward_to else None
            now_iso = _now_iso()
            encoded_webhooks = _encode_webhook_endpoints(webhook_endpoints, webhook_urls)
            public_endpoints = [_public_endpoint(endpoint) for endpoint in _decode_webhook_endpoints(encoded_webhooks)]
            record = {
                "id": str(uuid4()),
                "local_part": normalized_local,
                "domain": normalized_domain,
                "routing_mode": normalized_mode,
                "forward_to": normalized_forward_to,
                "min_sendable_sat": min_sendable_sat,
                "max_sendable_sat": max_sendable_sat,
                "metadata_description": metadata_description,
                "success_message": success_message,
                "webhook_url": encoded_webhooks,
                "webhook_urls": [endpoint["url"] for endpoint in public_endpoints],
                "webhook_endpoints": public_endpoints,
                "payer_data": payer_data or {},
                "payer_data_raw": _encode_payer_data(payer_data),
                "created_at": now_iso,
                "updated_at": now_iso,
            }
            try:
                with self._connect() as conn:
                    conn.execute(
                        """
                        INSERT INTO ln_addresses (
                            id, local_part, domain, routing_mode, forward_to, min_sendable_sat, max_sendable_sat,
                            metadata_description, success_message, webhook_url, payer_data, created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record["id"],
                            record["local_part"],
                            record["domain"],
                            record["routing_mode"],
                            record["forward_to"],
                            record["min_sendable_sat"],
                            record["max_sendable_sat"],
                            record["metadata_description"],
                            record["success_message"],
                            record["webhook_url"],
                            record["payer_data_raw"],
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
        webhook_endpoints: Optional[List[Dict[str, Any]]] = None,
        payer_data: Optional[Dict[str, bool]] = None,
        routing_mode: str = "local",
        forward_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        async with self._lock:
            normalized_local = self._normalize(local_part)
            normalized_domain = self._normalize(domain)
            normalized_mode = self._normalize(routing_mode or "local")
            normalized_forward_to = self._normalize(forward_to) if forward_to else None
            now_iso = _now_iso()
            try:
                with self._connect() as conn:
                    existing = conn.execute(
                        "SELECT webhook_url FROM ln_addresses WHERE id = ?",
                        (address_id,),
                    ).fetchone()
                    merged_endpoints = webhook_endpoints
                    if existing is not None and webhook_endpoints is not None:
                        existing_by_url = {
                            endpoint["url"]: endpoint
                            for endpoint in _decode_webhook_endpoints(existing["webhook_url"])
                        }
                        merged_endpoints = []
                        for endpoint in webhook_endpoints:
                            prepared = dict(endpoint)
                            existing_endpoint = existing_by_url.get(str(prepared.get("url") or ""))
                            if existing_endpoint and not prepared.get("secret"):
                                prepared["secret"] = existing_endpoint.get("secret")
                            merged_endpoints.append(prepared)
                    updated = conn.execute(
                        """
                        UPDATE ln_addresses
                        SET local_part = ?,
                            domain = ?,
                            routing_mode = ?,
                            forward_to = ?,
                            min_sendable_sat = ?,
                            max_sendable_sat = ?,
                            metadata_description = ?,
                            success_message = ?,
                            webhook_url = ?,
                            payer_data = ?,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            normalized_local,
                            normalized_domain,
                            normalized_mode,
                            normalized_forward_to,
                            min_sendable_sat,
                            max_sendable_sat,
                            metadata_description,
                            success_message,
                            _encode_webhook_endpoints(merged_endpoints, webhook_urls),
                            _encode_payer_data(payer_data),
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
