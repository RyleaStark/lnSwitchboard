"""UI helper routes."""

from __future__ import annotations

import asyncio
import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Set, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from ..config import Settings
from ..deps import (
    get_ln_client_dep,
    get_log_storage_dep,
    get_macaroon_store_dep,
    get_settings_dep,
)
from ..ln_client import LNClient
from ..log_storage import RequestLogStorage
from ..macaroon_store import MacaroonStore
from ..env_settings import list_env_settings, update_env_settings


logger = logging.getLogger(__name__)


router = APIRouter(prefix="/api", tags=["ui"])


class EnvSettingsUpdate(BaseModel):
    values: Dict[str, Any]


class MacaroonPayload(BaseModel):
    macaroon: str


async def _refresh_invoice_statuses(entries: List[Dict[str, Any]], ln_client: LNClient) -> None:
    pending: List[Tuple[Dict[str, Any], Dict[str, Any], bytes]] = []
    for entry in entries:
        if entry.get("event") != "invoice":
            continue
        details = entry.get("details")
        if not isinstance(details, dict):
            continue
        payment_hash = details.get("payment_hash")
        if not isinstance(payment_hash, str):
            continue
        invoice_info = details.get("invoice")
        if not isinstance(invoice_info, dict):
            invoice_info = {}
        if invoice_info.get("settled") is True:
            continue
        try:
            payment_hash_bytes = bytes.fromhex(payment_hash.strip())
        except ValueError:
            continue
        pending.append((entry, invoice_info if isinstance(invoice_info, dict) else {}, payment_hash_bytes))

    if not pending:
        return

    async def _lookup(payment_hash_bytes: bytes) -> Any:
        try:
            return await ln_client.lookup_invoice(payment_hash_bytes)
        except Exception as exc:  # pragma: no cover - diagnostics only
            return exc

    results = await asyncio.gather(
        *[_lookup(payment_hash_bytes) for _, _, payment_hash_bytes in pending]
    )

    for (entry, invoice_info, _), result in zip(pending, results):
        if isinstance(result, Exception):
            continue
        settled = bool(result.get("settled"))
        details = entry.setdefault("details", {})
        invoice_details = invoice_info
        invoice_details["settled"] = settled
        details["invoice"] = invoice_details


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


@router.get("/logs/recent")
async def recent_logs(
    storage: RequestLogStorage = Depends(get_log_storage_dep),
    settings: Settings = Depends(get_settings_dep),
    ln_client: LNClient = Depends(get_ln_client_dep),
    q: str = Query("", description="Search query for filtering log entries."),
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        10,
        ge=1,
        le=100,
        description="Number of log entries per page.",
    ),
) -> Dict[str, Any]:
    items = await storage.get_recent(limit=settings.recent_log_limit)
    ordered = list(reversed(items))

    query = q.strip().lower()
    if query:
        def matches(entry: Dict[str, Any]) -> bool:
            for key in ("timestamp", "username", "domain", "ip", "event", "status", "message"):
                value = entry.get(key)
                if isinstance(value, str) and query in value.lower():
                    return True
            amount_msat = entry.get("amount_msat")
            if amount_msat is not None and query in str(amount_msat):
                return True
            details = entry.get("details")
            if isinstance(details, str):
                if query in details.lower():
                    return True
            elif isinstance(details, dict):
                try:
                    if query in str(details).lower():
                        return True
                except Exception:  # pragma: no cover - defensive
                    return False
            return False

        filtered = [entry for entry in ordered if matches(entry)]
    else:
        filtered = ordered

    total_items = len(filtered)
    if total_items == 0:
        return {
            "items": [],
            "page": 1,
            "page_size": page_size,
            "total_items": 0,
            "total_pages": 0,
            "has_next": False,
            "has_prev": False,
            "query": q,
        }

    total_pages = max(1, math.ceil(total_items / page_size))
    current_page = min(page, total_pages)
    start = (current_page - 1) * page_size
    end = start + page_size
    page_items = filtered[start:end]
    await _refresh_invoice_statuses(page_items, ln_client)

    return {
        "items": page_items,
        "page": current_page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "has_next": current_page < total_pages,
        "has_prev": current_page > 1,
        "query": q,
    }


@router.get("/stats/summary")
async def stats_summary(
    storage: RequestLogStorage = Depends(get_log_storage_dep),
) -> Dict[str, int]:
    entries = await storage.get_recent()
    domains: Set[str] = set()
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    requests_24h = 0

    for entry in entries:
        domain = entry.get("domain")
        if isinstance(domain, str):
            normalized = domain.strip().lower()
            if normalized:
                domains.add(normalized)

        ts = _parse_timestamp(entry.get("timestamp"))
        if ts and ts >= cutoff:
            requests_24h += 1

    return {
        "connected_domains": len(domains),
        "requests_24h": requests_24h,
    }


@router.get("/settings/env")
async def get_env_settings(
    ln_client: LNClient = Depends(get_ln_client_dep),
) -> Dict[str, Any]:
    settings = list_env_settings()
    max_field = next((field for field in settings if field.get("key") == "MAX_SENDABLE_SAT"), None)
    if max_field is not None:
        try:
            channels = await ln_client.list_channels(public_only=False)
        except Exception as exc:  # pragma: no cover - network errors
            logger.warning("Failed to refresh max sendable from channels: %s", exc)
        else:
            max_receiving = 0
            for channel in channels:
                value = channel.get("receiving_capacity_sat")
                if isinstance(value, int) and value > max_receiving:
                    max_receiving = value
            max_field["value"] = str(max_receiving)
    return {"settings": settings}


@router.put("/settings/env")
async def put_env_settings(payload: EnvSettingsUpdate) -> Dict[str, Any]:
    updated = update_env_settings(payload.values)
    return {"updated": list(updated.keys())}


@router.get("/channels/public")
async def public_channels(
    ln_client: LNClient = Depends(get_ln_client_dep),
) -> Dict[str, Any]:
    try:
        channels = await ln_client.list_channels(public_only=False)
    except Exception as exc:  # pragma: no cover - network errors
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to load channels") from exc
    total_receiving = sum(channel.get("receiving_capacity_sat", 0) for channel in channels)
    return {
        "channels": channels,
        "total_receiving_capacity_sat": total_receiving,
    }


@router.delete("/logs/recent")
async def clear_recent_logs(
    storage: RequestLogStorage = Depends(get_log_storage_dep),
) -> Dict[str, str]:
    await storage.clear()
    return {"status": "cleared"}


@router.get("/health")
async def healthcheck() -> Dict[str, str]:
    return {"status": "ok"}


@router.get("/auth/status")
async def macaroon_status(
    store: MacaroonStore = Depends(get_macaroon_store_dep),
) -> Dict[str, bool]:
    configured = await store.is_configured()
    return {"configured": configured}


@router.post("/auth/macaroon")
async def set_macaroon(
    payload: MacaroonPayload,
    store: MacaroonStore = Depends(get_macaroon_store_dep),
) -> Dict[str, str]:
    try:
        await store.set(payload.macaroon)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return {"status": "saved"}
