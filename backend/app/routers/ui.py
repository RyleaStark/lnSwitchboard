"""UI helper routes."""

from __future__ import annotations

import asyncio
import math
from typing import Any, Dict, List, Tuple

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


router = APIRouter(prefix="/api", tags=["ui"])


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


@router.delete("/logs/recent")
async def clear_recent_logs(
    storage: RequestLogStorage = Depends(get_log_storage_dep),
) -> Dict[str, str]:
    await storage.clear()
    return {"status": "cleared"}


@router.get("/health")
async def healthcheck() -> Dict[str, str]:
    return {"status": "ok"}


class MacaroonPayload(BaseModel):
    macaroon: str


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
