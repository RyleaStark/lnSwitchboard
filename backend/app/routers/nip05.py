"""NIP-05 identity management endpoints and well-known handler."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from ..deps import get_ln_address_store_dep, get_nip05_store_dep, get_nostr_signer_store_dep
from ..ln_address_store import LNAddressStore
from ..nostr_signer_store import NostrSignerStore
from ..nip05_store import (
    IdentityConflictError,
    IdentityNotFoundError,
    NostrIdentityStore,
)
from ..nip05_utils import NpubFormatError, hex_to_npub, npub_to_hex


api_router = APIRouter(prefix="/api/nip05", tags=["nostr"])
public_router = APIRouter(include_in_schema=False)

LOCAL_PART_PATTERN = re.compile(r"^[a-z0-9._-]+$")
DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")
ALLOWED_RELAY_SCHEMES = {"ws", "wss"}
MAX_RELAYS = 16
RESERVED_LOCAL_PARTS = {"nip-profile"}


class IdentityPayload(BaseModel):
    local_part: str = Field(..., description="NIP-05 local-part before the '@'.")
    domain: str = Field(..., description="Domain that will serve the .well-known mapping.")
    npub: str = Field(..., description="Nostr public key (npub or 64-char hex).")
    relays: List[str] = Field(default_factory=list, description="Relay URLs advertising this pubkey.")

    @field_validator("local_part")
    @classmethod
    def _validate_local_part(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("local-part is required")
        if "@" in normalized:
            raise ValueError("Do not include '@' in the local-part")
        if not LOCAL_PART_PATTERN.fullmatch(normalized):
            raise ValueError("local-part may contain [a-z0-9._-] only")
        if normalized in RESERVED_LOCAL_PARTS:
            raise ValueError("local-part is reserved")
        return normalized

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("domain is required")
        if "://" in normalized:
            raise ValueError("domain must not include a URL scheme")
        normalized = normalized.rstrip(".")
        if not DOMAIN_PATTERN.fullmatch(normalized):
            raise ValueError("domain may contain letters, numbers, dots, and dashes only")
        return normalized

    @field_validator("relays", mode="before")
    @classmethod
    def _coerce_relays(cls, value):
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return value


def _normalize_relays(relays: Sequence[str]) -> List[str]:
    normalized: List[str] = []
    seen = set()
    for relay in relays:
        cleaned = relay.strip()
        if not cleaned:
            continue
        parsed = urlsplit(cleaned if "://" in cleaned else f"wss://{cleaned}")
        if parsed.scheme.lower() not in ALLOWED_RELAY_SCHEMES:
            raise ValueError("Relay URLs must use ws:// or wss://")
        if not parsed.netloc:
            raise ValueError("Relay URLs must include a host")
        path = parsed.path or ""
        normalized_url = f"{parsed.scheme.lower()}://{parsed.netloc}{path}"
        if parsed.query:
            normalized_url = f"{normalized_url}?{parsed.query}"
        if parsed.fragment:
            normalized_url = f"{normalized_url}#{parsed.fragment}"
        normalized_url = normalized_url.rstrip("/")
        if normalized_url not in seen:
            seen.add(normalized_url)
            normalized.append(normalized_url)
    if len(normalized) > MAX_RELAYS:
        raise ValueError(f"Provide at most {MAX_RELAYS} relay URLs")
    return normalized


def _public_relays(relays: Any) -> List[str]:
    if not isinstance(relays, list):
        return []
    normalized: List[str] = []
    seen = set()
    for relay in relays:
        if not isinstance(relay, str):
            continue
        try:
            candidates = _normalize_relays([relay])
        except ValueError:
            continue
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                normalized.append(candidate)
    return normalized


def _serialize_identity(record: Dict[str, Any]) -> Dict[str, Any]:
    identifier = f"{record['local_part']}@{record['domain']}"
    return {
        "id": record["id"],
        "local_part": record["local_part"],
        "domain": record["domain"],
        "identifier": identifier,
        "npub": record["npub"],
        "pubkey_hex": record["pubkey_hex"],
        "relays": record.get("relays", []),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
    }


def _prepare_payload(payload: IdentityPayload) -> Dict[str, Any]:
    try:
        pubkey_hex = npub_to_hex(payload.npub)
        canonical_npub = hex_to_npub(pubkey_hex)
    except NpubFormatError as exc:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    try:
        relays = _normalize_relays(payload.relays)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return {
        "local_part": payload.local_part,
        "domain": payload.domain,
        "npub": canonical_npub,
        "pubkey_hex": pubkey_hex,
        "relays": relays,
    }


@api_router.get("/identities")
async def list_identities(store: NostrIdentityStore = Depends(get_nip05_store_dep)) -> Dict[str, Any]:
    items = await store.list_identities()
    return {"items": [_serialize_identity(item) for item in items]}


@api_router.post("/identities", status_code=status.HTTP_201_CREATED)
async def create_identity(
    payload: IdentityPayload,
    store: NostrIdentityStore = Depends(get_nip05_store_dep),
) -> Dict[str, Any]:
    data = _prepare_payload(payload)
    try:
        created = await store.add_identity(**data)
    except IdentityConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"item": _serialize_identity(created)}


@api_router.put("/identities/{identity_id}")
async def update_identity(
    identity_id: str,
    payload: IdentityPayload,
    store: NostrIdentityStore = Depends(get_nip05_store_dep),
) -> Dict[str, Any]:
    data = _prepare_payload(payload)
    try:
        updated = await store.update_identity(identity_id, **data)
    except IdentityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found") from exc
    except IdentityConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"item": _serialize_identity(updated)}


@api_router.delete("/identities/{identity_id}")
async def delete_identity(
    identity_id: str,
    store: NostrIdentityStore = Depends(get_nip05_store_dep),
) -> Dict[str, str]:
    try:
        await store.delete_identity(identity_id)
    except IdentityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found") from exc
    return {"status": "deleted"}


def _resolve_domain(request: Request) -> str:
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("host")
        or (request.url.hostname or "")
    )
    host = host.split(",")[0].strip()
    if ":" in host:
        host = host.split(":", 1)[0]
    return host.lower()


@public_router.get("/.well-known/nostr.json")
async def nostr_well_known(
    request: Request,
    name: Optional[str] = Query(
        default=None,
        description="Optional NIP-05 local-part for filtering results.",
    ),
    store: NostrIdentityStore = Depends(get_nip05_store_dep),
) -> JSONResponse:
    domain = _resolve_domain(request)
    entries = await store.get_by_domain(domain) if domain else []
    if name:
        target = name.strip().lower()
        entries = [entry for entry in entries if entry["local_part"] == target]
    names = {entry["local_part"]: entry["pubkey_hex"] for entry in entries}
    relays_map: Dict[str, List[str]] = {}
    for entry in entries:
        relays = _public_relays(entry.get("relays"))
        if relays:
            relays_map[entry["pubkey_hex"]] = relays
    payload: Dict[str, Any] = {"names": names}
    if relays_map:
        payload["relays"] = relays_map
    response = JSONResponse(payload)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Cache-Control"] = "no-store"
    return response


@public_router.get("/.well-known/lnurlp/nip-profile/{local_part}")
async def public_profile(
    local_part: str,
    request: Request,
    identity_store: NostrIdentityStore = Depends(get_nip05_store_dep),
    address_store: LNAddressStore = Depends(get_ln_address_store_dep),
    signer_store: NostrSignerStore = Depends(get_nostr_signer_store_dep),
) -> JSONResponse:
    domain = _resolve_domain(request)
    local = local_part.strip().lower()
    if not LOCAL_PART_PATTERN.fullmatch(local):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
    identity = None
    for entry in await identity_store.get_by_domain(domain):
        if entry.get("local_part") == local:
            identity = entry
            break
    address = await address_store.get_by_identifier(local_part=local, domain=domain)
    signer = await signer_store.status()
    if identity is None and address is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
    payload = {
        "identifier": f"{local}@{domain}",
        "domain": domain,
        "local_part": local,
        "ln_address": f"{local}@{domain}" if address else None,
        "nostr": {
            "npub": identity.get("npub") if identity else None,
            "pubkey_hex": identity.get("pubkey_hex") if identity else None,
            "relays": _public_relays(identity.get("relays")) if identity else [],
        },
        "zap": {
            "ready": bool(identity and address and signer.configured),
            "receipt_pubkey": signer.pubkey if signer.configured else None,
            "forwarded": bool(address and address.get("routing_mode") == "forward"),
        },
    }
    response = JSONResponse(payload)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Cache-Control"] = "no-store"
    return response
