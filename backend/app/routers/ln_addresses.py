"""CRUD endpoints for LNURL address overrides."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator, model_validator

from ..deps import get_ln_address_store_dep
from ..ln_address_store import AddressConflictError, AddressNotFoundError, LNAddressStore
from ..lnurl_forwarding import ForwardingTarget, ForwardingTargetError, fetch_forwarding_discovery


api_router = APIRouter(prefix="/api/lnaddresses", tags=["ln_addresses"])

LOCAL_PART_PATTERN = re.compile(r"^[a-z0-9._-]+$")
DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")
MAX_TEMPLATE_CHARS = 512
WEBHOOK_SCHEMES = {"http", "https"}


def _clean_template(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def _normalize_webhook_url(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Invalid webhook URL")
    candidate = value.strip()
    if not candidate:
        return None
    parsed = urlsplit(candidate)
    scheme = (parsed.scheme or "").lower()
    if scheme not in WEBHOOK_SCHEMES:
        raise ValueError("Webhook URL must start with http:// or https://")
    if not parsed.netloc:
        raise ValueError("Webhook URL must include a host")
    path = parsed.path or "/"
    normalized = urlunsplit((scheme, parsed.netloc.lower(), path, parsed.query, parsed.fragment))
    return normalized


class LNAddressPayload(BaseModel):
    local_part: str = Field(
        ...,
        description="local-part used before the '@'. Configure the base handle only (tags like user+vip inherit automatically).",
    )
    domain: str = Field(..., description="Domain that hosts the LNURL endpoint.")
    routing_mode: Literal["local", "forward"] = Field(
        default="local",
        description="local mints invoices with this node; forward proxies to another Lightning Address.",
    )
    forward_to: Optional[str] = Field(
        default=None,
        description="Target Lightning Address when routing_mode is forward.",
    )
    min_sats: Optional[int] = Field(
        default=None,
        ge=1,
        description="Override for minimum sats (falls back to global minimum when omitted).",
    )
    max_sats: Optional[int] = Field(
        default=None,
        ge=1,
        description="Upper bound for sats (cannot be lower than min_sats).",
    )
    metadata_description: Optional[str] = Field(
        default=None,
        max_length=MAX_TEMPLATE_CHARS,
        description="Template used for LNURL metadata description.",
    )
    success_message: Optional[str] = Field(
        default=None,
        max_length=MAX_TEMPLATE_CHARS,
        description="Template used for the successAction message.",
    )
    webhook_urls: Optional[List[str]] = Field(
        default=None,
        description="List of HTTP(S) endpoints that receive a JSON payload when invoices settle for this handle (including +tags).",
    )
    legacy_webhook_url: Optional[str] = Field(
        default=None,
        alias="webhook_url",
        exclude=True,
        description="Deprecated single webhook field kept for backward compatibility.",
    )

    @field_validator("local_part")
    @classmethod
    def _validate_local_part(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("local-part is required")
        if "@" in normalized or " " in normalized:
            raise ValueError("Do not include '@' or spaces in the local-part")
        if "+" in normalized:
            raise ValueError("Overrides cannot include tags (+) in the local part")
        if not LOCAL_PART_PATTERN.fullmatch(normalized):
            raise ValueError("local-part may include lowercase letters, numbers, dot, dash, or underscore")
        return normalized

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        normalized = value.strip().lower().rstrip(".")
        if not normalized:
            raise ValueError("domain is required")
        if "://" in normalized:
            raise ValueError("Do not include protocol in domain")
        if not DOMAIN_PATTERN.fullmatch(normalized):
            raise ValueError("domain may include lowercase letters, numbers, dashes, and dots")
        return normalized

    @field_validator("forward_to", mode="before")
    @classmethod
    def _trim_forward_to(cls, value: Optional[Any]) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("forward_to must be a Lightning Address string")
        trimmed = value.strip()
        return trimmed or None

    @field_validator("metadata_description", "success_message", mode="before")
    @classmethod
    def _trim_templates(cls, value: Optional[str]) -> Optional[str]:
        return _clean_template(value)

    @field_validator("webhook_urls", mode="before")
    @classmethod
    def _normalize_webhook_list(cls, value: Optional[Any]) -> Optional[List[str]]:
        if value is None:
            return []
        if isinstance(value, str):
            candidates = [value]
        elif isinstance(value, (list, tuple, set)):
            candidates = list(value)
        else:
            raise ValueError("webhook_urls must be a list of strings")
        normalized: List[str] = []
        for entry in candidates:
            if not isinstance(entry, str):
                raise ValueError("Webhook URL must be a string")
            parts = [part for part in re.split(r"[\n,]+", entry) if part]
            if not parts:
                parts = [entry]
            for part in parts:
                normalized_url = _normalize_webhook_url(part)
                if normalized_url not in normalized:
                    normalized.append(normalized_url)
        return normalized

    @model_validator(mode="after")
    def _validate_bounds(self) -> "LNAddressPayload":
        min_sats = self.min_sats
        max_sats = self.max_sats
        if min_sats is not None and max_sats is not None and max_sats < min_sats:
            raise ValueError("max_sats cannot be smaller than min_sats")
        if self.routing_mode == "forward" and not self.forward_to:
            raise ValueError("forward_to is required for forwarded addresses")
        urls = list(dict.fromkeys(self.webhook_urls or []))
        if self.legacy_webhook_url:
            legacy_url = _normalize_webhook_url(self.legacy_webhook_url)
            if legacy_url not in urls:
                urls.append(legacy_url)
        self.webhook_urls = urls
        return self


class ForwardingValidationPayload(BaseModel):
    forward_to: str = Field(..., description="Lightning Address to validate as a forwarding target.")


def _serialize(record: Dict[str, Any]) -> Dict[str, Any]:
    local_part = record["local_part"]
    domain = record["domain"]
    identifier = f"{local_part}@{domain}"
    base, _, tag = local_part.partition("+")
    webhook_urls = record.get("webhook_urls") or []
    return {
        "id": record["id"],
        "local_part": local_part,
        "domain": domain,
        "identifier": identifier,
        "routing_mode": record.get("routing_mode") or "local",
        "forward_to": record.get("forward_to"),
        "base_local_part": base,
        "tag": tag or None,
        "min_sats": record.get("min_sendable_sat"),
        "max_sats": record.get("max_sendable_sat"),
        "metadata_description": record.get("metadata_description"),
        "success_message": record.get("success_message"),
        "webhook_urls": webhook_urls,
        "webhook_url": webhook_urls[0] if webhook_urls else None,
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
    }


async def _resolve_forwarding_target(payload: LNAddressPayload) -> Optional[ForwardingTarget]:
    if payload.routing_mode != "forward":
        return None
    try:
        target = await fetch_forwarding_discovery(payload.forward_to or "")
    except ForwardingTargetError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    local_identifier = f"{payload.local_part}@{payload.domain}"
    if target.address == local_identifier:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Forwarding target cannot be the same as the local address",
        )
    return target


def _forwarding_validation_response(target: ForwardingTarget) -> Dict[str, Any]:
    payload = target.payload
    return {
        "valid": True,
        "forward_to": target.address,
        "callback": payload.get("callback"),
        "min_sendable_msat": payload.get("minSendable"),
        "max_sendable_msat": payload.get("maxSendable"),
        "metadata": payload.get("metadata"),
    }


@api_router.get("")
async def list_addresses(store: LNAddressStore = Depends(get_ln_address_store_dep)) -> Dict[str, Any]:
    items = await store.list_addresses()
    return {"items": [_serialize(item) for item in items]}


@api_router.post("/forwarding/validate")
async def validate_forwarding_address(payload: ForwardingValidationPayload) -> Dict[str, Any]:
    try:
        target = await fetch_forwarding_discovery(payload.forward_to)
    except ForwardingTargetError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return _forwarding_validation_response(target)


@api_router.post("", status_code=status.HTTP_201_CREATED)
async def create_address(
    payload: LNAddressPayload,
    store: LNAddressStore = Depends(get_ln_address_store_dep),
) -> Dict[str, Any]:
    forwarding_target = await _resolve_forwarding_target(payload)
    routing_mode = "forward" if forwarding_target else "local"
    try:
        created = await store.add_address(
            local_part=payload.local_part,
            domain=payload.domain,
            routing_mode=routing_mode,
            forward_to=forwarding_target.address if forwarding_target else None,
            min_sendable_sat=payload.min_sats,
            max_sendable_sat=payload.max_sats,
            metadata_description=payload.metadata_description,
            success_message=payload.success_message,
            webhook_urls=payload.webhook_urls,
        )
    except AddressConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return {"item": _serialize(created)}


@api_router.put("/{address_id}")
async def update_address(
    address_id: str,
    payload: LNAddressPayload,
    store: LNAddressStore = Depends(get_ln_address_store_dep),
) -> Dict[str, Any]:
    forwarding_target = await _resolve_forwarding_target(payload)
    routing_mode = "forward" if forwarding_target else "local"
    try:
        updated = await store.update_address(
            address_id,
            local_part=payload.local_part,
            domain=payload.domain,
            routing_mode=routing_mode,
            forward_to=forwarding_target.address if forwarding_target else None,
            min_sendable_sat=payload.min_sats,
            max_sendable_sat=payload.max_sats,
            metadata_description=payload.metadata_description,
            success_message=payload.success_message,
            webhook_urls=payload.webhook_urls,
        )
    except AddressNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Address not found")
    except AddressConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"item": _serialize(updated)}


@api_router.delete("/{address_id}")
async def delete_address(
    address_id: str,
    store: LNAddressStore = Depends(get_ln_address_store_dep),
) -> Dict[str, str]:
    try:
        await store.delete_address(address_id)
    except AddressNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Address not found")
    return {"status": "deleted"}
