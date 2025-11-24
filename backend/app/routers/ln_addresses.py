"""CRUD endpoints for LNURL address overrides."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator, model_validator

from ..deps import get_ln_address_store_dep
from ..ln_address_store import AddressConflictError, AddressNotFoundError, LNAddressStore


api_router = APIRouter(prefix="/api/lnaddresses", tags=["ln_addresses"])

LOCAL_PART_PATTERN = re.compile(r"^[a-z0-9._-]+$")
DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")
MAX_TEMPLATE_CHARS = 512


def _clean_template(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


class LNAddressPayload(BaseModel):
    local_part: str = Field(
        ...,
        description="local-part used before the '@'. Configure the base handle only (tags like user+vip inherit automatically).",
    )
    domain: str = Field(..., description="Domain that hosts the LNURL endpoint.")
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

    @field_validator("metadata_description", "success_message", mode="before")
    @classmethod
    def _trim_templates(cls, value: Optional[str]) -> Optional[str]:
        return _clean_template(value)

    @model_validator(mode="after")
    def _validate_bounds(self) -> "LNAddressPayload":
        min_sats = self.min_sats
        max_sats = self.max_sats
        if min_sats is not None and max_sats is not None and max_sats < min_sats:
            raise ValueError("max_sats cannot be smaller than min_sats")
        return self


def _serialize(record: Dict[str, Any]) -> Dict[str, Any]:
    local_part = record["local_part"]
    domain = record["domain"]
    identifier = f"{local_part}@{domain}"
    base, _, tag = local_part.partition("+")
    return {
        "id": record["id"],
        "local_part": local_part,
        "domain": domain,
        "identifier": identifier,
        "base_local_part": base,
        "tag": tag or None,
        "min_sats": record.get("min_sendable_sat"),
        "max_sats": record.get("max_sendable_sat"),
        "metadata_description": record.get("metadata_description"),
        "success_message": record.get("success_message"),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
    }


@api_router.get("")
async def list_addresses(store: LNAddressStore = Depends(get_ln_address_store_dep)) -> Dict[str, Any]:
    items = await store.list_addresses()
    return {"items": [_serialize(item) for item in items]}


@api_router.post("", status_code=status.HTTP_201_CREATED)
async def create_address(
    payload: LNAddressPayload,
    store: LNAddressStore = Depends(get_ln_address_store_dep),
) -> Dict[str, Any]:
    try:
        created = await store.add_address(
            local_part=payload.local_part,
            domain=payload.domain,
            min_sendable_sat=payload.min_sats,
            max_sendable_sat=payload.max_sats,
            metadata_description=payload.metadata_description,
            success_message=payload.success_message,
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
    try:
        updated = await store.update_address(
            address_id,
            local_part=payload.local_part,
            domain=payload.domain,
            min_sendable_sat=payload.min_sats,
            max_sendable_sat=payload.max_sats,
            metadata_description=payload.metadata_description,
            success_message=payload.success_message,
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
