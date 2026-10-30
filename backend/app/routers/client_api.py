"""Private-listener-only scoped integration API; never mounted on public_app."""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
import re
from uuid import uuid4
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..client_store import ClientStore, digest
from ..config import get_settings
from ..deps import (get_connection_secret_store_dep, get_ln_address_store_dep,
                    get_ln_client_dep, get_log_storage_dep)
from ..ln_client import LNClient
from ..log_storage import RequestLogStorage
from ..connection_secret_store import ConnectionSecretStore
from ..ln_address_store import AddressConflictError, AddressNotFoundError, LNAddressStore

router = APIRouter(tags=["private_clients"])
client_router = APIRouter(tags=["private_clients"])
Scope = Literal["addresses:create", "addresses:read_own", "invoices:create"]


class StrictPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ClientPayload(StrictPayload):
    domain: str = Field(min_length=1, max_length=253)
    webhook_url: str = Field(min_length=1, max_length=2048)
    webhook_secret: str = Field(min_length=32, max_length=256)
    scopes: list[Scope] = Field(min_length=1, max_length=3)

    @field_validator("domain")
    @classmethod
    def domain_valid(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in value.split(".")
        ):
            raise ValueError("Invalid domain")
        return value

    @field_validator("webhook_url")
    @classmethod
    def webhook_valid(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Invalid bridge URL")
        if parsed.scheme == "http" and not get_settings().allow_private_webhooks:
            raise ValueError("HTTP bridge requires explicit private-webhook setting")
        return value


class AddressPayload(StrictPayload):
    external_user_ref: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


async def store_dep(secrets: ConnectionSecretStore = Depends(get_connection_secret_store_dep)) -> ClientStore:
    return ClientStore(get_settings().data_store_path, secrets)


def require_scope(scope: Scope):
    async def authorize(authorization: str | None = Header(default=None), store: ClientStore = Depends(store_dep)) -> dict:
        if not authorization or not re.fullmatch(r"Bearer lnsc_[A-Za-z0-9_-]{43}", authorization):
            raise HTTPException(401, "Client bearer credential required", headers={"WWW-Authenticate": "Bearer"})
        return store.authenticate(authorization[7:], scope)
    return authorize


def idempotency_key(value: str | None) -> str:
    if value is None or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", value):
        raise HTTPException(400, "Valid Idempotency-Key required")
    return value


def address_result(record: dict) -> dict:
    return {"address_id": record["id"], "ln_address": f'{record["local_part"]}@{record["domain"]}'}


@router.get("/api/client-credentials/status")
async def client_status(request: Request):
    settings = get_settings()
    listener = getattr(request.app.state, "client_listener", None)
    listening = bool(listener and listener[0].started and not listener[1].done())
    return {"enabled": settings.client_api_enabled, "listening": listening,
            "host": settings.client_api_host, "port": settings.client_api_port,
            "allow_private_webhooks": settings.allow_private_webhooks}


@router.post("/api/client-credentials", status_code=201)
async def provision(payload: ClientPayload, store: ClientStore = Depends(store_dep)):
    return store.provision(**payload.model_dump())


@router.get("/api/client-credentials")
async def list_clients(store: ClientStore = Depends(store_dep)):
    return {"clients": store.list_clients()}


@router.delete("/api/client-credentials/{client_id}", status_code=204)
async def revoke(client_id: str, store: ClientStore = Depends(store_dep)):
    store.revoke(client_id)
    return Response(status_code=204)


@client_router.post("/api/client/v1/addresses", status_code=201)
async def create_address(payload: AddressPayload, client: dict = Depends(require_scope("addresses:create")),
                         key: str | None = Header(default=None, alias="Idempotency-Key"),
                         store: ClientStore = Depends(store_dep),
                         addresses: LNAddressStore = Depends(get_ln_address_store_dep)):
    key = idempotency_key(key)
    request = store.claim(client["id"], key, "address", payload.model_dump(),
                          digest(payload.external_user_ref), resource_id=str(uuid4()))
    if request["result"]:
        return json.loads(request["result"])
    try:
        owned = store.reserve_address(client, payload.external_user_ref, request["resource_id"])
        try:
            record = await addresses.get_address(owned["id"])
        except AddressNotFoundError:
            bridge = store.secrets.get(f'api-client:{client["id"]}')
            if bridge is None:
                raise HTTPException(503, "Client bridge unavailable")
            try:
                record = await addresses.add_address(
                    record_id=owned["id"], local_part=owned["local_part"], domain=owned["domain"],
                    min_sendable_sat=None, max_sendable_sat=None, metadata_description=None,
                    success_message=None, webhook_urls=[], webhook_endpoints=[{
                        "url": bridge["webhook_url"], "secret": bridge["webhook_secret"],
                    }],
                )
            except AddressConflictError:
                raise HTTPException(409, "Address allocation conflict") from None
        result = address_result(record)
        store.finish(request, result)
        return result
    finally:
        store.release(request)


@client_router.get("/api/client/v1/addresses/{address_id}")
async def read_address(address_id: str, client: dict = Depends(require_scope("addresses:read_own")),
                       store: ClientStore = Depends(store_dep),
                       addresses: LNAddressStore = Depends(get_ln_address_store_dep)):
    store.own_address(client["id"], address_id)
    try:
        return address_result(await addresses.get_address(address_id))
    except AddressNotFoundError:
        raise HTTPException(404, "Not Found") from None


class InvoicePayload(StrictPayload):
    quote_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    amount_msat: int = Field(ge=1, le=9007199254740991)
    expiry_days: Literal[14, 30]

    @field_validator("expiry_days", mode="before")
    @classmethod
    def integer_days(cls, value):
        if type(value) is not int:
            raise ValueError("Integer expiry required")
        return value


@client_router.post("/api/client/v1/addresses/{address_id}/invoices", status_code=201)
async def create_invoice(address_id: str, payload: InvoicePayload,
                         client: dict = Depends(require_scope("invoices:create")),
                         key: str | None = Header(default=None, alias="Idempotency-Key"),
                         store: ClientStore = Depends(store_dep),
                         addresses: LNAddressStore = Depends(get_ln_address_store_dep),
                         lnd: LNClient = Depends(get_ln_client_dep),
                         logs: RequestLogStorage = Depends(get_log_storage_dep)):
    store.own_address(client["id"], address_id)
    try:
        address = await addresses.get_address(address_id)
    except AddressNotFoundError:
        raise HTTPException(404, "Not Found") from None
    if address["domain"] != client["domain"] or address["routing_mode"] != "local":
        raise HTTPException(409, "Address routing changed")
    settings = get_settings()
    minimum = max(address.get("min_sendable_sat") or settings.min_sendable_sat, settings.min_sendable_sat) * 1000
    maximum = min(address.get("max_sendable_sat") or settings.max_sendable_sat, settings.max_sendable_sat) * 1000
    if not minimum <= payload.amount_msat <= maximum:
        raise HTTPException(422, "Invoice amount outside configured limits")
    body = {**payload.model_dump(), "address_id": address_id}
    request = store.claim(client["id"], idempotency_key(key), "invoice", body,
                          digest(payload.quote_id), resource_id=address_id, invoice=True)
    if request["result"]:
        return json.loads(request["result"])
    try:
        payment_hash = request["payment_hash"]
        event = await logs.get_invoice_event_by_hash(payment_hash)
        binding = {"version": 1, "client_id": client["id"], "address_id": address_id,
                   "quote_id": payload.quote_id, "creation_pending": True}
        if event is None:
            await logs.log_invoice_event(
                username=address["local_part"], domain=address["domain"], amount_msat=payload.amount_msat,
                payment_hash=payment_hash, details={"address_override": {"id": address_id},
                    "client_invoice": binding, "invoice": {"payment_hash": payment_hash}},
            )
            event = await logs.get_invoice_event_by_hash(payment_hash)
        if event is None or event.amount_msat != payload.amount_msat or not isinstance(event.details, dict):
            raise HTTPException(503, "Invoice tracking unavailable")
        saved = event.details.get("client_invoice", {})
        if any(saved.get(k) != binding[k] for k in ("version", "client_id", "address_id", "quote_id")):
            raise HTTPException(409, "Invoice binding conflict")
        try:
            snapshot = await asyncio.wait_for(lnd.lookup_invoice(bytes.fromhex(payment_hash)), timeout=20)
        except LookupError:
            private = store.secrets.get(f'api-invoice:{request["id"]}')
            if private is None:
                raise HTTPException(503, "Invoice recovery material unavailable")
            preimage = bytes.fromhex(private["preimage"])
            if len(preimage) != 32 or hashlib.sha256(preimage).hexdigest() != payment_hash:
                raise HTTPException(503, "Invoice recovery material mismatch")
            store.require_active(client["id"])
            # One fixed preimage/hash for every attempt, even if a prior RPC
            # succeeded but its response was lost. LND rejects duplicate hashes.
            await asyncio.wait_for(lnd.create_invoice(
                amount_msat=payload.amount_msat, memo="lnSwitchboard client invoice",
                expiry_seconds=payload.expiry_days * 86400, r_preimage=preimage,
            ), timeout=20)
            snapshot = await asyncio.wait_for(lnd.lookup_invoice(bytes.fromhex(payment_hash)), timeout=20)
        created = snapshot.get("creation_date")
        expiry = snapshot.get("expiry")
        returned_hash = snapshot.get("r_hash")
        if isinstance(returned_hash, bytes):
            returned_hash = returned_hash.hex()
        bolt11 = snapshot.get("payment_request")
        if (returned_hash != payment_hash or type(created) is not int or not 0 < created < 253402300799
                or type(expiry) is not int or expiry != payload.expiry_days * 86400
                or created + expiry > 253402300799 or not isinstance(bolt11, str) or not bolt11):
            raise HTTPException(503, "Authoritative invoice details unavailable")
        if snapshot.get("state") == "CANCELED":
            raise HTTPException(409, "Invoice was canceled; use a new quote")
        result = {"address_id": address_id, "quote_id": payload.quote_id, "amount_msat": payload.amount_msat,
                  "payment_hash": payment_hash, "bolt11": bolt11,
                  "created_at": created, "expires_at": created + expiry}
        store.confirm_invoice(payment_hash, bolt11, datetime.fromtimestamp(created + expiry, timezone.utc).isoformat())
        store.finish(request, result)
        store.require_active(client["id"])
        return result
    except HTTPException:
        raise
    except Exception:
        # Provider/network errors must not reflect RPC arguments or credentials.
        raise HTTPException(503, "Invoice outcome unresolved; retry the same idempotency key") from None
    finally:
        store.release(request)
