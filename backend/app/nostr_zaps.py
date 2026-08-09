"""NIP-57 zap request validation and receipt publishing."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional

from .log_storage import InvoiceEvent, RequestLogStorage
from .nostr_crypto import event_id, first_tag_value, sign_event, verify_event
from .nostr_signer_store import NostrSignerStore
from .outbound_security import ensure_public_endpoint

LOGGER = logging.getLogger("lnswitchboard.zaps")
RelaySender = Callable[[str, Dict[str, Any]], Awaitable[None]]


class ZapRequestError(ValueError):
    """Raised when a NIP-57 zap request cannot be accepted."""


def _tag_values(tags: Iterable[Any], name: str) -> List[str]:
    values: List[str] = []
    for tag in tags:
        if not isinstance(tag, list) or len(tag) < 2:
            continue
        if tag[0] == name and isinstance(tag[1], str):
            values.append(tag[1])
    return values


def _normalize_hex(value: str, label: str) -> str:
    candidate = value.strip().lower()
    if len(candidate) != 64 or any(ch not in "0123456789abcdef" for ch in candidate):
        raise ZapRequestError(f"{label} must be a 32-byte hex value")
    return candidate


def _load_event(raw: str) -> Dict[str, Any]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ZapRequestError("Invalid nostr zap request JSON") from exc
    if not isinstance(payload, dict):
        raise ZapRequestError("nostr zap request must be a JSON object")
    return payload


def _relay_values(tags: Iterable[Any]) -> List[str]:
    relays: List[str] = []
    for tag in tags:
        if not isinstance(tag, list) or len(tag) < 2 or tag[0] != "relays":
            continue
        for value in tag[1:]:
            if not isinstance(value, str):
                continue
            relay = value.strip()
            if relay and relay.startswith(("ws://", "wss://")) and relay not in relays:
                relays.append(relay)
    return relays[:16]


def validate_zap_request(
    *,
    raw: str,
    amount_msat: int,
    recipient_pubkey: str,
    callback_lnurl: str,
) -> Dict[str, Any]:
    event = _load_event(raw)
    if event.get("kind") != 9734:
        raise ZapRequestError("nostr zap request must be kind 9734")
    if not isinstance(event.get("content"), str):
        raise ZapRequestError("nostr zap request content must be a string")
    tags = event.get("tags")
    if not isinstance(tags, list):
        raise ZapRequestError("nostr zap request tags must be a list")
    p_values = [_normalize_hex(value, "p tag") for value in _tag_values(tags, "p")]
    if len(p_values) != 1:
        raise ZapRequestError("nostr zap request must include exactly one p tag")
    if p_values[0] != recipient_pubkey.lower():
        raise ZapRequestError("nostr zap request recipient does not match this address")
    amount_values = _tag_values(tags, "amount")
    if amount_values:
        try:
            requested_amount = int(amount_values[0])
        except ValueError as exc:
            raise ZapRequestError("nostr zap request amount tag must be an integer") from exc
        if requested_amount != amount_msat:
            raise ZapRequestError("nostr zap request amount does not match requested invoice amount")
    lnurl_values = _tag_values(tags, "lnurl")
    if lnurl_values and lnurl_values[0] != callback_lnurl:
        raise ZapRequestError("nostr zap request lnurl tag does not match this callback")
    relays = _relay_values(tags)
    if not relays:
        raise ZapRequestError("nostr zap request must include at least one relay")
    if not verify_event(event):
        raise ZapRequestError("nostr zap request signature is invalid")
    return {
        "event": event,
        "event_id": event_id(event),
        "pubkey": str(event.get("pubkey", "")).lower(),
        "recipient_pubkey": p_values[0],
        "relays": relays,
        "raw": raw,
    }


def build_zap_receipt_event(
    *,
    private_key_hex: str,
    zap_request: Dict[str, Any],
    payment_request: str,
    preimage: Optional[str],
    settled_at: Optional[int] = None,
) -> Dict[str, Any]:
    request_event = zap_request["event"]
    request_tags = request_event.get("tags") if isinstance(request_event.get("tags"), list) else []
    tags: List[List[str]] = []
    p_value = first_tag_value(request_tags, "p")
    if p_value:
        tags.append(["p", p_value])
    tags.append(["P", str(request_event.get("pubkey", ""))])
    for tag_name in ("e", "a"):
        value = first_tag_value(request_tags, tag_name)
        if value:
            tags.append([tag_name, value])
    tags.append(["bolt11", payment_request])
    tags.append(["description", zap_request["raw"]])
    if preimage:
        tags.append(["preimage", preimage])
    event = {
        "kind": 9735,
        "created_at": int(settled_at or time.time()),
        "tags": tags,
        "content": "",
    }
    return sign_event(event, private_key_hex)


class NostrZapPublisher:
    """Publishes zap receipts to relays and records relay delivery attempts."""

    def __init__(
        self,
        *,
        signer_store: NostrSignerStore,
        storage: Optional[RequestLogStorage] = None,
        sender: Optional[RelaySender] = None,
        allow_private_relays: bool = False,
    ) -> None:
        self._signer_store = signer_store
        self._storage = storage
        self._sender = sender
        self._allow_private_relays = allow_private_relays

    async def publish_for_settlement(
        self,
        *,
        event: InvoiceEvent,
        details: Dict[str, Any],
        settled_at_ts: Optional[int] = None,
    ) -> bool:
        zap = details.get("zap_request") if isinstance(details, dict) else None
        if not isinstance(zap, dict) or not zap.get("raw"):
            return False
        private_key = await self._signer_store.get_private_key()
        invoice_details = details.get("invoice") if isinstance(details.get("invoice"), dict) else {}
        preimage = invoice_details.get("r_preimage")
        receipt = build_zap_receipt_event(
            private_key_hex=private_key,
            zap_request=zap,
            payment_request=event.payment_request or str(invoice_details.get("payment_request") or ""),
            preimage=preimage if isinstance(preimage, str) and preimage else None,
            settled_at=settled_at_ts,
        )
        details["zap_receipt"] = {"id": receipt["id"], "pubkey": receipt["pubkey"]}
        relays = [relay for relay in zap.get("relays", []) if isinstance(relay, str)]
        delivered = False
        for relay_url in relays:
            delivered = await self._publish_one(
                relay_url=relay_url,
                receipt=receipt,
                invoice_event=event,
            ) or delivered
        return delivered

    async def _publish_one(
        self,
        *,
        relay_url: str,
        receipt: Dict[str, Any],
        invoice_event: InvoiceEvent,
    ) -> bool:
        delivery_id: Optional[int] = None
        if self._storage is not None:
            delivery_id = await self._storage.create_delivery(
                kind="nostr.relay",
                target=relay_url,
                event="zap.receipt",
                payload=receipt,
                invoice_event_id=invoice_event.id,
                status="pending",
            )
        try:
            await self._send(relay_url, receipt)
        except Exception as exc:  # pragma: no cover - runtime network path
            LOGGER.warning(
                "Zap receipt publish failed (delivery_id=%s, error_type=%s)",
                delivery_id,
                type(exc).__name__,
            )
            if self._storage is not None and delivery_id is not None:
                await self._storage.record_delivery_attempt(
                    delivery_id=delivery_id,
                    success=False,
                    error=f"type:{type(exc).__name__}",
                    status_code=None,
                    latency_ms=None,
                    response_body=None,
                )
            return False
        if self._storage is not None and delivery_id is not None:
            await self._storage.record_delivery_attempt(
                delivery_id=delivery_id,
                success=True,
                error=None,
                status_code=None,
                latency_ms=None,
                response_body=None,
            )
        return True

    async def _send(self, relay_url: str, receipt: Dict[str, Any]) -> None:
        if self._sender is not None:
            await self._sender(relay_url, receipt)
            return
        connect_host = await ensure_public_endpoint(
            relay_url,
            allowed_schemes=("ws", "wss"),
            allow_private=self._allow_private_relays,
        )
        import websockets

        async with websockets.connect(
            relay_url,
            host=connect_host,
            proxy=None,
            open_timeout=5,
            close_timeout=2,
        ) as websocket:
            await websocket.send(json.dumps(["EVENT", receipt], separators=(",", ":"), ensure_ascii=False))
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=5)
            except asyncio.TimeoutError as exc:
                raise RuntimeError("relay did not acknowledge the event") from exc
            try:
                payload = json.loads(response)
            except json.JSONDecodeError as exc:
                raise RuntimeError("relay returned an invalid acknowledgement") from exc
            if not isinstance(payload, list) or len(payload) < 4 or payload[0] != "OK":
                raise RuntimeError("relay did not acknowledge the event")
            if payload[1] != receipt.get("id"):
                raise RuntimeError("relay acknowledged a different event")
            if payload[2] is not True:
                raise RuntimeError(str(payload[3]) or "relay rejected the event")
