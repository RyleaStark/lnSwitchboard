"""Helpers for dispatching per-address webhooks."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

import httpx

from .ln_address_store import AddressNotFoundError, LNAddressStore
from .log_storage import InvoiceEvent, RequestLogStorage
from .nostr_zaps import NostrZapPublisher
from .outbound_security import OutboundHTTPStatusError, ensure_public_endpoint, post_to_pinned_endpoint
from .version import get_version

Sender = Callable[[str, Dict[str, Any], Dict[str, str]], Awaitable[None]]


def _split_username_tag(username: str) -> Tuple[str, Optional[str]]:
    if "+" not in username:
        return username, None
    base, _, tag = username.partition("+")
    if not base or not tag:
        return username, None
    return base, tag


class WebhookDispatcher:
    """Dispatches webhook payloads when invoices settle."""

    def __init__(
        self,
        *,
        address_store: LNAddressStore,
        timeout_seconds: float = 5.0,
        max_retries: int = 5,
        retry_window_seconds: float = 600.0,
        sender: Optional[Sender] = None,
        delivery_storage: Optional[RequestLogStorage] = None,
        zap_publisher: Optional[NostrZapPublisher] = None,
        allow_private_webhooks: bool = False,
    ) -> None:
        self._address_store = address_store
        self._timeout = max(1.0, float(timeout_seconds))
        self._sender = sender
        self._user_agent = f"lnSwitchboard/{get_version()}"
        self._version = get_version()
        self._logger = logging.getLogger("lnswitchboard.webhooks")
        self._delivery_storage = delivery_storage
        self._zap_publisher = zap_publisher
        self._allow_private_webhooks = allow_private_webhooks
        self._max_retries = max(0, int(max_retries))
        self._max_attempts = 1 + self._max_retries
        if self._max_retries > 0:
            interval = float(retry_window_seconds) / float(self._max_retries)
            self._retry_interval = max(0.01, interval)
        else:
            self._retry_interval = 0.0
        self._retry_tasks: Set[asyncio.Task[Any]] = set()

    async def dispatch_payment_settled(
        self,
        *,
        event: InvoiceEvent,
        details: Dict[str, Any],
        settled_at: Optional[datetime],
    ) -> bool:
        address_meta = details.get("address_override") if isinstance(details, dict) else None
        if not isinstance(address_meta, dict):
            return False
        address_id = address_meta.get("id")
        if not address_id:
            return False
        try:
            record = await self._address_store.get_address(address_id)
        except AddressNotFoundError:
            return False
        endpoints = self._endpoints_for_record(record)

        payload = self._build_payload(event=event, details=details, address=record, settled_at=settled_at)
        delivered = False
        for endpoint in endpoints:
            webhook_url = endpoint["url"]
            if not self._matches_filters(endpoint.get("filters"), payload):
                if self._delivery_storage is not None:
                    await self._delivery_storage.create_delivery(
                        kind="http.webhook",
                        target=webhook_url,
                        event="payment.settled",
                        payload=payload,
                        headers={},
                        address_id=record.get("id"),
                        invoice_event_id=event.id,
                        request_log_id=event.request_log_id,
                        status="skipped",
                        delivery_key=f"http:{event.id}:{self._endpoint_identifier(endpoint)}:skipped",
                    )
                continue
            delivery_id = await self._create_delivery(
                endpoint=endpoint,
                payload=payload,
                event=event,
                address_id=record.get("id"),
            )
            headers = self._build_headers(
                address_id=record.get("id"),
                delivery_id=delivery_id,
                endpoint=endpoint,
                payload=payload,
            )
            attempt_success = await self._attempt_delivery(
                url=webhook_url,
                payload=payload,
                headers=headers,
                attempt=1,
                delivery_id=delivery_id,
            )
            delivered = delivered or attempt_success
        if self._zap_publisher is not None:
            try:
                delivered = await self._zap_publisher.publish_for_settlement(
                    event=event,
                    details=details,
                    settled_at_ts=int((settled_at or datetime.now(tz=timezone.utc)).timestamp()),
                ) or delivered
            except Exception as exc:  # pragma: no cover - runtime relay path
                self._logger.warning("Zap receipt publish failed for invoice event %s: %s", event.id, exc)
        return delivered

    async def dispatch_test(
        self,
        *,
        url: str,
        payload: Optional[Dict[str, Any]] = None,
        secret: Optional[str] = None,
    ) -> bool:
        endpoint = {
            "id": hashlib.sha256(url.encode("utf-8")).hexdigest()[:16],
            "url": url,
            "secret": secret,
            "filters": {},
        }
        test_payload = payload or {
            "event": "payment.settled",
            "source": "lnswitchboard",
            "version": self._version,
            "ln_address": "test@example.com",
            "local_part": "test",
            "username": "test",
            "tag": None,
            "domain": "example.com",
            "amount_msat": 1000,
            "amount_sat": 1,
            "payment_hash": "00" * 32,
            "payment_request": "lnbc1test",
            "settled_at": datetime.now(tz=timezone.utc).isoformat(),
            "invoice_event_id": None,
            "request_log_id": None,
        }
        delivery_id = 0
        if self._delivery_storage is not None:
            delivery_id = await self._delivery_storage.create_delivery(
                kind="http.webhook",
                target=url,
                event="payment.settled",
                payload=test_payload,
                status="pending",
            )
        headers = self._build_headers(address_id=None, delivery_id=delivery_id, endpoint=endpoint, payload=test_payload)
        return await self._attempt_delivery(
            url=url,
            payload=test_payload,
            headers=headers,
            attempt=1,
            delivery_id=delivery_id,
        )

    async def replay_delivery(self, delivery: Dict[str, Any]) -> bool:
        payload = delivery.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("Delivery payload is unavailable")
        endpoint = await self._resolve_delivery_endpoint(delivery)
        if endpoint is None:
            raise ValueError("Configured webhook endpoint is unavailable")
        delivery_id = int(delivery["id"])
        headers = self._build_headers(
            address_id=str(delivery.get("address_id") or "") or None,
            delivery_id=delivery_id,
            endpoint=endpoint,
            payload=payload,
        )
        return await self._attempt_delivery(
            url=str(endpoint["url"]),
            payload=payload,
            headers=headers,
            attempt=1,
            delivery_id=delivery_id,
        )

    async def resume_pending_retries(self, *, limit: int = 100) -> int:
        if self._delivery_storage is None:
            return 0
        deliveries = await self._delivery_storage.list_retryable_http_deliveries(limit=limit)
        resumed = 0
        for delivery in deliveries:
            payload = delivery.get("payload")
            delivery_id = int(delivery.get("id") or 0)
            endpoint = await self._resolve_delivery_endpoint(delivery)
            if endpoint is None or not isinstance(payload, dict) or delivery_id <= 0:
                if delivery_id > 0:
                    await self._delivery_storage.update_delivery_status(
                        delivery_id=delivery_id,
                        status="failed",
                    )
                continue
            attempts = delivery.get("attempts") if isinstance(delivery.get("attempts"), list) else []
            last_attempt = 0
            for attempt in attempts:
                if isinstance(attempt, dict):
                    last_attempt = max(last_attempt, int(attempt.get("attempt_number") or 0))
            next_attempt = last_attempt + 1
            if next_attempt > self._max_attempts:
                await self._delivery_storage.update_delivery_status(delivery_id=delivery_id, status="failed")
                continue
            headers = self._build_headers(
                address_id=str(delivery.get("address_id") or "") or None,
                delivery_id=delivery_id,
                endpoint=endpoint,
                payload=payload,
            )
            self._schedule_retry(
                url=str(endpoint["url"]),
                payload=payload,
                headers=headers,
                next_attempt=next_attempt,
                delivery_id=delivery_id,
                delay_seconds=0.01,
            )
            resumed += 1
        if resumed:
            self._logger.info("Resumed %s pending webhook deliveries", resumed)
        return resumed

    def _endpoints_for_record(self, record: Dict[str, Any]) -> List[Dict[str, Any]]:
        endpoints = [item for item in record.get("webhook_endpoints") or [] if isinstance(item, dict) and item.get("url")]
        if endpoints:
            return endpoints
        return [
            {
                "id": hashlib.sha256(str(url).encode("utf-8")).hexdigest()[:16],
                "url": str(url),
                "label": "",
                "secret": None,
                "filters": {},
            }
            for url in record.get("webhook_urls") or []
        ]

    @staticmethod
    def _endpoint_identifier(endpoint: Dict[str, Any]) -> str:
        identifier = str(endpoint.get("id") or "").strip()
        if identifier:
            return identifier
        return hashlib.sha256(str(endpoint.get("url") or "").encode("utf-8")).hexdigest()[:16]

    async def _resolve_delivery_endpoint(self, delivery: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        address_id = str(delivery.get("address_id") or "").strip()
        delivery_key = str(delivery.get("delivery_key") or "")
        endpoint_id = delivery_key.rpartition(":")[2].strip()
        if not address_id or not endpoint_id:
            return None
        try:
            record = await self._address_store.get_address(address_id)
        except AddressNotFoundError:
            return None
        for endpoint in self._endpoints_for_record(record):
            if self._endpoint_identifier(endpoint) == endpoint_id:
                return endpoint
        return None

    async def _create_delivery(
        self,
        *,
        endpoint: Dict[str, Any],
        payload: Dict[str, Any],
        event: InvoiceEvent,
        address_id: Optional[str],
    ) -> int:
        if self._delivery_storage is None:
            return 0
        return await self._delivery_storage.create_delivery(
            kind="http.webhook",
            target=str(endpoint["url"]),
            event="payment.settled",
            payload=payload,
            headers={},
            address_id=address_id,
            invoice_event_id=event.id,
            request_log_id=event.request_log_id,
            delivery_key=f"http:{event.id}:{self._endpoint_identifier(endpoint)}",
        )

    def _matches_filters(self, filters: Any, payload: Dict[str, Any]) -> bool:
        if not isinstance(filters, dict) or not filters:
            return True
        tag_filter = filters.get("tags")
        if isinstance(tag_filter, str):
            tags = [item.strip() for item in tag_filter.split(",") if item.strip()]
        elif isinstance(tag_filter, list):
            tags = [str(item).strip() for item in tag_filter if str(item).strip()]
        else:
            tags = []
        if tags and str(payload.get("tag") or "") not in tags:
            return False
        min_msat = self._optional_int(filters.get("min_msat"))
        if min_msat is not None and int(payload.get("amount_msat") or 0) < min_msat:
            return False
        max_msat = self._optional_int(filters.get("max_msat"))
        if max_msat is not None and int(payload.get("amount_msat") or 0) > max_msat:
            return False
        route = str(filters.get("route") or "any")
        if route == "forwarded" and not payload.get("forwarded"):
            return False
        if route == "local" and payload.get("forwarded"):
            return False
        if bool(filters.get("require_comment")) and not payload.get("comment"):
            return False
        payer_field = str(filters.get("payer_data_field") or "").strip()
        payer_data = payload.get("payer_data")
        if payer_field and not (isinstance(payer_data, dict) and payer_field in payer_data):
            return False
        return True

    @staticmethod
    def _optional_int(value: Any) -> Optional[int]:
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _build_payload(
        self,
        *,
        event: InvoiceEvent,
        details: Dict[str, Any],
        address: Dict[str, Any],
        settled_at: Optional[datetime],
    ) -> Dict[str, Any]:
        details = details if isinstance(details, dict) else {}
        raw_username = details.get("username_raw") or event.username or address.get("local_part") or ""
        raw_username = str(raw_username)
        base_local, tag = _split_username_tag(raw_username)
        domain = (
            details.get("domain")
            or event.domain
            or address.get("domain")
            or ""
        )
        ln_address = details.get("ln_address")
        if not ln_address and raw_username:
            ln_address = f"{raw_username}@{domain}" if domain else raw_username
        amount_msat = event.amount_msat
        amount_sat = amount_msat // 1000 if isinstance(amount_msat, int) else None
        payment_hash = details.get("payment_hash") or event.payment_hash
        payer_data = details.get("payerdata")
        settled_at_dt = settled_at or datetime.now(tz=timezone.utc)
        payload: Dict[str, Any] = {
            "event": "payment.settled",
            "source": "lnswitchboard",
            "version": self._version,
            "address_id": address.get("id"),
            "ln_address": ln_address,
            "local_part": base_local,
            "username": raw_username,
            "tag": tag,
            "domain": domain,
            "amount_msat": amount_msat,
            "amount_sat": amount_sat,
            "payment_hash": payment_hash,
            "payment_request": event.payment_request,
            "settled_at": settled_at_dt.isoformat(),
            "comment": details.get("comment"),
            "payer_data": payer_data,
            "payer_data_raw": details.get("payerdata_raw"),
            "verify_url": details.get("verify_url") or details.get("verify_url_http"),
            "invoice_event_id": event.id,
            "request_log_id": event.request_log_id,
        }
        if details.get("forwarded") is not None:
            payload["forwarded"] = bool(details.get("forwarded"))
        if details.get("forward_to"):
            payload["forward_to"] = details.get("forward_to")
        if details.get("settlement_source"):
            payload["settlement_source"] = details.get("settlement_source")
        return payload

    def _build_headers(
        self,
        *,
        address_id: Optional[str],
        delivery_id: int,
        endpoint: Dict[str, Any],
        payload: Dict[str, Any],
    ) -> Dict[str, str]:
        headers = {
            "User-Agent": self._user_agent,
            "X-LnSwitchboard-Event": "payment.settled",
            "X-LnSwitchboard-Version": self._version,
        }
        if address_id:
            headers["X-LnSwitchboard-Address-Id"] = address_id
        if delivery_id:
            headers["X-LnSwitchboard-Delivery-Id"] = str(delivery_id)
        secret = endpoint.get("secret")
        if isinstance(secret, str) and secret:
            timestamp = str(int(time.time()))
            body = self._payload_body(payload)
            signature_payload = f"{timestamp}.{delivery_id}.{body}".encode("utf-8")
            signature = hmac.new(secret.encode("utf-8"), signature_payload, hashlib.sha256).hexdigest()
            headers["X-LnSwitchboard-Signature-Timestamp"] = timestamp
            headers["X-LnSwitchboard-Signature"] = f"sha256={signature}"
        return headers

    async def _attempt_delivery(
        self,
        *,
        url: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        attempt: int,
        delivery_id: int = 0,
    ) -> bool:
        started = time.perf_counter()
        try:
            await self._send(url=url, payload=payload, headers=headers)
            latency_ms = int((time.perf_counter() - started) * 1000)
            if self._delivery_storage is not None and delivery_id:
                await self._delivery_storage.update_delivery_status(
                    delivery_id=delivery_id,
                    status="delivered",
                    headers=headers,
                )
                await self._delivery_storage.record_delivery_attempt(
                    delivery_id=delivery_id,
                    success=True,
                    error=None,
                    status_code=200,
                    latency_ms=latency_ms,
                    response_body=None,
                    delivery_status="delivered",
                )
            self._logger.info(
                "Webhook delivered (delivery_id=%s, attempt=%s)",
                delivery_id,
                attempt,
            )
            return True
        except Exception as exc:  # pragma: no cover - network runtime
            latency_ms = int((time.perf_counter() - started) * 1000)
            if isinstance(exc, httpx.HTTPStatusError):
                status_code = exc.response.status_code
                response_body = exc.response.text
            elif isinstance(exc, OutboundHTTPStatusError):
                status_code = exc.status_code
                response_body = exc.response_body
            else:
                status_code = None
                response_body = None
            will_retry = attempt < self._max_attempts and self._max_retries > 0
            delivery_status = "retrying" if will_retry else "failed"
            if self._delivery_storage is not None and delivery_id:
                await self._delivery_storage.update_delivery_status(
                    delivery_id=delivery_id,
                    status=delivery_status,
                    headers=headers,
                )
                await self._delivery_storage.record_delivery_attempt(
                    delivery_id=delivery_id,
                    success=False,
                    error=f"type:{type(exc).__name__}",
                    status_code=status_code,
                    latency_ms=latency_ms,
                    response_body=response_body,
                    delivery_status=delivery_status,
                )
            if attempt >= self._max_attempts or self._max_retries == 0:
                self._logger.warning(
                    "Webhook delivery failed "
                    "(delivery_id=%s, attempt=%s/%s, error_type=%s, status_code=%s)",
                    delivery_id,
                    attempt,
                    self._max_attempts,
                    type(exc).__name__,
                    status_code,
                )
                return False
            self._logger.warning(
                "Webhook delivery failed; retrying "
                "(delivery_id=%s, attempt=%s/%s, error_type=%s, "
                "status_code=%s, retry_delay_seconds=%.2f)",
                delivery_id,
                attempt,
                self._max_attempts,
                type(exc).__name__,
                status_code,
                self._retry_interval,
            )
            self._schedule_retry(url=url, payload=payload, headers=headers, next_attempt=attempt + 1, delivery_id=delivery_id)
            return False

    def _schedule_retry(
        self,
        *,
        url: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        next_attempt: int,
        delivery_id: int,
        delay_seconds: Optional[float] = None,
    ) -> None:
        async def _retry() -> None:
            try:
                delay = self._retry_interval if delay_seconds is None else max(0.0, float(delay_seconds))
                await asyncio.sleep(delay)
                await self._attempt_delivery(
                    url=url,
                    payload=payload,
                    headers=headers,
                    attempt=next_attempt,
                    delivery_id=delivery_id,
                )
            except asyncio.CancelledError:  # pragma: no cover - defensive
                raise
            except Exception as exc:  # pragma: no cover - defensive
                self._logger.warning(
                    "Unhandled error during webhook retry "
                    "(delivery_id=%s, error_type=%s)",
                    delivery_id,
                    type(exc).__name__,
                )

        task = asyncio.create_task(_retry())
        self._retry_tasks.add(task)
        task.add_done_callback(self._retry_tasks.discard)

    async def _send(self, *, url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> None:
        if self._sender is not None:
            await self._sender(url, payload, headers)
            return
        connect_host = await ensure_public_endpoint(
            url,
            allowed_schemes=("http", "https"),
            allow_private=self._allow_private_webhooks,
        )
        await post_to_pinned_endpoint(
            url,
            connect_host=connect_host,
            body=self._payload_body(payload).encode("utf-8"),
            headers={**headers, "Content-Type": "application/json"},
            timeout=self._timeout,
        )

    @staticmethod
    def _payload_body(payload: Dict[str, Any]) -> str:
        return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
