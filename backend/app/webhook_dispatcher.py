"""Helpers for dispatching per-address webhooks."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Awaitable, Callable, Dict, Optional, Set, Tuple

import httpx

from .ln_address_store import AddressNotFoundError, LNAddressStore
from .log_storage import InvoiceEvent
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
    ) -> None:
        self._address_store = address_store
        self._timeout = max(1.0, float(timeout_seconds))
        self._sender = sender
        self._user_agent = f"lnSwitchboard/{get_version()}"
        self._version = get_version()
        self._logger = logging.getLogger("lnswitchboard.webhooks")
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
        webhook_urls = record.get("webhook_urls") or []
        if not webhook_urls:
            return False

        payload = self._build_payload(event=event, details=details, address=record, settled_at=settled_at)
        headers = self._build_headers(address_id=record.get("id"))
        delivered = False
        for webhook_url in webhook_urls:
            attempt_success = await self._attempt_delivery(
                url=webhook_url,
                payload=payload,
                headers=headers,
                attempt=1,
            )
            delivered = delivered or attempt_success
        return delivered

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
        return payload

    def _build_headers(self, *, address_id: Optional[str]) -> Dict[str, str]:
        headers = {
            "User-Agent": self._user_agent,
            "X-LnSwitchboard-Event": "payment.settled",
            "X-LnSwitchboard-Version": self._version,
        }
        if address_id:
            headers["X-LnSwitchboard-Address-Id"] = address_id
        return headers

    async def _attempt_delivery(
        self,
        *,
        url: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        attempt: int,
    ) -> bool:
        try:
            await self._send(url=url, payload=payload, headers=headers)
            if attempt == 1:
                self._logger.info("Webhook delivered to %s", url)
            else:
                self._logger.info("Webhook delivered to %s on attempt %s", url, attempt)
            return True
        except Exception as exc:  # pragma: no cover - network runtime
            if attempt >= self._max_attempts or self._max_retries == 0:
                self._logger.warning("Webhook delivery failed for %s after %s attempts: %s", url, attempt, exc)
                return False
            self._logger.warning(
                "Webhook delivery failed for %s (attempt %s/%s): %s; retrying in %.2fs",
                url,
                attempt,
                self._max_attempts,
                exc,
                self._retry_interval,
            )
            self._schedule_retry(url=url, payload=payload, headers=headers, next_attempt=attempt + 1)
            return False

    def _schedule_retry(
        self,
        *,
        url: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        next_attempt: int,
    ) -> None:
        async def _retry() -> None:
            try:
                await asyncio.sleep(self._retry_interval)
                await self._attempt_delivery(
                    url=url,
                    payload=payload,
                    headers=headers,
                    attempt=next_attempt,
                )
            except asyncio.CancelledError:  # pragma: no cover - defensive
                raise
            except Exception as exc:  # pragma: no cover - defensive
                self._logger.warning("Unhandled error during webhook retry for %s: %s", url, exc)

        task = asyncio.create_task(_retry())
        self._retry_tasks.add(task)
        task.add_done_callback(self._retry_tasks.discard)

    async def _send(self, *, url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> None:
        if self._sender is not None:
            await self._sender(url, payload, headers)
            return
        timeout = httpx.Timeout(self._timeout)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
