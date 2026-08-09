"""Background worker and helpers for refreshing invoice statuses."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .ln_client import LNClient
from .lnurl_forwarding import fetch_forwarding_verify
from .log_storage import InvoiceEvent, RequestLogStorage
from .webhook_dispatcher import WebhookDispatcher

LOGGER = logging.getLogger("lnswitchboard.invoice_worker")


def _parse_iso8601(value: Optional[str]) -> Optional[datetime]:
    if not value:
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


def _derive_expires_at(snapshot: Dict[str, Any]) -> Optional[datetime]:
    expires_at = snapshot.get("expires_at")
    if isinstance(expires_at, str):
        parsed = _parse_iso8601(expires_at)
        if parsed:
            return parsed
    creation_date = snapshot.get("creation_date")
    expiry = snapshot.get("expiry")
    try:
        if creation_date is not None and expiry is not None:
            creation_ts = int(creation_date)
            expiry_seconds = int(expiry)
            return datetime.fromtimestamp(creation_ts + expiry_seconds, tz=timezone.utc)
    except (TypeError, ValueError):
        return None
    return None


def _merge_invoice_snapshot(
    details: Dict[str, Any],
    snapshot: Dict[str, Any],
    *,
    settled: bool,
    expired: bool,
) -> Dict[str, Any]:
    invoice_details = details.get("invoice")
    if not isinstance(invoice_details, dict):
        invoice_details = {}
        details["invoice"] = invoice_details
    invoice_details["settled"] = settled
    if "state" in snapshot and snapshot["state"] is not None:
        invoice_details["state"] = snapshot["state"]
    if "creation_date" in snapshot and snapshot["creation_date"] is not None:
        invoice_details["creation_date"] = snapshot["creation_date"]
    if "expiry" in snapshot and snapshot["expiry"] is not None:
        invoice_details["expiry"] = snapshot["expiry"]
    if "expires_at" in snapshot and snapshot["expires_at"] is not None:
        invoice_details["expires_at"] = snapshot["expires_at"]
    if "is_expired" in snapshot and snapshot["is_expired"] is not None:
        invoice_details["is_expired"] = snapshot["is_expired"]
    invoice_details["expired"] = expired
    if "payment_request" in snapshot and snapshot["payment_request"]:
        invoice_details.setdefault("payment_request", snapshot["payment_request"])
    if "r_hash" in snapshot and snapshot["r_hash"]:
        payment_hash_value = snapshot["r_hash"]
        if isinstance(payment_hash_value, bytes):
            payment_hash_value = payment_hash_value.hex()
        invoice_details["payment_hash"] = payment_hash_value
    if "r_preimage" in snapshot and snapshot["r_preimage"]:
        preimage_value = snapshot["r_preimage"]
        if isinstance(preimage_value, bytes):
            preimage_value = preimage_value.hex()
        invoice_details["r_preimage"] = preimage_value
    if "htlcs" in snapshot and isinstance(snapshot["htlcs"], list):
        invoice_details["htlcs"] = snapshot["htlcs"]
    invoice_details["last_checked_at"] = datetime.now(tz=timezone.utc).isoformat()
    return details


async def _dispatch_webhook_if_needed(
    dispatcher: Optional[WebhookDispatcher],
    *,
    event: InvoiceEvent,
    details: Dict[str, Any],
    settled_at: Optional[datetime],
) -> None:
    if dispatcher is None:
        return
    try:
        await dispatcher.dispatch_payment_settled(event=event, details=details, settled_at=settled_at)
    except Exception as exc:  # pragma: no cover - defensive logging
        LOGGER.warning(
            "Webhook dispatcher raised for invoice event %s (error_type=%s)",
            event.id,
            type(exc).__name__,
        )


def _is_remote_verify_event(event: InvoiceEvent) -> bool:
    details = event.details if isinstance(event.details, dict) else {}
    return bool(details.get("forwarded")) and details.get("settlement_source") == "remote_verify"


def _interval_for_age(
    *,
    created_at: Optional[str],
    now: datetime,
    quick_window: timedelta,
    mid_window: timedelta,
    quick_interval: timedelta,
    mid_interval: timedelta,
    slow_interval: timedelta,
) -> timedelta:
    created_at_dt = _parse_iso8601(created_at) or now
    age = now - created_at_dt
    if age <= quick_window:
        return quick_interval
    if age <= mid_window:
        return mid_interval
    return slow_interval


async def _refresh_remote_verify_status(
    storage: RequestLogStorage,
    *,
    event: InvoiceEvent,
    now: datetime,
    quick_window: timedelta,
    mid_window: timedelta,
    quick_interval: timedelta,
    mid_interval: timedelta,
    slow_interval: timedelta,
    webhook_dispatcher: Optional[WebhookDispatcher],
    logger: logging.Logger,
) -> int:
    details = event.details if isinstance(event.details, dict) else {}
    verify_url = details.get("verify_url") or details.get("verify_url_http")
    if not isinstance(verify_url, str) or not verify_url.strip():
        await storage.apply_invoice_event_update(
            event=event,
            details=details,
            settled=False,
            expired=True,
            next_check=None,
            expires_at=None,
            interval_seconds=0,
            settled_at=None,
        )
        return 0

    try:
        snapshot = await fetch_forwarding_verify(verify_url)
    except Exception as exc:  # pragma: no cover - network/runtime
        logger.warning(
            "Forwarded invoice verify failed for event %s (error_type=%s)",
            event.id,
            type(exc).__name__,
        )
        await storage.apply_invoice_event_update(
            event=event,
            details=details,
            settled=False,
            expired=False,
            next_check=now + quick_interval,
            expires_at=_parse_iso8601(event.expires_at),
            interval_seconds=int(quick_interval.total_seconds()),
            settled_at=None,
        )
        return 0

    status_value = snapshot.get("status")
    status_text = status_value.upper() if isinstance(status_value, str) else ""
    preimage = snapshot.get("preimage")
    settled = bool(snapshot.get("settled")) or (isinstance(preimage, str) and bool(preimage.strip()))
    expired_flag = status_text == "ERROR"
    expires_at_dt = _parse_iso8601(event.expires_at)
    if not settled and not expired_flag and expires_at_dt is not None:
        expired_flag = now >= expires_at_dt

    invoice_details = details.get("invoice")
    if not isinstance(invoice_details, dict):
        invoice_details = {}
        details["invoice"] = invoice_details
    invoice_details["settled"] = settled
    invoice_details["expired"] = expired_flag
    invoice_details["last_checked_at"] = now.isoformat()
    invoice_details["remote_verify_response"] = snapshot
    if preimage:
        invoice_details["r_preimage"] = preimage
    payment_request = snapshot.get("pr") or snapshot.get("payment_request")
    if payment_request:
        invoice_details.setdefault("payment_request", payment_request)
    details["remote_verify_response"] = snapshot

    interval = _interval_for_age(
        created_at=event.created_at,
        now=now,
        quick_window=quick_window,
        mid_window=mid_window,
        quick_interval=quick_interval,
        mid_interval=mid_interval,
        slow_interval=slow_interval,
    )
    if settled or expired_flag:
        next_check = None
        interval_seconds = 0
    else:
        next_check = now + interval
        interval_seconds = int(interval.total_seconds())

    newly_settled = settled and not event.settled
    settled_at_dt = now if newly_settled else None
    await storage.apply_invoice_event_update(
        event=event,
        details=details,
        settled=settled,
        expired=expired_flag,
        next_check=next_check,
        expires_at=expires_at_dt,
        interval_seconds=interval_seconds,
        settled_at=settled_at_dt,
    )
    if newly_settled:
        await _dispatch_webhook_if_needed(
            webhook_dispatcher,
            event=event,
            details=details,
            settled_at=settled_at_dt,
        )
    return 1


async def refresh_invoice_statuses(
    storage: RequestLogStorage,
    ln_client: LNClient,
    *,
    quick_window_minutes: int = 5,
    quick_interval_seconds: int = 15,
    mid_window_minutes: int = 60,
    mid_interval_seconds: int = 60,
    slow_interval_seconds: int = 900,
    batch_size: int = 50,
    logger: Optional[logging.Logger] = None,
    events: Optional[List[InvoiceEvent]] = None,
    webhook_dispatcher: Optional[WebhookDispatcher] = None,
) -> int:
    logger = logger or LOGGER
    if events is None:
        events = await storage.get_due_invoice_events(limit=batch_size)
    if not events:
        return 0

    now = datetime.now(tz=timezone.utc)
    quick_window = timedelta(minutes=quick_window_minutes)
    mid_window = timedelta(minutes=mid_window_minutes)
    quick_interval = timedelta(seconds=quick_interval_seconds)
    mid_interval = timedelta(seconds=mid_interval_seconds)
    slow_interval = timedelta(seconds=slow_interval_seconds)

    processed = 0
    for event in events:
        if _is_remote_verify_event(event):
            processed += await _refresh_remote_verify_status(
                storage,
                event=event,
                now=now,
                quick_window=quick_window,
                mid_window=mid_window,
                quick_interval=quick_interval,
                mid_interval=mid_interval,
                slow_interval=slow_interval,
                webhook_dispatcher=webhook_dispatcher,
                logger=logger,
            )
            continue
        payment_hash_hex = (event.payment_hash or "").strip()
        if not payment_hash_hex:
            await storage.apply_invoice_event_update(
                event=event,
                details=event.details,
                settled=False,
                expired=True,
                next_check=None,
                expires_at=None,
                interval_seconds=0,
                settled_at=None,
            )
            continue
        try:
            payment_hash_bytes = bytes.fromhex(payment_hash_hex)
        except ValueError:
            logger.warning("Invalid payment hash on invoice event %s", event.id)
            await storage.apply_invoice_event_update(
                event=event,
                details=event.details,
                settled=False,
                expired=True,
                next_check=None,
                expires_at=None,
                interval_seconds=0,
                settled_at=None,
            )
            continue

        try:
            snapshot = await ln_client.lookup_invoice(payment_hash_bytes)
        except LookupError:
            logger.info("Invoice lookup returned not found for invoice event %s", event.id)
            await storage.apply_invoice_event_update(
                event=event,
                details=event.details,
                settled=False,
                expired=True,
                next_check=None,
                expires_at=None,
                interval_seconds=0,
                settled_at=None,
            )
            continue
        except Exception as exc:  # pragma: no cover - network/runtime
            logger.warning(
                "Invoice lookup failed for invoice event %s (error_type=%s)",
                event.id,
                type(exc).__name__,
            )
            next_check = now + quick_interval
            await storage.apply_invoice_event_update(
                event=event,
                details=event.details,
                settled=False,
                expired=False,
                next_check=next_check,
                expires_at=None,
                interval_seconds=int(quick_interval.total_seconds()),
                settled_at=None,
            )
            continue

        processed += 1
        snapshot_data = dict(snapshot or {})
        settled = bool(snapshot_data.get("settled"))
        expires_at_dt = _derive_expires_at(snapshot_data) or _parse_iso8601(event.expires_at)
        expired_flag = bool(snapshot_data.get("is_expired"))
        if not expired_flag and expires_at_dt is not None:
            expired_flag = datetime.now(tz=timezone.utc) >= expires_at_dt

        details = event.details if isinstance(event.details, dict) else {}
        details = _merge_invoice_snapshot(details, snapshot_data, settled=settled, expired=expired_flag)

        interval = _interval_for_age(
            created_at=event.created_at,
            now=now,
            quick_window=quick_window,
            mid_window=mid_window,
            quick_interval=quick_interval,
            mid_interval=mid_interval,
            slow_interval=slow_interval,
        )
        next_check: Optional[datetime]
        interval_seconds = 0
        if settled or expired_flag:
            next_check = None
        else:
            next_check = now + interval
            interval_seconds = int(interval.total_seconds())

        newly_settled = settled and not event.settled
        settled_at_dt = now if newly_settled else None

        await storage.apply_invoice_event_update(
            event=event,
            details=details,
            settled=settled,
            expired=expired_flag,
            next_check=next_check,
            expires_at=expires_at_dt,
            interval_seconds=interval_seconds,
            settled_at=settled_at_dt,
        )
        if newly_settled:
            await _dispatch_webhook_if_needed(
                webhook_dispatcher,
                event=event,
                details=details,
                settled_at=settled_at_dt,
            )

    return processed


async def refresh_all_pending_invoices(
    storage: RequestLogStorage,
    ln_client: LNClient,
    *,
    batch_size: int = 100,
    quick_window_minutes: int = 5,
    quick_interval_seconds: int = 15,
    mid_window_minutes: int = 60,
    mid_interval_seconds: int = 60,
    slow_interval_seconds: int = 900,
    logger: Optional[logging.Logger] = None,
    webhook_dispatcher: Optional[WebhookDispatcher] = None,
) -> int:
    logger = logger or LOGGER
    total = 0
    last_id: Optional[int] = None
    while True:
        events = await storage.get_unsettled_invoice_events(limit=batch_size, min_id=last_id)
        if not events:
            break
        await refresh_invoice_statuses(
            storage,
            ln_client,
            quick_window_minutes=quick_window_minutes,
            quick_interval_seconds=quick_interval_seconds,
            mid_window_minutes=mid_window_minutes,
            mid_interval_seconds=mid_interval_seconds,
            slow_interval_seconds=slow_interval_seconds,
            batch_size=batch_size,
            logger=logger,
            events=events,
            webhook_dispatcher=webhook_dispatcher,
        )
        total += len(events)
        last_id = events[-1].id
        if len(events) < batch_size:
            break
    return total


class InvoiceSubscriptionWorker:
    """Streams invoice updates from LND and mirrors them into storage."""

    def __init__(
        self,
        storage: RequestLogStorage,
        ln_client: LNClient,
        *,
        pending_interval_seconds: int = 300,
        backoff_initial_seconds: int = 5,
        backoff_max_seconds: int = 60,
        webhook_dispatcher: Optional[WebhookDispatcher] = None,
    ) -> None:
        self._storage = storage
        self._ln_client = ln_client
        self._pending_interval = timedelta(seconds=max(1, pending_interval_seconds))
        self._backoff_initial = max(1, backoff_initial_seconds)
        self._backoff_max = max(self._backoff_initial, backoff_max_seconds)
        self._task: Optional[asyncio.Task[None]] = None
        self._stop_event = asyncio.Event()
        self._webhook_dispatcher = webhook_dispatcher

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._run(), name="invoice-subscription-worker")

    async def stop(self) -> None:
        if not self._task:
            return
        self._stop_event.set()
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None

    async def _run(self) -> None:
        backoff = self._backoff_initial
        try:
            while not self._stop_event.is_set():
                try:
                    await self._consume_stream()
                    backoff = self._backoff_initial
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # pragma: no cover - runtime errors
                    LOGGER.warning(
                        "Invoice subscription stream failed (error_type=%s)",
                        type(exc).__name__,
                    )
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, self._backoff_max)
        except asyncio.CancelledError:
            pass

    async def _consume_stream(self) -> None:
        async for snapshot in self._ln_client.subscribe_invoices():
            if self._stop_event.is_set():
                break
            try:
                await self._apply_snapshot(snapshot)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - runtime errors
                LOGGER.warning(
                    "Failed to apply invoice subscription update (error_type=%s)",
                    type(exc).__name__,
                )

    async def _apply_snapshot(self, snapshot: Dict[str, Any]) -> None:
        payment_hash_value = snapshot.get("r_hash") or snapshot.get("payment_hash")
        if isinstance(payment_hash_value, bytes):
            payment_hash_hex = payment_hash_value.hex()
        elif isinstance(payment_hash_value, str):
            payment_hash_hex = payment_hash_value.strip().lower()
        else:
            return
        if not payment_hash_hex:
            return
        event = await self._storage.get_invoice_event_by_hash(payment_hash_hex)
        if not event:
            return
        snapshot_data = dict(snapshot)
        settled = bool(snapshot_data.get("settled"))
        expires_at_dt = _derive_expires_at(snapshot_data) or _parse_iso8601(event.expires_at)
        expired_flag = bool(snapshot_data.get("is_expired"))
        if not expired_flag and expires_at_dt is not None:
            expired_flag = datetime.now(tz=timezone.utc) >= expires_at_dt
        details = event.details if isinstance(event.details, dict) else {}
        details = _merge_invoice_snapshot(details, snapshot_data, settled=settled, expired=expired_flag)

        now = datetime.now(tz=timezone.utc)
        next_check: Optional[datetime]
        interval_seconds = 0
        if settled or expired_flag:
            next_check = None
        else:
            next_check = now + self._pending_interval
            interval_seconds = int(self._pending_interval.total_seconds())

        newly_settled = settled and not event.settled
        settled_at_dt = now if newly_settled else None

        await self._storage.apply_invoice_event_update(
            event=event,
            details=details,
            settled=settled,
            expired=expired_flag,
            next_check=next_check,
            expires_at=expires_at_dt,
            interval_seconds=interval_seconds,
            settled_at=settled_at_dt,
        )
        if newly_settled:
            await _dispatch_webhook_if_needed(
                self._webhook_dispatcher,
                event=event,
                details=details,
                settled_at=settled_at_dt,
            )


class InvoiceFullRefreshWorker:
    """Runs a full pending-invoice refresh on a fixed interval."""

    def __init__(
        self,
        storage: RequestLogStorage,
        ln_client: LNClient,
        *,
        interval_seconds: int = 1_800,
        batch_size: int = 250,
        webhook_dispatcher: Optional[WebhookDispatcher] = None,
    ) -> None:
        self._storage = storage
        self._ln_client = ln_client
        self._interval = max(60, interval_seconds)
        self._batch_size = max(1, batch_size)
        self._task: Optional[asyncio.Task[None]] = None
        self._stop_event = asyncio.Event()
        self._webhook_dispatcher = webhook_dispatcher

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop_event.clear()
        try:
            await self.run_once()
        except Exception as exc:  # pragma: no cover - runtime errors
            LOGGER.warning(
                "Startup full invoice refresh failed (error_type=%s)",
                type(exc).__name__,
            )
        self._task = asyncio.create_task(self._run(), name="invoice-full-refresh-worker")

    async def stop(self) -> None:
        if not self._task:
            return
        self._stop_event.set()
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None

    async def run_once(self) -> int:
        return await refresh_all_pending_invoices(
            self._storage,
            self._ln_client,
            batch_size=self._batch_size,
            webhook_dispatcher=self._webhook_dispatcher,
        )

    async def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self._interval)
                except asyncio.TimeoutError:
                    try:
                        await self.run_once()
                    except Exception as exc:  # pragma: no cover - runtime errors
                        LOGGER.warning(
                            "Full invoice refresh failed (error_type=%s)",
                            type(exc).__name__,
                        )
                    continue
        except asyncio.CancelledError:
            pass
