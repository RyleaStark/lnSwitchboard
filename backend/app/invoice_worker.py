"""Background worker and helpers for refreshing invoice statuses."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from .ln_client import LNClient
from .log_storage import RequestLogStorage

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
    invoice_details["last_checked_at"] = datetime.now(tz=timezone.utc).isoformat()
    return details


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
) -> int:
    logger = logger or LOGGER
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
            )
            continue
        try:
            payment_hash_bytes = bytes.fromhex(payment_hash_hex)
        except ValueError:
            logger.warning("Invalid payment hash %s on invoice event %s", payment_hash_hex, event.id)
            await storage.apply_invoice_event_update(
                event=event,
                details=event.details,
                settled=False,
                expired=True,
                next_check=None,
                expires_at=None,
                interval_seconds=0,
            )
            continue

        try:
            snapshot = await ln_client.lookup_invoice(payment_hash_bytes)
        except Exception as exc:  # pragma: no cover - network/runtime
            logger.warning("Invoice lookup failed for %s: %s", payment_hash_hex, exc)
            next_check = now + quick_interval
            await storage.apply_invoice_event_update(
                event=event,
                details=event.details,
                settled=False,
                expired=False,
                next_check=next_check,
                expires_at=None,
                interval_seconds=int(quick_interval.total_seconds()),
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

        created_at_dt = _parse_iso8601(event.created_at) or now
        age = now - created_at_dt
        if age <= quick_window:
            interval = quick_interval
        elif age <= mid_window:
            interval = mid_interval
        else:
            interval = slow_interval
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

    return processed


class InvoiceStatusWorker:
    """Background worker that keeps invoice/request logs in sync with LND."""

    def __init__(
        self,
        storage: RequestLogStorage,
        ln_client: LNClient,
        *,
        batch_size: int = 50,
        quick_window_minutes: int = 5,
        quick_interval_seconds: int = 15,
        mid_window_minutes: int = 60,
        mid_interval_seconds: int = 60,
        slow_interval_seconds: int = 900,
        idle_sleep_seconds: int = 15,
    ) -> None:
        self._storage = storage
        self._ln_client = ln_client
        self._batch_size = batch_size
        self._quick_window_minutes = quick_window_minutes
        self._quick_interval_seconds = quick_interval_seconds
        self._mid_window_minutes = mid_window_minutes
        self._mid_interval_seconds = mid_interval_seconds
        self._slow_interval_seconds = slow_interval_seconds
        self._idle_sleep_seconds = max(1, idle_sleep_seconds)
        self._task: Optional[asyncio.Task[None]] = None
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._run(), name="invoice-status-worker")

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
        try:
            while not self._stop_event.is_set():
                processed = await refresh_invoice_statuses(
                    self._storage,
                    self._ln_client,
                    quick_window_minutes=self._quick_window_minutes,
                    quick_interval_seconds=self._quick_interval_seconds,
                    mid_window_minutes=self._mid_window_minutes,
                    mid_interval_seconds=self._mid_interval_seconds,
                    slow_interval_seconds=self._slow_interval_seconds,
                    batch_size=self._batch_size,
                    logger=LOGGER,
                )
                if processed:
                    await asyncio.sleep(0)
                    continue
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self._idle_sleep_seconds)
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            pass
