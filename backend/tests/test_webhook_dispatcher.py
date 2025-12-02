from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from backend.app.ln_address_store import LNAddressStore
from backend.app.log_storage import InvoiceEvent
from backend.app.webhook_dispatcher import WebhookDispatcher


async def _create_address(tmp_path):
    store = LNAddressStore(tmp_path / "addresses.db")
    record = await store.add_address(
        local_part="pay",
        domain="testserver",
        min_sendable_sat=None,
        max_sendable_sat=None,
        metadata_description=None,
        success_message=None,
        webhook_urls=["https://hooks.example.com/payments"],
    )
    return store, record


def _make_event(address, payment_hash: str = "ab" * 32) -> tuple[InvoiceEvent, dict]:
    created = datetime.now(tz=timezone.utc).isoformat()
    details = {
        "ln_address": f'{address["local_part"]}@{address["domain"]}',
        "username_raw": address["local_part"],
        "domain": address["domain"],
        "payment_hash": payment_hash,
        "address_override": {
            "id": address["id"],
            "local_part": address["local_part"],
            "domain": address["domain"],
        },
        "invoice": {"payment_hash": payment_hash, "settled": True},
    }
    event = InvoiceEvent(
        id=1,
        username=address["local_part"],
        domain=address["domain"],
        ip="127.0.0.1",
        amount_msat=2000,
        payment_hash=payment_hash,
        payment_request="lnbc1tester",
        request_log_id=None,
        created_at=created,
        next_check_at=None,
        check_interval_seconds=60,
        expires_at=None,
        settled=True,
        expired=False,
        details=details,
        settled_at=None,
    )
    return event, details


def test_webhook_retry_eventually_succeeds(tmp_path):
    asyncio.run(_exercise_retry_eventually_succeeds(tmp_path))


async def _exercise_retry_eventually_succeeds(tmp_path):
    address_store, address = await _create_address(tmp_path)
    event, details = _make_event(address)
    attempts = []
    success_event = asyncio.Event()

    async def flaky_sender(url, payload, headers):
        attempts.append(len(attempts) + 1)
        if len(attempts) < 3:
            raise RuntimeError("temporary failure")
        success_event.set()

    dispatcher = WebhookDispatcher(
        address_store=address_store,
        sender=flaky_sender,
        max_retries=5,
        retry_window_seconds=0.25,
    )
    delivered = await dispatcher.dispatch_payment_settled(
        event=event,
        details=details,
        settled_at=datetime.now(tz=timezone.utc),
    )
    assert delivered is False
    await asyncio.wait_for(success_event.wait(), timeout=1.0)
    assert attempts == [1, 2, 3]


def test_webhook_retry_stops_after_max_attempts(tmp_path):
    asyncio.run(_exercise_retry_stops_after_max_attempts(tmp_path))


async def _exercise_retry_stops_after_max_attempts(tmp_path):
    address_store, address = await _create_address(tmp_path)
    event, details = _make_event(address)
    attempts = []

    async def failing_sender(url, payload, headers):
        attempts.append(len(attempts) + 1)
        raise RuntimeError("permanent failure")

    dispatcher = WebhookDispatcher(
        address_store=address_store,
        sender=failing_sender,
        max_retries=2,
        retry_window_seconds=0.1,
    )
    delivered = await dispatcher.dispatch_payment_settled(
        event=event,
        details=details,
        settled_at=datetime.now(tz=timezone.utc),
    )
    assert delivered is False
    await asyncio.sleep(0.35)
    assert len(attempts) == 3
