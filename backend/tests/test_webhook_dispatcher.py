from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timezone

from backend.app.ln_address_store import LNAddressStore
from backend.app.log_storage import InvoiceEvent, RequestLogStorage
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


def test_webhook_delivery_history_and_hmac_headers(tmp_path):
    asyncio.run(_exercise_delivery_history_and_hmac_headers(tmp_path))


async def _exercise_delivery_history_and_hmac_headers(tmp_path):
    db_path = tmp_path / "deliveries.db"
    storage = RequestLogStorage(db_path)
    address_store = LNAddressStore(db_path)
    address = await address_store.add_address(
        local_part="pay",
        domain="testserver",
        min_sendable_sat=None,
        max_sendable_sat=None,
        metadata_description=None,
        success_message=None,
        webhook_urls=[],
        webhook_endpoints=[
            {
                "url": "https://hooks.example.com/payments",
                "secret": "receiver-secret",
                "filters": {"tags": ["vip"]},
            }
        ],
    )
    event, details = _make_event(address)
    details["username_raw"] = "pay+vip"
    details["ln_address"] = "pay+vip@testserver"
    captured = []

    async def sender(url, payload, headers):
        captured.append({"url": url, "payload": payload, "headers": headers})

    dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=storage,
        sender=sender,
    )
    delivered = await dispatcher.dispatch_payment_settled(
        event=event,
        details=details,
        settled_at=datetime.now(tz=timezone.utc),
    )

    assert delivered is True
    assert len(captured) == 1
    headers = captured[0]["headers"]
    delivery_id = headers["X-LnSwitchboard-Delivery-Id"]
    assert headers["X-LnSwitchboard-Signature"].startswith("sha256=")
    body = json.dumps(captured[0]["payload"], separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    expected = hmac.new(
        b"receiver-secret",
        f"{headers['X-LnSwitchboard-Signature-Timestamp']}.{delivery_id}.{body}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert headers["X-LnSwitchboard-Signature"] == f"sha256={expected}"

    deliveries = await storage.list_deliveries(page=1, page_size=5)
    assert deliveries["total_items"] == 1
    delivery = deliveries["items"][0]
    assert delivery["status"] == "delivered"
    assert delivery["target"] == "https://hooks.example.com/payments"
    assert delivery["last_attempt"]["success"] is True
    delivery_logs = [entry for entry in await storage.get_recent() if entry["event"] == "webhook_delivery"]
    assert len(delivery_logs) == 1
    delivery_log = delivery_logs[0]
    assert delivery_log["status"] == "ok"
    assert delivery_log["username"] == "pay+vip"
    assert delivery_log["domain"] == "testserver"
    assert delivery_log["amount_msat"] == 2000
    assert delivery_log["details"]["delivery_id"] == delivery["id"]
    assert delivery_log["details"]["delivery_status"] == "delivered"
    assert delivery_log["details"]["attempt_number"] == 1
    assert delivery_log["details"]["headers"]["X-LnSwitchboard-Signature"].startswith("sha256=")


def test_webhook_filters_skip_non_matching_endpoint(tmp_path):
    asyncio.run(_exercise_webhook_filters_skip_non_matching_endpoint(tmp_path))


async def _exercise_webhook_filters_skip_non_matching_endpoint(tmp_path):
    db_path = tmp_path / "filters.db"
    storage = RequestLogStorage(db_path)
    address_store = LNAddressStore(db_path)
    address = await address_store.add_address(
        local_part="pay",
        domain="testserver",
        min_sendable_sat=None,
        max_sendable_sat=None,
        metadata_description=None,
        success_message=None,
        webhook_urls=[],
        webhook_endpoints=[
            {
                "url": "https://hooks.example.com/payments",
                "filters": {"tags": ["vip"]},
            }
        ],
    )
    event, details = _make_event(address)
    captured = []

    async def sender(url, payload, headers):
        captured.append(url)

    dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=storage,
        sender=sender,
    )
    delivered = await dispatcher.dispatch_payment_settled(
        event=event,
        details=details,
        settled_at=datetime.now(tz=timezone.utc),
    )
    assert delivered is False
    assert captured == []
    deliveries = await storage.list_deliveries(page=1, page_size=5)
    assert deliveries["items"][0]["status"] == "skipped"
    delivery_logs = [entry for entry in await storage.get_recent() if entry["event"] == "webhook_delivery"]
    assert len(delivery_logs) == 1
    assert delivery_logs[0]["status"] == "skipped"
    assert delivery_logs[0]["details"]["delivery_status"] == "skipped"
    assert delivery_logs[0]["details"]["target"] == "https://hooks.example.com/payments"


def test_webhook_retry_resumes_after_restart(tmp_path):
    asyncio.run(_exercise_webhook_retry_resumes_after_restart(tmp_path))


async def _exercise_webhook_retry_resumes_after_restart(tmp_path):
    db_path = tmp_path / "restart-deliveries.db"
    storage = RequestLogStorage(db_path)
    address_store, address = await _create_address(tmp_path)
    event, details = _make_event(address)

    async def failing_sender(url, payload, headers):
        raise RuntimeError("receiver offline")

    first_dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=storage,
        sender=failing_sender,
        max_retries=2,
        retry_window_seconds=60,
    )
    delivered = await first_dispatcher.dispatch_payment_settled(
        event=event,
        details=details,
        settled_at=datetime.now(tz=timezone.utc),
    )
    assert delivered is False

    deliveries = await storage.list_deliveries(page=1, page_size=5)
    delivery = deliveries["items"][0]
    assert delivery["status"] == "retrying"
    assert delivery["last_attempt"]["success"] is False
    delivery_logs = [entry for entry in await storage.get_recent() if entry["event"] == "webhook_delivery"]
    assert len(delivery_logs) == 1
    assert delivery_logs[0]["status"] == "retrying"
    assert delivery_logs[0]["details"]["delivery_status"] == "retrying"
    assert delivery_logs[0]["details"]["attempt_number"] == 1

    resumed_event = asyncio.Event()
    captured = []

    async def recovering_sender(url, payload, headers):
        captured.append({"url": url, "payload": payload, "headers": headers})
        resumed_event.set()

    restarted_dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=storage,
        sender=recovering_sender,
        max_retries=2,
        retry_window_seconds=60,
    )
    resumed = await restarted_dispatcher.resume_pending_retries()
    assert resumed == 1
    await asyncio.wait_for(resumed_event.wait(), timeout=1.0)
    assert len(captured) == 1

    attempts = await storage.list_delivery_attempts(int(delivery["id"]))
    assert [attempt["attempt_number"] for attempt in attempts] == [1, 2]
    assert [attempt["success"] for attempt in attempts] == [False, True]
    delivery_after = await storage.get_delivery(int(delivery["id"]))
    assert delivery_after is not None
    assert delivery_after["status"] == "delivered"
    delivery_logs = [entry for entry in await storage.get_recent() if entry["event"] == "webhook_delivery"]
    assert [entry["details"]["delivery_status"] for entry in delivery_logs] == ["retrying", "delivered"]
    assert [entry["details"]["attempt_number"] for entry in delivery_logs] == [1, 2]
