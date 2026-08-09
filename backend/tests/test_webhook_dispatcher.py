from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import sqlite3
from datetime import datetime, timezone

import pytest

from backend.app.ln_address_store import LNAddressStore
from backend.app.log_storage import InvoiceEvent, RequestLogStorage
from ..app.outbound_security import OutboundHTTPStatusError, UnsafeOutboundTarget
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


def test_private_webhook_targets_are_blocked_by_default(tmp_path) -> None:
    async def exercise() -> None:
        address_store, _address = await _create_address(tmp_path)
        dispatcher = WebhookDispatcher(address_store=address_store)

        with pytest.raises(UnsafeOutboundTarget, match="non-public network"):
            await dispatcher._send(url="http://127.0.0.1/admin", payload={}, headers={})

    asyncio.run(exercise())


def test_success_logs_do_not_expose_webhook_url_secrets(tmp_path, caplog) -> None:
    async def exercise() -> None:
        address_store, _address = await _create_address(tmp_path)

        async def sender(url, payload, headers):
            return None

        dispatcher = WebhookDispatcher(address_store=address_store, sender=sender)
        secret_url = (
            "https://hooks.example.invalid/services/PATH_SECRET"
            "?token=QUERY_SECRET"
        )
        with caplog.at_level(logging.INFO):
            delivered = await dispatcher._attempt_delivery(
                url=secret_url,
                payload={},
                headers={},
                attempt=1,
                delivery_id=0,
            )

        assert delivered is True
        messages = "\n".join(record.getMessage() for record in caplog.records)
        assert "PATH_SECRET" not in messages
        assert "QUERY_SECRET" not in messages
        assert secret_url not in messages

    asyncio.run(exercise())


def test_failure_logs_do_not_expose_webhook_url_or_exception_secrets(
    tmp_path, caplog
) -> None:
    async def exercise() -> None:
        address_store, _address = await _create_address(tmp_path)

        async def sender(url, payload, headers):
            raise RuntimeError("delivery failed with EXCEPTION_SECRET")

        dispatcher = WebhookDispatcher(
            address_store=address_store,
            sender=sender,
            max_retries=0,
        )
        secret_url = (
            "https://hooks.example.invalid/services/PATH_SECRET"
            "?token=QUERY_SECRET"
        )
        with caplog.at_level(logging.WARNING):
            delivered = await dispatcher._attempt_delivery(
                url=secret_url,
                payload={},
                headers={},
                attempt=1,
                delivery_id=0,
            )

        assert delivered is False
        messages = "\n".join(record.getMessage() for record in caplog.records)
        for secret in (
            "PATH_SECRET",
            "QUERY_SECRET",
            "EXCEPTION_SECRET",
            secret_url,
        ):
            assert secret not in messages

    asyncio.run(exercise())


def test_persisted_delivery_history_never_contains_webhook_secrets(tmp_path) -> None:
    async def exercise() -> None:
        db_path = tmp_path / "persisted-redaction.db"
        storage = RequestLogStorage(db_path)
        address_store = LNAddressStore(db_path)
        secret_url = (
            "https://hooks.example.invalid/services/PERSISTED_PATH_SECRET"
            "?token=PERSISTED_QUERY_SECRET"
        )
        address = await address_store.add_address(
            local_part="pay",
            domain="testserver",
            min_sendable_sat=None,
            max_sendable_sat=None,
            metadata_description=None,
            success_message=None,
            webhook_urls=[secret_url],
        )
        event, details = _make_event(address)

        class SecretStatusError(OutboundHTTPStatusError):
            def __str__(self) -> str:
                return "PERSISTED_EXCEPTION_SECRET"

        async def sender(url, payload, headers):
            raise SecretStatusError(503, "PERSISTED_RESPONSE_SECRET")

        dispatcher = WebhookDispatcher(
            address_store=address_store,
            delivery_storage=storage,
            sender=sender,
            max_retries=0,
        )
        delivered = await dispatcher.dispatch_payment_settled(
            event=event,
            details=details,
            settled_at=datetime.now(tz=timezone.utc),
        )
        assert delivered is False

        exposed = json.dumps(
            {
                "deliveries": await storage.list_deliveries(page=1, page_size=5),
                "attempts": await storage.list_delivery_attempts(1),
                "request_logs": await storage.get_recent(),
            },
            sort_keys=True,
        )
        with sqlite3.connect(db_path) as conn:
            persisted = json.dumps(
                {
                    "deliveries": conn.execute(
                        "SELECT target, headers FROM webhook_deliveries"
                    ).fetchall(),
                    "attempts": conn.execute(
                        "SELECT error, response_body FROM webhook_attempts"
                    ).fetchall(),
                    "request_logs": conn.execute(
                        "SELECT message, details FROM request_logs WHERE event = 'webhook_delivery'"
                    ).fetchall(),
                },
                sort_keys=True,
            )

        for secret in (
            "PERSISTED_PATH_SECRET",
            "PERSISTED_QUERY_SECRET",
            "PERSISTED_EXCEPTION_SECRET",
            "PERSISTED_RESPONSE_SECRET",
        ):
            assert secret not in exposed
            assert secret not in persisted

    asyncio.run(exercise())


def test_startup_scrubs_legacy_webhook_history_secrets(tmp_path) -> None:
    db_path = tmp_path / "legacy-redaction.db"
    RequestLogStorage(db_path)
    now = datetime.now(tz=timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "DELETE FROM lnswitchboard_migrations WHERE name = 'webhook_history_redaction_v1'"
        )
        conn.execute(
            """
            INSERT INTO webhook_deliveries (
                created_at, updated_at, kind, event, target, status, payload,
                headers, address_id, invoice_event_id, request_log_id, delivery_key
            ) VALUES (?, ?, 'http.webhook', 'payment.settled', ?, 'failed', '{}', ?, NULL, NULL, NULL, 'legacy')
            """,
            (
                now,
                now,
                "https://hooks.invalid/LEGACY_PATH_SECRET?token=LEGACY_QUERY_SECRET",
                json.dumps({"X-LnSwitchboard-Signature": "LEGACY_SIGNATURE_SECRET"}),
            ),
        )
        delivery_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.execute(
            """
            INSERT INTO webhook_attempts (
                delivery_id, attempted_at, attempt_number, success, error, response_body
            ) VALUES (?, ?, 1, 0, 'LEGACY_EXCEPTION_SECRET', 'LEGACY_RESPONSE_SECRET')
            """,
            (delivery_id, now),
        )
        conn.execute(
            """
            INSERT INTO request_logs (
                timestamp, username, ip, event, status, message, details
            ) VALUES (?, 'webhook', 'internal', 'webhook_delivery', 'failed',
                      'LEGACY_LOG_SECRET', '{"target":"LEGACY_DETAIL_SECRET"}')
            """,
            (now,),
        )

    RequestLogStorage(db_path)
    with sqlite3.connect(db_path) as conn:
        persisted = json.dumps(
            {
                "deliveries": conn.execute(
                    "SELECT target, headers FROM webhook_deliveries"
                ).fetchall(),
                "attempts": conn.execute(
                    "SELECT error, response_body FROM webhook_attempts"
                ).fetchall(),
                "request_logs": conn.execute(
                    "SELECT message, details FROM request_logs WHERE event = 'webhook_delivery'"
                ).fetchall(),
            },
            sort_keys=True,
        )
        assert conn.execute(
            "SELECT COUNT(*) FROM lnswitchboard_migrations WHERE name = 'webhook_history_redaction_v1'"
        ).fetchone()[0] == 1

    for secret in (
        "LEGACY_PATH_SECRET",
        "LEGACY_QUERY_SECRET",
        "LEGACY_SIGNATURE_SECRET",
        "LEGACY_EXCEPTION_SECRET",
        "LEGACY_RESPONSE_SECRET",
        "LEGACY_LOG_SECRET",
        "LEGACY_DETAIL_SECRET",
    ):
        assert secret not in persisted


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
    target_reference = f"webhook:{hashlib.sha256(b'https://hooks.example.com/payments').hexdigest()[:16]}"
    assert delivery["target"] == target_reference
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
    assert "X-LnSwitchboard-Signature" not in delivery_log["details"]["headers"]
    assert delivery_log["details"]["headers"]["X-LnSwitchboard-Delivery-Id"] == delivery_id


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
    assert delivery_logs[0]["details"]["target"] == (
        f"webhook:{hashlib.sha256(b'https://hooks.example.com/payments').hexdigest()[:16]}"
    )


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
