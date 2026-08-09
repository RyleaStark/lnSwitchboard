from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from backend.app.ln_address_store import LNAddressStore
from backend.app.log_storage import InvoiceEvent, RequestLogStorage
from backend.app.routers.webhooks import replay_delivery as replay_delivery_route
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


def test_persisted_retry_uses_current_endpoint_and_secret(tmp_path):
    asyncio.run(_exercise_persisted_retry_uses_current_endpoint_and_secret(tmp_path))


def test_manual_replay_conflicts_with_pending_successful_retry(tmp_path):
    asyncio.run(_exercise_manual_replay_conflicts_with_pending_success(tmp_path))


def test_manual_replay_conflicts_with_pending_failed_retry(tmp_path):
    asyncio.run(_exercise_manual_replay_conflicts_with_pending_failure(tmp_path))


def test_two_dispatchers_share_one_persistent_retry_claim(tmp_path):
    asyncio.run(_exercise_two_dispatchers_share_one_persistent_retry_claim(tmp_path))


def test_manual_replay_cannot_overlap_initial_delivery_claim(tmp_path):
    asyncio.run(_exercise_manual_replay_cannot_overlap_initial_claim(tmp_path))


def test_manual_replay_rejects_inflight_claim_without_cancelling_owner(tmp_path):
    asyncio.run(_exercise_manual_replay_rejects_inflight_claim(tmp_path))


def test_unreconstructable_delivery_replay_returns_conflict(tmp_path):
    class Storage:
        async def get_delivery(self, delivery_id):
            return {"id": delivery_id, "kind": "http.webhook"}

    class Dispatcher:
        async def replay_delivery(self, delivery):
            raise ValueError("Delivery payload is unavailable")

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            replay_delivery_route(
                1,
                storage=Storage(),
                dispatcher=Dispatcher(),
            )
        )
    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "Delivery can no longer be replayed from authoritative state"


def test_webhook_test_payload_is_transient(tmp_path) -> None:
    async def exercise() -> None:
        address_store, _address = await _create_address(tmp_path)
        storage = RequestLogStorage(tmp_path / "test-delivery.db")
        sent = []

        async def sender(url, payload, headers):
            sent.append((url, payload, headers))

        dispatcher = WebhookDispatcher(
            address_store=address_store,
            delivery_storage=storage,
            sender=sender,
        )
        assert await dispatcher.dispatch_test(
            url="https://hooks.example.invalid/test",
            payload={"body": "TRANSIENT_TEST_PAYLOAD_SECRET"},
            secret="TRANSIENT_TEST_HMAC_SECRET",
        )
        assert sent[0][1] == {"body": "TRANSIENT_TEST_PAYLOAD_SECRET"}
        deliveries = await storage.list_deliveries(page=1, page_size=10)
        assert deliveries["items"] == []

    asyncio.run(exercise())


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
        details["comment"] = "PERSISTED_PAYLOAD_SECRET"
        details["username_raw"] = "PERSISTED_USERNAME_SECRET"

        class SecretStatusError(OutboundHTTPStatusError):
            def __str__(self) -> str:
                return "ClassShapedSecretError"

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
                        "SELECT target, payload, headers FROM webhook_deliveries"
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
            "ClassShapedSecretError",
            "PERSISTED_RESPONSE_SECRET",
            "PERSISTED_PAYLOAD_SECRET",
            "PERSISTED_USERNAME_SECRET",
        ):
            assert secret not in exposed
            assert secret not in persisted

    asyncio.run(exercise())


@pytest.mark.parametrize("migration_marker_exists", [False, True])
def test_startup_scrubs_legacy_webhook_history_secrets(
    tmp_path, migration_marker_exists: bool
) -> None:
    db_path = tmp_path / f"legacy-redaction-{migration_marker_exists}.db"
    RequestLogStorage(db_path)
    now = datetime.now(tz=timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        if not migration_marker_exists:
            conn.execute(
                "DELETE FROM lnswitchboard_migrations "
                "WHERE name = 'webhook_history_redaction_v1'"
            )
        conn.execute(
            """
            INSERT INTO webhook_deliveries (
                created_at, updated_at, kind, event, target, status, payload,
                headers, address_id, invoice_event_id, request_log_id, delivery_key
            ) VALUES (?, ?, 'http.webhook', 'payment.settled', ?, 'failed', ?, ?, NULL, NULL, NULL, 'legacy')
            """,
            (
                now,
                now,
                "https://hooks.invalid/LEGACY_PATH_SECRET?token=LEGACY_QUERY_SECRET",
                json.dumps({"oauth_code": "LEGACY_PAYLOAD_SECRET"}),
                json.dumps({"X-LnSwitchboard-Signature": "LEGACY_SIGNATURE_SECRET"}),
            ),
        )
        delivery_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.execute(
            """
            INSERT INTO webhook_attempts (
                delivery_id, attempted_at, attempt_number, success, error, response_body
            ) VALUES (?, ?, 1, 0, 'type:RollbackClassShapedSecretError', 'LEGACY_RESPONSE_SECRET')
            """,
            (delivery_id, now),
        )
        conn.execute(
            """
            INSERT INTO request_logs (
                timestamp, username, domain, ip, amount_msat, event, status, message, details
            ) VALUES (?, 'LEGACY_PAYLOAD_DERIVED_USERNAME_SECRET',
                      'LEGACY_PAYLOAD_DERIVED_DOMAIN_SECRET.invalid',
                      'LEGACY_PROXY_HEADER_AS_IP_SECRET', 112233445566,
                      'webhook_delivery', 'failed',
                      'LEGACY_LOG_SECRET', '{"target":"LEGACY_DETAIL_SECRET"}')
            """,
            (now,),
        )
        conn.execute(
            """
            INSERT INTO request_logs (
                timestamp, username, ip, event, domain, amount_msat, status, message, details
            ) VALUES (?, 'payer', 'internal', 'invoice', 'example.invalid', 1000, 'error', ?, ?)
            """,
            (
                now,
                "LEGACY_INVOICE_EXCEPTION_SECRET",
                json.dumps(
                    {
                        "response": {"body": "LEGACY_REMOTE_BODY_SECRET"},
                        "payerdata_raw": "LEGACY_PAYER_SECRET",
                        "preimage": "LEGACY_PREIMAGE_SECRET",
                        "verify_url": "https://example.invalid/LEGACY_VERIFY_SECRET",
                        "error": {
                            "type": "LEGACY_ERROR_TYPE_SECRET",
                            "message": "LEGACY_ERROR_MESSAGE_SECRET",
                        },
                    }
                ),
            ),
        )
        conn.execute(
            """
            INSERT INTO invoice_events (
                created_at, username, domain, ip, amount_msat, payment_hash,
                payment_request, details, settled, expired, check_interval_seconds
            ) VALUES (?, 'payer', 'example.invalid', 'internal', 1000, ?, 'lnbc1safe', ?, 0, 0, 60)
            """,
            (
                now,
                "ab" * 32,
                json.dumps(
                    {
                        "response": {"body": "LEGACY_EVENT_RESPONSE_SECRET"},
                        "ln_client_response": {"token": "LEGACY_CLIENT_RESPONSE_SECRET"},
                        "metadata_for_hash": "LEGACY_METADATA_PAYLOAD_SECRET",
                        "proxy": {"header": "LEGACY_PROXY_HEADER_SECRET"},
                    }
                ),
            ),
        )

    sanitized_storage = RequestLogStorage(db_path)
    with sqlite3.connect(db_path) as conn:
        persisted = json.dumps(
            {
                "deliveries": conn.execute(
                    "SELECT target, payload, headers FROM webhook_deliveries"
                ).fetchall(),
                "attempts": conn.execute(
                    "SELECT error, response_body FROM webhook_attempts"
                ).fetchall(),
                "request_logs": conn.execute(
                    "SELECT username, domain, ip, amount_msat, message, details FROM request_logs"
                ).fetchall(),
                "invoice_events": conn.execute("SELECT details FROM invoice_events").fetchall(),
            },
            sort_keys=True,
        )
        assert conn.execute(
            "SELECT COUNT(*) FROM lnswitchboard_migrations WHERE name = 'webhook_history_redaction_v1'"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM request_logs WHERE event = 'webhook_delivery'"
        ).fetchone()[0] == 1
        assert conn.execute(
            """
            SELECT username, domain, ip, amount_msat
            FROM request_logs
            WHERE event = 'webhook_delivery'
            """
        ).fetchone() == ("webhook", None, "redacted", None)
    exposed = json.dumps(
        asyncio.run(sanitized_storage.list_invoice_events(page=1, page_size=10)),
        sort_keys=True,
    )

    for secret in (
        "LEGACY_PATH_SECRET",
        "LEGACY_QUERY_SECRET",
        "LEGACY_SIGNATURE_SECRET",
        "LEGACY_PAYLOAD_SECRET",
        "RollbackClassShapedSecretError",
        "LEGACY_RESPONSE_SECRET",
        "LEGACY_LOG_SECRET",
        "LEGACY_DETAIL_SECRET",
        "LEGACY_INVOICE_EXCEPTION_SECRET",
        "LEGACY_REMOTE_BODY_SECRET",
        "LEGACY_PAYER_SECRET",
        "LEGACY_PREIMAGE_SECRET",
        "LEGACY_VERIFY_SECRET",
        "LEGACY_ERROR_TYPE_SECRET",
        "LEGACY_ERROR_MESSAGE_SECRET",
        "LEGACY_EVENT_RESPONSE_SECRET",
        "LEGACY_CLIENT_RESPONSE_SECRET",
        "LEGACY_METADATA_PAYLOAD_SECRET",
        "LEGACY_PROXY_HEADER_SECRET",
        "LEGACY_PAYLOAD_DERIVED_USERNAME_SECRET",
        "LEGACY_PAYLOAD_DERIVED_DOMAIN_SECRET",
        "LEGACY_PROXY_HEADER_AS_IP_SECRET",
    ):
        assert secret not in persisted
        assert secret not in exposed


def test_cleanup_expires_terminal_history_but_preserves_retry_authority(tmp_path) -> None:
    db_path = tmp_path / "retention.db"
    storage = RequestLogStorage(db_path, retention_days=1)
    old = "2000-01-01T00:00:00+00:00"
    with sqlite3.connect(db_path) as conn:
        invoice_ids = []
        for payment_hash in ("11" * 32, "22" * 32, "33" * 32):
            conn.execute(
                """
                INSERT INTO invoice_events (
                    created_at, username, domain, ip, amount_msat, payment_hash,
                    details, settled, expired, check_interval_seconds
                ) VALUES (?, 'pay', 'testserver', 'redacted', 1000, ?, '{}', 1, 0, 60)
                """,
                (old, payment_hash),
            )
            invoice_ids.append(int(conn.execute("SELECT last_insert_rowid()").fetchone()[0]))
        delivery_ids = []
        for status_value, invoice_id in zip(
            ("delivered", "retrying", "skipped"), invoice_ids, strict=True
        ):
            conn.execute(
                """
                INSERT INTO webhook_deliveries (
                    created_at, updated_at, kind, event, target, status, payload,
                    headers, invoice_event_id, delivery_key
                ) VALUES (?, ?, 'http.webhook', 'payment.settled', 'webhook:safe', ?,
                          NULL, '{}', ?, ?)
                """,
                (old, old, status_value, invoice_id, f"retention-{invoice_id}"),
            )
            delivery_ids.append(int(conn.execute("SELECT last_insert_rowid()").fetchone()[0]))
        for delivery_id in delivery_ids:
            conn.execute(
                """
                INSERT INTO webhook_attempts (
                    delivery_id, attempted_at, attempt_number, success, error
                ) VALUES (?, ?, 1, 0, 'type:DeliveryError')
                """,
                (delivery_id, old),
            )

    asyncio.run(storage.cleanup())

    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT id FROM webhook_deliveries ORDER BY id"
        ).fetchall() == [(delivery_ids[1],)]
        assert conn.execute(
            "SELECT delivery_id FROM webhook_attempts ORDER BY delivery_id"
        ).fetchall() == [(delivery_ids[1],)]
        assert conn.execute(
            "SELECT id FROM invoice_events ORDER BY id"
        ).fetchall() == [(invoice_ids[1],)]


def test_startup_applies_retention_before_loading_operator_history(tmp_path) -> None:
    db_path = tmp_path / "startup-retention.db"
    RequestLogStorage(db_path, retention_days=1)
    old = "2000-01-01T00:00:00+00:00"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO invoice_events (
                created_at, username, domain, ip, amount_msat, payment_hash,
                details, settled, expired, check_interval_seconds
            ) VALUES (?, 'pay', 'testserver', 'redacted', 1000, ?, '{}', 1, 0, 60)
            """,
            (old, "44" * 32),
        )
        invoice_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.execute(
            """
            INSERT INTO webhook_deliveries (
                created_at, updated_at, kind, event, target, status, payload,
                headers, invoice_event_id, delivery_key
            ) VALUES (?, ?, 'http.webhook', 'payment.settled', 'webhook:safe',
                      'skipped', NULL, '{}', ?, 'startup-retention')
            """,
            (old, old, invoice_id),
        )
        delivery_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.execute(
            """
            INSERT INTO webhook_attempts (
                delivery_id, attempted_at, attempt_number, success, error
            ) VALUES (?, ?, 1, 0, 'type:DeliveryError')
            """,
            (delivery_id, old),
        )

    restarted = RequestLogStorage(db_path, retention_days=1)

    assert asyncio.run(restarted.get_recent()) == []
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM webhook_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM webhook_deliveries").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM invoice_events").fetchone()[0] == 0


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


async def _exercise_persisted_retry_uses_current_endpoint_and_secret(tmp_path):
    db_path = tmp_path / "retry-rotation.db"
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
                "id": "stable",
                "url": "https://old.example.invalid/endpoint",
                "secret": "old-secret",
                "filters": {},
            }
        ],
    )
    storage = RequestLogStorage(db_path)
    event, details = _make_event(address)
    settled_at = datetime.now(tz=timezone.utc)
    await storage.log_invoice_event(
        username=event.username,
        domain=event.domain,
        amount_msat=event.amount_msat,
        ip=event.ip,
        payment_hash=event.payment_hash,
        payment_request=event.payment_request,
        details=details,
        request_log_id=event.request_log_id,
    )
    await storage.apply_invoice_event_update(
        event=event,
        details=details,
        settled=True,
        expired=False,
        next_check=None,
        expires_at=None,
        interval_seconds=60,
        settled_at=settled_at,
    )

    calls: list[tuple[str, dict, dict]] = []
    retried = asyncio.Event()

    async def sender(url, payload, headers):
        calls.append((url, payload, headers))
        if len(calls) == 1:
            await address_store.update_address(
                address["id"],
                local_part=address["local_part"],
                domain=address["domain"],
                min_sendable_sat=address.get("min_sendable_sat"),
                max_sendable_sat=address.get("max_sendable_sat"),
                metadata_description=address.get("metadata_description"),
                success_message=address.get("success_message"),
                webhook_urls=[],
                webhook_endpoints=[
                    {
                        "id": "stable",
                        "url": "https://current.example.invalid/endpoint",
                        "secret": "current-secret",
                        "filters": {},
                    }
                ],
                payer_data=address.get("payer_data") or {},
                routing_mode=address.get("routing_mode") or "local",
                forward_to=address.get("forward_to"),
            )
            raise RuntimeError("retry")
        retried.set()

    dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=storage,
        sender=sender,
        max_retries=1,
        retry_window_seconds=0.1,
    )
    assert not await dispatcher.dispatch_payment_settled(
        event=event,
        details=details,
        settled_at=settled_at,
    )
    await asyncio.wait_for(retried.wait(), timeout=1.0)
    assert [call[0] for call in calls] == [
        "https://old.example.invalid/endpoint",
        "https://current.example.invalid/endpoint",
    ]
    assert calls[0][1] == calls[1][1]
    assert calls[1][1]["version"] == "1"
    headers = calls[1][2]
    signed = (
        f'{headers["X-LnSwitchboard-Signature-Timestamp"]}.'
        f'{headers["X-LnSwitchboard-Delivery-Id"]}.'
        f'{WebhookDispatcher._payload_body(calls[1][1])}'
    ).encode()
    expected = hmac.new(b"current-secret", signed, hashlib.sha256).hexdigest()
    assert headers["X-LnSwitchboard-Signature"] == f"sha256={expected}"


async def _seed_retry_authority(tmp_path, filename: str):
    db_path = tmp_path / filename
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
                "id": "stable",
                "url": "https://current.example.invalid/endpoint",
                "secret": "current-secret",
                "filters": {},
            }
        ],
    )
    storage = RequestLogStorage(db_path)
    event, details = _make_event(address)
    settled_at = datetime.now(tz=timezone.utc)
    await storage.log_invoice_event(
        username=event.username,
        domain=event.domain,
        amount_msat=event.amount_msat,
        ip=event.ip,
        payment_hash=event.payment_hash,
        payment_request=event.payment_request,
        details=details,
        request_log_id=event.request_log_id,
    )
    await storage.apply_invoice_event_update(
        event=event,
        details=details,
        settled=True,
        expired=False,
        next_check=None,
        expires_at=None,
        interval_seconds=60,
        settled_at=settled_at,
    )
    return db_path, address_store, storage, event, details, settled_at


async def _exercise_manual_replay_conflicts_with_pending_success(tmp_path) -> None:
    _, address_store, storage, event, details, settled_at = (
        await _seed_retry_authority(tmp_path, "manual-replay-race.db")
    )

    calls: list[tuple[str, dict, dict]] = []

    async def sender(url, payload, headers):
        calls.append((url, payload, headers))
        if len(calls) == 1:
            raise RuntimeError("schedule one retry")

    dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=storage,
        sender=sender,
        max_retries=1,
        retry_window_seconds=0.2,
    )
    assert not await dispatcher.dispatch_payment_settled(
        event=event,
        details=details,
        settled_at=settled_at,
    )
    delivery = (await storage.list_deliveries(page=1, page_size=10))["items"][0]
    with pytest.raises(ValueError, match="in progress"):
        await dispatcher.replay_delivery(delivery)

    await asyncio.sleep(0.3)

    assert len(calls) == 2
    refreshed = await storage.get_delivery(int(delivery["id"]))
    assert refreshed is not None
    assert refreshed["status"] == "delivered"
    assert [
        attempt["attempt_number"]
        for attempt in await storage.list_delivery_attempts(int(delivery["id"]))
    ] == [1, 2]


async def _cancel_retry_tasks(dispatcher: WebhookDispatcher) -> None:
    tasks = tuple(dispatcher._retry_tasks)
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _exercise_manual_replay_conflicts_with_pending_failure(tmp_path) -> None:
    _, address_store, storage, event, details, settled_at = (
        await _seed_retry_authority(tmp_path, "failed-manual-replay.db")
    )
    calls = 0

    async def sender(_url, _payload, _headers):
        nonlocal calls
        calls += 1
        raise RuntimeError("inert failure")

    dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=storage,
        sender=sender,
        max_retries=1,
        retry_window_seconds=0.2,
    )
    assert not await dispatcher.dispatch_payment_settled(
        event=event, details=details, settled_at=settled_at
    )
    delivery = (await storage.list_deliveries(page=1, page_size=10))["items"][0]
    with pytest.raises(ValueError, match="in progress"):
        await dispatcher.replay_delivery(delivery)
    await asyncio.sleep(0.3)
    await _cancel_retry_tasks(dispatcher)

    assert calls == 2
    refreshed = await storage.get_delivery(int(delivery["id"]))
    assert refreshed is not None and refreshed["status"] == "failed"
    attempts = await storage.list_delivery_attempts(int(delivery["id"]))
    assert [item["attempt_number"] for item in attempts] == [1, 2]


async def _exercise_two_dispatchers_share_one_persistent_retry_claim(tmp_path) -> None:
    db_path, address_store, seed_storage, event, details, settled_at = (
        await _seed_retry_authority(tmp_path, "persistent-retry-claim.db")
    )

    async def fail_seed(_url, _payload, _headers):
        raise RuntimeError("seed retryable state")

    seed_dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=seed_storage,
        sender=fail_seed,
        max_retries=1,
        retry_window_seconds=60,
    )
    assert not await seed_dispatcher.dispatch_payment_settled(
        event=event, details=details, settled_at=settled_at
    )
    await _cancel_retry_tasks(seed_dispatcher)

    calls = 0

    async def succeed_once(_url, _payload, _headers):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.05)

    storages = [RequestLogStorage(db_path), RequestLogStorage(db_path)]
    dispatchers = [
        WebhookDispatcher(
            address_store=address_store,
            delivery_storage=storage,
            sender=succeed_once,
            max_retries=1,
            retry_window_seconds=0.02,
        )
        for storage in storages
    ]
    await asyncio.gather(
        *(dispatcher.resume_pending_retries() for dispatcher in dispatchers)
    )
    await asyncio.sleep(0.2)
    for dispatcher in dispatchers:
        await _cancel_retry_tasks(dispatcher)

    assert calls == 1
    delivery = (await seed_storage.list_deliveries(page=1, page_size=10))["items"][0]
    refreshed = await seed_storage.get_delivery(int(delivery["id"]))
    assert refreshed is not None and refreshed["status"] == "delivered"
    attempts = await seed_storage.list_delivery_attempts(int(delivery["id"]))
    assert [item["attempt_number"] for item in attempts] == [1, 2]


def test_restart_wakes_retry_after_crash_claim_expires(tmp_path):
    asyncio.run(_exercise_restart_wakes_retry_after_crash_claim_expires(tmp_path))


async def _exercise_restart_wakes_retry_after_crash_claim_expires(tmp_path):
    db_path, address_store, storage, event, details, settled_at = (
        await _seed_retry_authority(tmp_path, "expired-crash-claim.db")
    )

    async def fail_seed(_url, _payload, _headers):
        raise RuntimeError("seed")

    seed = WebhookDispatcher(
        address_store=address_store, delivery_storage=storage, sender=fail_seed,
        max_retries=2, retry_window_seconds=60,
    )
    assert not await seed.dispatch_payment_settled(
        event=event, details=details, settled_at=settled_at
    )
    await _cancel_retry_tasks(seed)
    delivery = (await storage.list_deliveries(page=1, page_size=10))["items"][0]
    expires = (datetime.now(tz=timezone.utc) + timedelta(seconds=0.15)).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE webhook_deliveries SET claim_token='crashed', claim_expires_at=?, "
            "claim_attempt_number=2 WHERE id=?",
            (expires, delivery["id"]),
        )

    calls = 0

    async def succeed(_url, _payload, _headers):
        nonlocal calls
        calls += 1

    restarted = WebhookDispatcher(
        address_store=address_store, delivery_storage=RequestLogStorage(db_path),
        sender=succeed, max_retries=2, retry_window_seconds=0.1,
    )
    assert await restarted.resume_pending_retries() == 1
    await asyncio.sleep(0.35)
    await _cancel_retry_tasks(restarted)
    assert calls == 1


async def _exercise_manual_replay_cannot_overlap_initial_claim(tmp_path) -> None:
    _, address_store, storage, event, details, settled_at = (
        await _seed_retry_authority(tmp_path, "initial-delivery-claim.db")
    )
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def sender(_url, _payload, _headers):
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()

    dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=storage,
        sender=sender,
        max_retries=1,
        retry_window_seconds=0.2,
    )
    initial = asyncio.create_task(
        dispatcher.dispatch_payment_settled(
            event=event, details=details, settled_at=settled_at
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=1)
    delivery = (await storage.list_deliveries(page=1, page_size=10))["items"][0]
    with pytest.raises(ValueError, match="in progress"):
        await dispatcher.replay_delivery(delivery)
    release.set()
    assert await initial

    assert calls == 1
    attempts = await storage.list_delivery_attempts(int(delivery["id"]))
    assert [item["attempt_number"] for item in attempts] == [1]


async def _exercise_manual_replay_rejects_inflight_claim(tmp_path) -> None:
    _, address_store, storage, event, details, settled_at = (
        await _seed_retry_authority(tmp_path, "inflight-retry-claim.db")
    )
    entered_retry = asyncio.Event()
    release_retry = asyncio.Event()
    calls = 0

    async def sender(_url, _payload, _headers):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("seed")
        entered_retry.set()
        await release_retry.wait()

    dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=storage,
        sender=sender,
        max_retries=1,
        retry_window_seconds=0.02,
    )
    assert not await dispatcher.dispatch_payment_settled(
        event=event, details=details, settled_at=settled_at
    )
    await asyncio.wait_for(entered_retry.wait(), timeout=1)
    delivery = (await storage.list_deliveries(page=1, page_size=10))["items"][0]
    with pytest.raises(ValueError, match="in progress"):
        await dispatcher.replay_delivery(delivery)
    assert calls == 2
    release_retry.set()
    await asyncio.sleep(0.05)
    await _cancel_retry_tasks(dispatcher)
    refreshed = await storage.get_delivery(int(delivery["id"]))
    assert refreshed is not None and refreshed["status"] == "delivered"
    attempts = await storage.list_delivery_attempts(int(delivery["id"]))
    assert [item["attempt_number"] for item in attempts] == [1, 2]


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
    assert delivery["payload"] is None
    target_reference = f"webhook:{hashlib.sha256(b'https://hooks.example.com/payments').hexdigest()[:16]}"
    assert delivery["target"] == target_reference
    assert delivery["last_attempt"]["success"] is True
    delivery_logs = [entry for entry in await storage.get_recent() if entry["event"] == "webhook_delivery"]
    assert len(delivery_logs) == 1
    delivery_log = delivery_logs[0]
    assert delivery_log["status"] == "ok"
    assert delivery_log["username"] == "webhook"
    assert delivery_log["domain"] is None
    assert delivery_log["amount_msat"] is None
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
    settled_at = datetime.now(tz=timezone.utc)
    await storage.log_invoice_event(
        username=event.username,
        domain=event.domain,
        amount_msat=event.amount_msat,
        ip=event.ip,
        payment_hash=event.payment_hash,
        payment_request=event.payment_request,
        details=details,
        request_log_id=event.request_log_id,
    )
    await storage.apply_invoice_event_update(
        event=event,
        details=details,
        settled=True,
        expired=False,
        next_check=None,
        expires_at=None,
        interval_seconds=event.check_interval_seconds,
        settled_at=settled_at,
    )

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
    assert delivery["payload"] is None
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
    assert captured[0]["payload"]["event"] == "payment.settled"
    assert captured[0]["payload"]["payment_request"] == event.payment_request

    attempts = await storage.list_delivery_attempts(int(delivery["id"]))
    assert [attempt["attempt_number"] for attempt in attempts] == [1, 2]
    assert [attempt["success"] for attempt in attempts] == [False, True]
    delivery_after = await storage.get_delivery(int(delivery["id"]))
    assert delivery_after is not None
    assert delivery_after["status"] == "delivered"
    delivery_logs = [entry for entry in await storage.get_recent() if entry["event"] == "webhook_delivery"]
    assert [entry["details"]["delivery_status"] for entry in delivery_logs] == ["retrying", "delivered"]
    assert [entry["details"]["attempt_number"] for entry in delivery_logs] == [1, 2]
