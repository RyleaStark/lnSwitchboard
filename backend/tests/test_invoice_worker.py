from __future__ import annotations

import asyncio
import json
import stat
from datetime import datetime, timezone

from backend.app.invoice_worker import (
    InvoiceSubscriptionWorker,
    InvoiceFullRefreshWorker,
    refresh_all_pending_invoices,
    refresh_invoice_statuses,
)
from backend.app.log_storage import RequestLogStorage
from backend.app.ln_address_store import LNAddressStore
from backend.app.nostr_crypto import generate_private_key_hex, public_key_from_private_hex, sign_event
from backend.app.nostr_signer_store import NostrSignerStore
from backend.app.nostr_zaps import NostrZapPublisher
from backend.app.version import get_version
from backend.app.webhook_dispatcher import WebhookDispatcher


class DummySubscriptionClient:
    def __init__(self, snapshots):
        self._snapshots = list(snapshots)

    async def subscribe_invoices(self, **kwargs):
        try:
            for item in self._snapshots:
                yield item
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            raise


class DummyLookupClient:
    def __init__(self, records):
        self.records = records
        self.calls: list[str] = []

    async def lookup_invoice(self, payment_hash):
        hex_hash = payment_hash.hex()
        self.calls.append(hex_hash)
        return self.records[hex_hash]


def test_invoice_subscription_worker_marks_settled(tmp_path):
    asyncio.run(_exercise_subscription_worker(tmp_path))


async def _exercise_subscription_worker(tmp_path):
    storage = RequestLogStorage(tmp_path / "worker.db")
    payment_hash = "ab" * 32
    await storage.log_invoice_event(
        username="tester",
        domain="example.com",
        amount_msat=2000,
        ip="127.0.0.1",
        payment_hash=payment_hash,
        payment_request="lnbc1tester",
        details={"invoice": {"payment_hash": payment_hash, "settled": False}},
        request_log_id=None,
        expires_at=None,
    )

    now_ts = int(datetime.now(tz=timezone.utc).timestamp())
    snapshot = {
        "settled": True,
        "r_hash": bytes.fromhex(payment_hash),
        "r_preimage": bytes.fromhex("02" * 32),
        "state": "SETTLED",
        "creation_date": now_ts - 10,
        "expiry": 120,
        "payment_request": "lnbc1tester",
    }

    worker = InvoiceSubscriptionWorker(storage=storage, ln_client=DummySubscriptionClient([snapshot]))
    await worker.start()
    try:
        await asyncio.wait_for(_wait_for_settlement(storage, payment_hash), timeout=1.0)
    finally:
        await worker.stop()


async def _wait_for_settlement(storage: RequestLogStorage, payment_hash: str) -> None:
    for _ in range(50):
        listing = await storage.list_invoice_events(page=1, page_size=5)
        if listing["items"]:
            record = listing["items"][0]
            if record["payment_hash"] == payment_hash and record["settled"]:
                details = record["details"]["invoice"]
                assert details["settled"] is True
                assert "r_preimage" not in details
                return
        await asyncio.sleep(0.05)
    raise AssertionError("Invoice was not marked settled via subscription")


def test_refresh_all_pending_invoices_scans_everything(tmp_path):
    asyncio.run(_exercise_full_refresh(tmp_path))


async def _exercise_full_refresh(tmp_path):
    storage = RequestLogStorage(tmp_path / "full-refresh.db")
    now_ts = int(datetime.now(tz=timezone.utc).timestamp())
    snapshots = {}
    for idx in range(3):
        payment_hash = f"{idx + 1:064x}"
        await storage.log_invoice_event(
            username="tester",
            domain="example.com",
            amount_msat=2000 + idx,
            ip="127.0.0.1",
            payment_hash=payment_hash,
            payment_request=f"req-{idx}",
            details={"invoice": {"payment_hash": payment_hash, "settled": False}},
            request_log_id=None,
            expires_at=None,
        )
        snapshots[payment_hash] = {
            "settled": idx % 2 == 0,
            "r_hash": bytes.fromhex(payment_hash),
            "payment_request": f"req-{idx}",
            "state": "SETTLED" if idx % 2 == 0 else "OPEN",
            "creation_date": now_ts - 60,
            "expiry": 120,
        }

    client = DummyLookupClient(snapshots)
    processed = await refresh_all_pending_invoices(storage, client, batch_size=2)
    assert processed == len(snapshots)
    assert sorted(client.calls) == sorted(snapshots.keys())
    listing = await storage.list_invoice_events(page=1, page_size=10)
    items = {item["payment_hash"]: item for item in listing["items"]}
    for payment_hash, snapshot in snapshots.items():
        record = items[payment_hash]
        assert record["settled"] is snapshot["settled"]
    assert record["details"]["invoice"]["settled"] is snapshot["settled"]


def test_refresh_all_pending_invoices_skips_expired(tmp_path):
    asyncio.run(_exercise_full_refresh_skip_expired(tmp_path))


async def _exercise_full_refresh_skip_expired(tmp_path):
    storage = RequestLogStorage(tmp_path / "full-refresh-skip.db")
    hashes = ["aa" * 32, "bb" * 32]
    for idx, payment_hash in enumerate(hashes):
        await storage.log_invoice_event(
            username="tester",
            domain="example.com",
            amount_msat=1000 + idx,
            ip="127.0.0.1",
            payment_hash=payment_hash,
            payment_request=f"req-{idx}",
            details={"invoice": {"payment_hash": payment_hash, "settled": False}},
            request_log_id=None,
            expires_at=None,
        )

    events = await storage.get_unsettled_invoice_events(limit=10)
    expired_event = next(event for event in events if event.payment_hash == hashes[0])
    await storage.apply_invoice_event_update(
        event=expired_event,
        details=expired_event.details,
        settled=False,
        expired=True,
        next_check=None,
        expires_at=None,
        interval_seconds=0,
        settled_at=None,
    )

    snapshots = {
        hashes[1]: {
            "settled": True,
            "r_hash": bytes.fromhex(hashes[1]),
            "payment_request": "req-1",
            "state": "SETTLED",
            "creation_date": int(datetime.now(tz=timezone.utc).timestamp()) - 60,
            "expiry": 120,
        }
    }
    client = DummyLookupClient(snapshots)
    processed = await refresh_all_pending_invoices(storage, client, batch_size=5)
    assert processed == 1
    assert client.calls == [hashes[1]]


def test_full_refresh_worker_runs_on_startup(tmp_path):
    asyncio.run(_exercise_full_refresh_worker(tmp_path))


async def _exercise_full_refresh_worker(tmp_path):
    storage = RequestLogStorage(tmp_path / "full-refresh-worker.db")
    payment_hash = "ef" * 32
    await storage.log_invoice_event(
        username="tester",
        domain="example.com",
        amount_msat=4000,
        ip="127.0.0.1",
        payment_hash=payment_hash,
        payment_request="req",
        details={"invoice": {"payment_hash": payment_hash, "settled": False}},
        request_log_id=None,
        expires_at=None,
    )

    class StaticLookupClient(DummyLookupClient):
        def __init__(self):
            super().__init__({})

        async def lookup_invoice(self, payment_hash_bytes):
            return {
                "settled": True,
                "r_hash": payment_hash_bytes,
                "payment_request": "req",
                "state": "SETTLED",
                "creation_date": int(datetime.now(tz=timezone.utc).timestamp()) - 60,
                "expiry": 120,
            }

    worker = InvoiceFullRefreshWorker(
        storage=storage,
        ln_client=StaticLookupClient(),
        interval_seconds=1,
        batch_size=1,
    )
    await worker.start()
    try:
        listing = await storage.list_invoice_events(page=1, page_size=1)
        assert listing["items"][0]["settled"] is True
    finally:
        await worker.stop()


def test_webhook_dispatch_on_settlement(tmp_path):
    asyncio.run(_exercise_webhook_dispatch(tmp_path))


async def _exercise_webhook_dispatch(tmp_path):
    db_path = tmp_path / "webhooks.db"
    storage = RequestLogStorage(db_path)
    address_store = LNAddressStore(db_path)
    address = await address_store.add_address(
        local_part="pay",
        domain="testserver",
        min_sendable_sat=None,
        max_sendable_sat=None,
        metadata_description=None,
        success_message=None,
        webhook_urls=[
            "https://hooks.example.com/payments",
            "https://hooks.example.com/audit",
        ],
    )
    payment_hash = "be" * 32
    details = {
        "ln_address": "pay+vip@testserver",
        "username_raw": "pay+vip",
        "domain": "testserver",
        "payment_hash": payment_hash,
        "address_override": {
            "id": address["id"],
            "local_part": address["local_part"],
            "domain": address["domain"],
        },
        "invoice": {"payment_hash": payment_hash, "settled": False},
    }
    await storage.log_invoice_event(
        username="pay",
        domain="testserver",
        amount_msat=2000,
        ip="127.0.0.1",
        payment_hash=payment_hash,
        payment_request="lnbc1test",
        details=details,
        request_log_id=None,
        expires_at=None,
    )
    events = await storage.get_due_invoice_events(limit=5)

    class SettledLookupClient:
        async def lookup_invoice(self, payment_hash_bytes):
            return {
                "settled": True,
                "r_hash": payment_hash_bytes,
                "payment_request": "lnbc1test",
            }

    captured = []

    async def fake_sender(url, payload, headers):
        captured.append({"url": url, "payload": payload, "headers": headers})

    dispatcher = WebhookDispatcher(address_store=address_store, sender=fake_sender)
    await refresh_invoice_statuses(
        storage,
        SettledLookupClient(),
        events=events,
        webhook_dispatcher=dispatcher,
    )
    assert {call["url"] for call in captured} == {
        "https://hooks.example.com/payments",
        "https://hooks.example.com/audit",
    }
    delivery = captured[0]
    payload = delivery["payload"]
    assert payload["event"] == "payment.settled"
    assert payload["ln_address"] == "pay+vip@testserver"
    assert payload["tag"] == "vip"
    assert payload["amount_msat"] == 2000
    assert payload["amount_sat"] == 2
    assert payload["payment_hash"] == payment_hash
    assert payload["payment_request"] == "lnbc1test"
    assert payload["address_id"] == address["id"]
    assert payload["invoice_event_id"] == events[0].id
    assert payload["source"] == "lnswitchboard"
    assert payload["version"] == "1"
    assert payload["settled_at"].endswith("+00:00")
    headers = delivery["headers"]
    assert headers["User-Agent"] == f"lnSwitchboard/{get_version()}"
    assert headers["X-LnSwitchboard-Event"] == "payment.settled"
    assert headers["X-LnSwitchboard-Version"] == get_version()
    assert headers["X-LnSwitchboard-Address-Id"] == address["id"]


def test_forwarded_webhook_dispatch_on_remote_verify(monkeypatch, tmp_path):
    async def fake_verify(verify_url):
        assert verify_url == "https://wallet.example/verify"
        return {
            "status": "OK",
            "settled": True,
            "preimage": "aa" * 32,
            "pr": "lnbc1forward",
        }

    monkeypatch.setattr("backend.app.invoice_worker.fetch_forwarding_verify", fake_verify)
    asyncio.run(_exercise_forwarded_webhook_dispatch(tmp_path))


async def _exercise_forwarded_webhook_dispatch(tmp_path):
    db_path = tmp_path / "forwarded-webhooks.db"
    storage = RequestLogStorage(db_path)
    address_store = LNAddressStore(db_path)
    address = await address_store.add_address(
        local_part="pay",
        domain="testserver",
        routing_mode="forward",
        forward_to="bones@walletofsatoshi.com",
        min_sendable_sat=None,
        max_sendable_sat=None,
        metadata_description=None,
        success_message=None,
        webhook_urls=["https://hooks.example.com/forwarded"],
    )
    details = {
        "forwarded": True,
        "forward_to": "bones@walletofsatoshi.com",
        "settlement_source": "remote_verify",
        "verify_url": "https://wallet.example/verify",
        "ln_address": "pay@testserver",
        "username_raw": "pay",
        "domain": "testserver",
        "address_override": {
            "id": address["id"],
            "local_part": address["local_part"],
            "domain": address["domain"],
            "routing_mode": "forward",
            "forward_to": "bones@walletofsatoshi.com",
        },
        "invoice": {"payment_request": "lnbc1forward", "settled": False},
    }
    await storage.log_invoice_event(
        username="pay",
        domain="testserver",
        amount_msat=2000,
        ip="127.0.0.1",
        payment_hash=None,
        payment_request="lnbc1forward",
        details=details,
        request_log_id=None,
        expires_at=None,
    )
    events = await storage.get_due_invoice_events(limit=5)

    captured = []

    async def fake_sender(url, payload, headers):
        captured.append({"url": url, "payload": payload, "headers": headers})

    dispatcher = WebhookDispatcher(address_store=address_store, sender=fake_sender)
    await refresh_invoice_statuses(
        storage,
        DummyLookupClient({}),
        events=events,
        webhook_dispatcher=dispatcher,
    )

    assert len(captured) == 1
    delivery = captured[0]
    assert delivery["url"] == "https://hooks.example.com/forwarded"
    payload = delivery["payload"]
    assert payload["event"] == "payment.settled"
    assert payload["forwarded"] is True
    assert payload["forward_to"] == "bones@walletofsatoshi.com"
    assert payload["settlement_source"] == "remote_verify"
    assert payload["ln_address"] == "pay@testserver"


def test_zap_receipt_delivery_on_settlement(tmp_path):
    asyncio.run(_exercise_zap_receipt_delivery_on_settlement(tmp_path))


async def _exercise_zap_receipt_delivery_on_settlement(tmp_path):
    db_path = tmp_path / "zap-receipts.db"
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
    )
    signer_store = NostrSignerStore(tmp_path / "zap-signer.hex")
    signer = await signer_store.generate()
    assert signer.pubkey
    assert stat.S_IMODE((tmp_path / "zap-signer.hex").stat().st_mode) == 0o600
    zapper_secret = generate_private_key_hex()
    recipient_pubkey = public_key_from_private_hex(generate_private_key_hex())
    zap_request_event = sign_event(
        {
            "kind": 9734,
            "created_at": 1_714_566_896,
            "tags": [
                ["p", recipient_pubkey],
                ["amount", "2000"],
                ["relays", "wss://relay.example.com"],
            ],
            "content": "",
        },
        zapper_secret,
    )
    payment_hash = "cd" * 32
    details = {
        "ln_address": "pay@testserver",
        "username_raw": "pay",
        "domain": "testserver",
        "payment_hash": payment_hash,
        "address_override": {
            "id": address["id"],
            "local_part": address["local_part"],
            "domain": address["domain"],
        },
        "zap_request": {
            "event": zap_request_event,
            "event_id": zap_request_event["id"],
            "pubkey": zap_request_event["pubkey"],
            "recipient_pubkey": recipient_pubkey,
            "relays": ["wss://relay.example.com"],
            "raw": json.dumps(zap_request_event, separators=(",", ":")),
        },
        "invoice": {"payment_hash": payment_hash, "settled": False},
    }
    await storage.log_invoice_event(
        username="pay",
        domain="testserver",
        amount_msat=2000,
        ip="127.0.0.1",
        payment_hash=payment_hash,
        payment_request="lnbc1zap",
        details=details,
        request_log_id=None,
        expires_at=None,
    )
    events = await storage.get_due_invoice_events(limit=5)
    published = []

    async def relay_sender(url, receipt):
        published.append({"url": url, "receipt": receipt})

    dispatcher = WebhookDispatcher(
        address_store=address_store,
        delivery_storage=storage,
        zap_publisher=NostrZapPublisher(
            signer_store=signer_store,
            storage=storage,
            sender=relay_sender,
        ),
    )

    class SettledLookupClient:
        async def lookup_invoice(self, payment_hash_bytes):
            return {
                "settled": True,
                "r_hash": payment_hash_bytes,
                "r_preimage": bytes.fromhex("44" * 32),
                "payment_request": "lnbc1zap",
            }

    await refresh_invoice_statuses(
        storage,
        SettledLookupClient(),
        events=events,
        webhook_dispatcher=dispatcher,
    )

    assert len(published) == 1
    receipt = published[0]["receipt"]
    assert published[0]["url"] == "wss://relay.example.com"
    assert receipt["kind"] == 9735
    assert receipt["pubkey"] == signer.pubkey
    assert ["bolt11", "lnbc1zap"] in receipt["tags"]
    assert ["preimage", "44" * 32] in receipt["tags"]
    deliveries = await storage.list_deliveries(page=1, page_size=5)
    assert deliveries["items"][0]["kind"] == "nostr.relay"
    assert deliveries["items"][0]["status"] == "delivered"
