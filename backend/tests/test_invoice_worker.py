from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from backend.app.invoice_worker import (
    InvoiceSubscriptionWorker,
    InvoiceFullRefreshWorker,
    refresh_all_pending_invoices,
)
from backend.app.log_storage import RequestLogStorage


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
                assert details.get("r_preimage") == "02" * 32
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
