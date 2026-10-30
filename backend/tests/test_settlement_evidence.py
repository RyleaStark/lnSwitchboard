"""Local LND evidence is durable before any signed settlement delivery."""
import asyncio
import copy
import pytest

from backend.app.invoice_worker import InvoiceSubscriptionWorker, refresh_invoice_statuses
from backend.app.log_storage import RequestLogStorage


PROOF = {
    "version": 1,
    "settlement_source": "local_lnd",
    "amount_paid_msat": 2200,
    "settle_date": 1790000000,
}


def test_poll_and_subscription_persist_actual_evidence_before_dispatch(tmp_path):
    async def exercise(mode):
        path = tmp_path / f"{mode}.db"
        storage = RequestLogStorage(path)
        payment_hash = "ab" * 32
        await storage.log_invoice_event(
            username="pay", domain="testserver", amount_msat=2000, ip="127.0.0.1",
            payment_hash=payment_hash, payment_request="lnbc1test", details={"invoice": {}},
            request_log_id=None, expires_at=None,
        )
        snapshot = {"r_hash": bytes.fromhex(payment_hash), "settled": True, "state": "SETTLED",
                    "amt_paid_msat": 2200, "settle_date": 1790000000}
        dispatched = []

        class Dispatcher:
            async def dispatch_payment_settled(self, *, event, details, settled_at):
                # A new connection sees the commit before any webhook is queued/sent.
                saved = await RequestLogStorage(path).get_invoice_event_by_hash(payment_hash)
                assert saved.details["invoice"]["settlement_proof"] == PROOF
                assert details["invoice"]["settlement_proof"] == PROOF
                dispatched.append(event.id)

        class Client:
            async def lookup_invoice(self, payment_hash):
                return snapshot

        if mode == "poll":
            await refresh_invoice_statuses(storage, Client(), webhook_dispatcher=Dispatcher())
        else:
            worker = InvoiceSubscriptionWorker(storage, Client(), webhook_dispatcher=Dispatcher())
            await worker._apply_snapshot(snapshot)
        assert len(dispatched) == 1
        saved = await RequestLogStorage(path).get_invoice_event_by_hash(payment_hash)
        assert saved.details["invoice"]["settlement_proof"] == PROOF
        assert saved.amount_msat == 2000

    for mode in ("poll", "subscription"):
        asyncio.run(exercise(mode))


def test_signed_delivery_restart_and_manual_replay_preserve_proof(tmp_path):
    import hashlib
    import hmac
    from backend.app.ln_address_store import LNAddressStore
    from backend.app.webhook_dispatcher import WebhookDispatcher

    async def exercise():
        path = tmp_path / "replay.db"
        storage = RequestLogStorage(path)
        addresses = LNAddressStore(path)
        address = await addresses.add_address(
            local_part="pay", domain="testserver", min_sendable_sat=None, max_sendable_sat=None,
            metadata_description=None, success_message=None, webhook_urls=[],
            webhook_endpoints=[{"url": "https://hooks.example.com/paid", "secret": "test-only-secret"}],
        )
        payment_hash = "ab" * 32
        await storage.log_invoice_event(
            username="pay", domain="testserver", amount_msat=2000, ip="127.0.0.1",
            payment_hash=payment_hash, payment_request="lnbc1test", request_log_id=None,
            expires_at=None, details={"address_override": {"id": address["id"]}, "invoice": {}},
        )
        payloads = []

        async def sender(url, payload, headers):
            assert payload["settlement_proof"] == PROOF
            assert payload["amount_msat"] == 2000
            assert payload["version"] == "1"
            body = WebhookDispatcher._payload_body(payload)
            signed = f'{headers["X-LnSwitchboard-Signature-Timestamp"]}.{headers["X-LnSwitchboard-Delivery-Id"]}.{body}'
            expected = hmac.new(b"test-only-secret", signed.encode(), hashlib.sha256).hexdigest()
            assert headers["X-LnSwitchboard-Signature"] == f"sha256={expected}"
            payloads.append(payload)

        dispatcher = WebhookDispatcher(address_store=addresses, delivery_storage=storage,
                                       sender=sender, max_retries=0)
        worker = InvoiceSubscriptionWorker(storage, None, webhook_dispatcher=dispatcher)
        await worker._apply_snapshot({"r_hash": bytes.fromhex(payment_hash), "settled": True,
                                      "state": "SETTLED", "amt_paid_msat": 2200,
                                      "settle_date": 1790000000})
        assert len(payloads) == 1
        deliveries = await storage.list_deliveries(page=1, page_size=10)
        delivery = await storage.get_delivery(deliveries["items"][0]["id"])
        restarted_storage = RequestLogStorage(path)
        restarted = WebhookDispatcher(address_store=LNAddressStore(path),
                                      delivery_storage=restarted_storage, sender=sender)
        assert await restarted.replay_delivery(delivery)
        await restarted_storage.update_delivery_status(delivery_id=delivery["id"], status="retrying")
        assert await restarted.resume_pending_retries() == 1
        for _ in range(100):
            if len(payloads) == 3:
                break
            await asyncio.sleep(0.01)
        assert len(payloads) == 3
        assert payloads[0] == payloads[1] == payloads[2]

    asyncio.run(exercise())


@pytest.mark.parametrize("key,value", [
    ("state", "OPEN"), ("state", 1), ("settled", 1),
    ("amt_paid_msat", None), ("amt_paid_msat", 0), ("amt_paid_msat", -1),
    ("amt_paid_msat", True), ("amt_paid_msat", "2200"), ("amt_paid_msat", 2200.0),
    ("amt_paid_msat", 9007199254740992),
    ("settle_date", None), ("settle_date", 0), ("settle_date", -1),
    ("settle_date", True), ("settle_date", "1790000000"),
    ("settle_date", 253402300800),
])
def test_invalid_snapshots_never_mint_proof(key, value):
    from backend.app.invoice_worker import _merge_invoice_snapshot
    snapshot = {"state": "SETTLED", "settled": True,
                "amt_paid_msat": 2200, "settle_date": 1790000000}
    snapshot[key] = value
    details = _merge_invoice_snapshot({}, snapshot, settled=True, expired=False)
    assert "settlement_proof" not in details["invoice"]


def test_test_delivery_cannot_claim_local_payment():
    from backend.app.webhook_dispatcher import WebhookDispatcher

    async def exercise():
        sent = []

        async def sender(url, payload, headers):
            sent.append(payload)

        dispatcher = WebhookDispatcher(address_store=None, sender=sender)
        supplied = {"event": "payment.settled", "settlement_proof": copy.deepcopy(PROOF)}
        assert await dispatcher.dispatch_test(url="https://hooks.example.com/test", payload=supplied)
        assert "settlement_proof" not in sent[0]
        assert supplied["settlement_proof"] == PROOF

    asyncio.run(exercise())


@pytest.mark.parametrize("routing", [
    {"forwarded": True}, {"settlement_source": "remote_verify"},
    {"settlement_source": "unknown"},
])
def test_remote_routes_cannot_relabel_local_evidence(routing):
    from backend.tests.test_webhook_dispatcher import _make_event
    from backend.app.invoice_worker import _merge_invoice_snapshot
    from backend.app.webhook_dispatcher import WebhookDispatcher
    event, details = _make_event({"id": "address", "local_part": "pay", "domain": "testserver"})
    details.update(routing)
    snapshot = {"state": "SETTLED", "settled": True,
                "amt_paid_msat": 2200, "settle_date": 1790000000}
    merged = _merge_invoice_snapshot(copy.deepcopy(details), snapshot, settled=True, expired=False)
    assert "settlement_proof" not in merged["invoice"]
    details["invoice"].update({"state": "SETTLED", "settled": True,
                               "settlement_proof": copy.deepcopy(PROOF)})
    dispatcher = WebhookDispatcher(address_store=None)
    payload = dispatcher._build_payload(event=event, details=details, address={}, settled_at=None)
    assert "settlement_proof" not in payload
