"""Synthetic authenticated client API lifecycle; never calls a live node."""
import asyncio
import hashlib

import pytest

from backend.app.config import get_settings
from backend.app.deps import _get_log_storage
from backend.app.ln_client import LNClient
from backend.app.sqlite_utils import sqlite_connection

from .conftest import SimpleTestClient


def test_client_provisioning_auth_scope_ownership_and_revocation():
    with SimpleTestClient() as client:
        missing = client.post("/api/client/v1/addresses", json={"external_user_ref": "opaque-user-00000001"},
                              headers={"Idempotency-Key": "address-request-1"})
        assert missing.status_code == 401
        configured = client.post("/api/client-credentials", json={
            "domain": "pay.example.com", "webhook_url": "https://billing.example.com/bridge",
            "webhook_secret": "synthetic-webhook-secret-00000000",
            "scopes": ["addresses:create", "addresses:read_own", "invoices:create"],
        })
        assert configured.status_code == 201
        issued = configured.json()
        assert configured.headers["cache-control"] == "no-store, private"
        headers = {"Authorization": f'Bearer {issued["token"]}', "Idempotency-Key": "address-request-1"}
        created = client.post("/api/client/v1/addresses", headers=headers,
                              json={"external_user_ref": "opaque-user-00000001"})
        assert created.status_code == 201
        address = created.json()
        assert address["ln_address"].endswith("@pay.example.com")
        replay = client.post("/api/client/v1/addresses", headers=headers,
                             json={"external_user_ref": "opaque-user-00000001"})
        assert replay.json() == address
        changed = client.post("/api/client/v1/addresses", headers=headers,
                              json={"external_user_ref": "opaque-user-00000002"})
        assert changed.status_code == 409
        own = client.get(f'/api/client/v1/addresses/{address["address_id"]}', headers=headers)
        assert own.json() == address
        listed = client.get("/api/client-credentials")
        assert issued["token"] not in listed.text
        assert "synthetic-webhook-secret" not in listed.text
        assert client.delete(f'/api/client-credentials/{issued["client_id"]}').status_code == 204
        assert client.get(f'/api/client/v1/addresses/{address["address_id"]}', headers=headers).status_code == 401


@pytest.mark.parametrize("days", [14, 30])
def test_fixed_invoice_timeout_reconciliation_and_authoritative_dates(monkeypatch, days):
    node = {}
    calls = []
    secrets_seen = []

    async def lookup(self, payment_hash):
        key = payment_hash.hex()
        if key not in node:
            raise LookupError("synthetic missing")
        return node[key]

    async def add(self, *, amount_msat, memo, expiry_seconds, r_preimage):
        assert memo == "lnSwitchboard client invoice"
        assert expiry_seconds == days * 86400
        assert len(r_preimage) == 32
        payment_hash = hashlib.sha256(r_preimage).hexdigest()
        event = await _get_log_storage().get_invoice_event_by_hash(payment_hash)
        assert event is not None
        assert event.details["address_override"]["id"] == address["address_id"]
        assert event.details["client_invoice"]["quote_id"] == "quote-0001"
        with sqlite_connection(get_settings().data_store_path) as db:
            request = db.execute("SELECT * FROM api_client_requests WHERE payment_hash=?", (payment_hash,)).fetchone()
            assert request is not None
            encrypted = db.execute("SELECT ciphertext FROM connection_secrets WHERE owner_id=?",
                                   (f'api-invoice:{request["id"]}',)).fetchone()[0]
            assert r_preimage not in encrypted
            assert r_preimage.hex().encode() not in encrypted
        calls.append(payment_hash)
        secrets_seen.append(r_preimage.hex())
        node[payment_hash] = {"r_hash": bytes.fromhex(payment_hash), "state": "OPEN", "settled": False,
                              "creation_date": 1790000000, "expiry": expiry_seconds,
                              "payment_request": "lnbc1-synthetic-fixed-invoice"}
        raise TimeoutError("synthetic AddInvoice reply lost")

    monkeypatch.setattr(LNClient, "lookup_invoice", lookup)
    monkeypatch.setattr(LNClient, "create_invoice", add)
    with SimpleTestClient() as client:
        configured = client.post("/api/client-credentials", json={
            "domain": "pay.example.com", "webhook_url": "https://billing.example.com/bridge",
            "webhook_secret": "synthetic-webhook-secret-00000000",
            "scopes": ["addresses:create", "addresses:read_own", "invoices:create"],
        }).json()
        headers = {"Authorization": f'Bearer {configured["token"]}', "Idempotency-Key": "address-request-1"}
        address = client.post("/api/client/v1/addresses", headers=headers,
                              json={"external_user_ref": "opaque-user-00000001"}).json()
        path = f'/api/client/v1/addresses/{address["address_id"]}/invoices'
        headers["Idempotency-Key"] = "invoice-request-1"
        body = {"quote_id": "quote-0001", "amount_msat": 2000, "expiry_days": days}
        first = client.post(path, headers=headers, json=body)
        assert first.status_code == 503
        second = client.post(path, headers=headers, json=body)
        assert second.status_code == 201
        result = second.json()
        assert result == {"address_id": address["address_id"], "quote_id": "quote-0001",
                          "amount_msat": 2000, "payment_hash": calls[0],
                          "bolt11": "lnbc1-synthetic-fixed-invoice",
                          "created_at": 1790000000, "expires_at": 1790000000 + days * 86400}
        assert client.post(path, headers=headers, json=body).json() == result
        assert len(calls) == 1
        with sqlite_connection(get_settings().data_store_path) as db:
            assert db.execute("SELECT COUNT(*) FROM connection_secrets WHERE owner_id LIKE 'api-invoice:%'").fetchone()[0] == 1
        assert client.post(path, headers=headers, json={**body, "amount_msat": 3000}).status_code == 409
        assert secrets_seen[0] not in second.text
        event = asyncio.run(_get_log_storage().get_invoice_event_by_hash(calls[0]))
        assert event.payment_request == result["bolt11"]
        assert event.details["client_invoice"]["creation_pending"] is False

        from backend.app.invoice_worker import InvoiceSubscriptionWorker
        from backend.app.webhook_dispatcher import WebhookDispatcher
        from backend.app.deps import _get_ln_address_store
        observed = []

        async def sender(url, payload, headers):
            assert url == "https://billing.example.com/bridge"
            assert payload["invoice_binding"] == {
                "version": 1, "client_id": configured["client_id"],
                "address_id": address["address_id"], "quote_id": "quote-0001",
            }
            assert payload["settlement_proof"]["amount_paid_msat"] == 2500
            import hmac
            body = WebhookDispatcher._payload_body(payload)
            signed = f'{headers["X-LnSwitchboard-Signature-Timestamp"]}.{headers["X-LnSwitchboard-Delivery-Id"]}.{body}'
            expected = hmac.new(b"synthetic-webhook-secret-00000000", signed.encode(), hashlib.sha256).hexdigest()
            assert headers["X-LnSwitchboard-Signature"] == f"sha256={expected}"
            observed.append(payload)

        async def settle():
            dispatcher = WebhookDispatcher(address_store=_get_ln_address_store(),
                delivery_storage=_get_log_storage(), sender=sender, max_retries=0)
            worker = InvoiceSubscriptionWorker(_get_log_storage(), None, webhook_dispatcher=dispatcher)
            await worker._apply_snapshot({**node[calls[0]], "state": "SETTLED", "settled": True,
                                          "amt_paid_msat": 2500, "settle_date": 1790000100})
            assert len(observed) == 1
            deliveries = await _get_log_storage().list_deliveries(page=1, page_size=5)
            delivery = await _get_log_storage().get_delivery(deliveries["items"][0]["id"])
            assert await dispatcher.replay_delivery(delivery)
            assert observed[0] == observed[1]

        asyncio.run(settle())


def test_lnd_optional_expiry_and_preimage_are_sent_without_changing_lnurl_defaults(monkeypatch):
    from types import SimpleNamespace
    from backend.app.deps import _get_ln_client
    requests = []

    class Stub:
        async def AddInvoice(self, request, metadata):
            requests.append(request)
            return SimpleNamespace(payment_request="lnbc1-synthetic", r_hash=b"h" * 32)

    async def load(self):
        return Stub()

    async def metadata(self):
        return []

    monkeypatch.setattr(LNClient, "_load_stub", load)
    monkeypatch.setattr(LNClient, "_metadata", metadata)

    async def exercise():
        node = _get_ln_client()
        await node.create_invoice(amount_msat=2000, memo="normal")
        assert requests[-1].expiry == 0
        assert requests[-1].r_preimage == b""
        await node.create_invoice(amount_msat=2000, memo="fixed", expiry_seconds=2592000, r_preimage=b"p" * 32)
        assert requests[-1].expiry == 2592000
        assert requests[-1].r_preimage == b"p" * 32

    asyncio.run(exercise())


def provision_for_test(client, scopes=None):
    issued = client.post("/api/client-credentials", json={
        "domain": "pay.example.com", "webhook_url": "https://billing.example.com/bridge",
        "webhook_secret": "synthetic-webhook-secret-00000000",
        "scopes": scopes or ["addresses:create", "addresses:read_own", "invoices:create"],
    }).json()
    return issued, {"Authorization": f'Bearer {issued["token"]}', "Idempotency-Key": "address-request-1"}


def test_foreign_objects_scopes_validation_and_private_listener(monkeypatch):
    import httpx
    from backend.app.main import admin_app, public_app, require_configured_public_domain
    with SimpleTestClient() as client:
        _issued, headers = provision_for_test(client)
        address = client.post("/api/client/v1/addresses", headers=headers,
                              json={"external_user_ref": "opaque-user-00000001"}).json()
        _foreign, foreign_headers = provision_for_test(client)
        path = f'/api/client/v1/addresses/{address["address_id"]}'
        assert client.get(path, headers=foreign_headers).status_code == 404
        assert client.post(path + "/invoices", headers=foreign_headers,
                           json={"quote_id": "quote-1", "amount_msat": 2000, "expiry_days": 14}).status_code == 404
        _limited, limited_headers = provision_for_test(client, ["addresses:read_own"])
        assert client.post("/api/client/v1/addresses", headers=limited_headers,
                           json={"external_user_ref": "opaque-user-00000001"}).status_code == 403
        invalid = client.post("/api/client-credentials", json={"webhook_secret": "SENTINEL-NO-REFLECTION"})
        assert invalid.status_code == 422
        assert "SENTINEL" not in invalid.text
        assert invalid.headers["cache-control"] == "no-store, private"
        for value in (True, "14", 14.0, 7, 365):
            response = client.post(path + "/invoices", headers=headers,
                                  json={"quote_id": "quote-1", "amount_msat": 2000, "expiry_days": value})
            assert response.status_code == 422
        with sqlite_connection(get_settings().data_store_path) as db:
            assert db.execute("SELECT COUNT(*) FROM api_client_requests WHERE kind='invoice'").fetchone()[0] == 0

        async def check_listeners():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=admin_app, client=("8.8.8.8", 1234)),
                                         base_url="http://testserver") as remote:
                assert (await remote.get(path, headers=headers)).status_code == 403
            public_app.dependency_overrides[require_configured_public_domain] = lambda: None
            try:
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=public_app, client=("192.168.1.3", 1234)),
                                             base_url="http://testserver") as public:
                    assert (await public.get(path, headers=headers)).status_code == 404
                    assert (await public.post("/api/client-credentials", json={})).status_code in (404, 405)
            finally:
                public_app.dependency_overrides.clear()
        asyncio.run(check_listeners())


def test_concurrent_request_lease_is_fenced_and_keys_cannot_change_body():
    from backend.app.client_store import ClientStore
    from backend.app.deps import _get_connection_secret_store
    from fastapi import HTTPException
    with SimpleTestClient() as client:
        issued, _headers = provision_for_test(client)
        store = ClientStore(get_settings().data_store_path, _get_connection_secret_store())
        body = {"quote_id": "quote-1", "amount_msat": 2000, "expiry_days": 14}
        first = store.claim(issued["client_id"], "invoice-request-1", "invoice", body, "logical-quote", resource_id="addr", invoice=True)
        with pytest.raises(HTTPException) as blocked:
            ClientStore(store.path, store.secrets).claim(issued["client_id"], "invoice-request-1", "invoice", body, "logical-quote", resource_id="addr", invoice=True)
        assert blocked.value.status_code == 409
        with sqlite_connection(store.path) as db:
            assert db.execute("SELECT COUNT(*) FROM connection_secrets WHERE owner_id LIKE 'api-invoice:%'").fetchone()[0] == 1
            db.execute("UPDATE api_client_requests SET lease_until=0 WHERE id=?", (first["id"],))
        successor = store.claim(issued["client_id"], "invoice-request-1", "invoice", body, "logical-quote", resource_id="addr", invoice=True)
        assert successor["payment_hash"] == first["payment_hash"]
        with pytest.raises(HTTPException):
            store.finish(first, {"old": True})
        store.finish(successor, {"new": True})
        store.release(first)
        assert store.claim(issued["client_id"], "invoice-request-1", "invoice", body, "logical-quote", resource_id="addr", invoice=True)["result"] == '{"new": true}'


def test_open_client_invoice_survives_short_history_retention(tmp_path):
    from datetime import datetime, timedelta, timezone
    from backend.app.log_storage import RequestLogStorage
    path = tmp_path / "retention.db"

    async def exercise():
        storage = RequestLogStorage(path, retention_days=1)
        now = datetime.now(timezone.utc)
        for index, binding in enumerate(({"client_invoice": {"version": 1}}, {})):
            await storage.log_invoice_event(username="pay", domain="example.com", amount_msat=2000,
                payment_hash=f"{index + 1:064x}", details=binding,
                expires_at=(now + timedelta(days=14)).isoformat())
        with sqlite_connection(path) as db:
            db.execute("UPDATE invoice_events SET created_at=?", ((now - timedelta(days=2)).isoformat(),))
        await storage.cleanup()
        assert await storage.get_invoice_event_by_hash(f"{1:064x}") is not None
        assert await storage.get_invoice_event_by_hash(f"{2:064x}") is None
        with sqlite_connection(path) as db:
            db.execute("UPDATE invoice_events SET expired=1")
        await storage.cleanup()
        assert await storage.get_invoice_event_by_hash(f"{1:064x}") is None

    asyncio.run(exercise())


def test_planned_invoice_lookup_miss_does_not_retire_before_add(tmp_path):
    from backend.app.log_storage import RequestLogStorage
    from backend.app.invoice_worker import refresh_invoice_statuses

    async def exercise():
        storage = RequestLogStorage(tmp_path / "planned.db")
        await storage.log_invoice_event(username="pay", domain="example.com", amount_msat=2000,
            payment_hash="ab" * 32, details={"client_invoice": {"creation_pending": True}})

        class Missing:
            async def lookup_invoice(self, payment_hash):
                raise LookupError("planned invoice not yet added")

        await refresh_invoice_statuses(storage, Missing())
        event = await storage.get_invoice_event_by_hash("ab" * 32)
        assert not event.expired
        assert event.next_check_at is not None

    asyncio.run(exercise())
