"""Operator adoption of existing LN addresses, using only disposable local state."""
import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException

from backend.app.client_store import ClientStore
from backend.app.config import get_settings
from backend.app.deps import _get_connection_secret_store, _get_ln_address_store, _get_log_storage
from backend.app.main import admin_app, client_only_app, public_app, require_configured_public_domain
from backend.app.sqlite_utils import sqlite_connection
from .conftest import SimpleTestClient


def provision(client, domain="pay.example.com", scopes=None):
    issued = client.post("/api/client-credentials", json={
        "domain": domain, "webhook_url": "https://billing.example.com/bridge",
        "webhook_secret": "synthetic-webhook-secret-00000000",
        "scopes": scopes or ["addresses:create", "addresses:read_own", "invoices:create"],
    })
    assert issued.status_code == 201
    return issued.json()


def address(local_part="paycf", domain="pay.example.com", routing_mode="local"):
    return asyncio.run(_get_ln_address_store().add_address(
        local_part=local_part, domain=domain, routing_mode=routing_mode,
        min_sendable_sat=None, max_sendable_sat=None, metadata_description=None,
        success_message=None, webhook_urls=["https://guestlist.example.com/callback"],
    ))


def snapshot():
    _get_log_storage()
    with sqlite_connection(get_settings().data_store_path) as db:
        return {table: [tuple(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                for table in ("ln_addresses", "invoice_events", "webhook_deliveries", "api_client_requests")}


def test_scoped_get_verifies_adopted_user_ref_hash_without_mutating_state():
    with SimpleTestClient() as client:
        issued = provision(client)
        original = address()
        ref = "opaque-user-00000012"
        adopted = client.post(f'/api/client-credentials/{issued["client_id"]}/addresses/adopt',
                              json={"address_id": original["id"], "external_user_ref": ref})
        assert adopted.status_code == 201
        path = f'/api/client/v1/addresses/{original["id"]}'
        headers = {"Authorization": f'Bearer {issued["token"]}'}
        before = snapshot()
        with sqlite_connection(get_settings().data_store_path) as db:
            owners_before = [tuple(row) for row in db.execute("SELECT * FROM api_owned_addresses")]
        result = client.get(path, params={"user_ref_hash": hashlib.sha256(ref.encode()).hexdigest()}, headers=headers)
        assert result.status_code == 200
        assert result.json() == adopted.json() == {"address_id": original["id"],
                                                    "ln_address": "paycf@pay.example.com"}
        assert result.headers["cache-control"] == "no-store, private"
        assert client.get(path, headers=headers).json() == adopted.json()
        with sqlite_connection(get_settings().data_store_path) as db:
            assert [tuple(row) for row in db.execute("SELECT * FROM api_owned_addresses")] == owners_before
        assert snapshot() == before


def test_scoped_get_rejects_wrong_and_malformed_user_ref_hash_with_generic_404():
    with SimpleTestClient() as client:
        issued = provision(client)
        original = address()
        assert client.post(f'/api/client-credentials/{issued["client_id"]}/addresses/adopt',
                           json={"address_id": original["id"],
                                 "external_user_ref": "opaque-user-00000012"}).status_code == 201
        path = f'/api/client/v1/addresses/{original["id"]}'
        headers = {"Authorization": f'Bearer {issued["token"]}'}
        before = snapshot()
        with sqlite_connection(get_settings().data_store_path) as db:
            owners_before = [tuple(row) for row in db.execute("SELECT * FROM api_owned_addresses")]
        for value in ("0" * 64, "", "a" * 63, "A" * 64, "g" * 64, "a" * 65):
            result = client.get(path, params={"user_ref_hash": value}, headers=headers)
            assert result.status_code == 404
            assert result.json() == {"detail": "Not Found"}
        with sqlite_connection(get_settings().data_store_path) as db:
            assert [tuple(row) for row in db.execute("SELECT * FROM api_owned_addresses")] == owners_before
        assert snapshot() == before


def test_scoped_get_cannot_verify_foreign_client_even_with_matching_user_ref_hash():
    with SimpleTestClient() as client:
        owner, foreign = provision(client), provision(client)
        original = address()
        ref = "opaque-user-00000012"
        assert client.post(f'/api/client-credentials/{owner["client_id"]}/addresses/adopt',
                           json={"address_id": original["id"], "external_user_ref": ref}).status_code == 201
        result = client.get(f'/api/client/v1/addresses/{original["id"]}',
                            params={"user_ref_hash": hashlib.sha256(ref.encode()).hexdigest()},
                            headers={"Authorization": f'Bearer {foreign["token"]}'})
        assert result.status_code == 404
        assert result.json() == {"detail": "Not Found"}


def test_operator_adopts_existing_address_without_mutating_history_and_machine_gets_exact_address():
    with SimpleTestClient() as client:
        issued = provision(client)
        original = address()
        path = f'/api/client-credentials/{issued["client_id"]}/addresses/adopt'
        body = {"address_id": original["id"], "external_user_ref": "opaque-user-00000012"}
        logs = _get_log_storage()
        asyncio.run(logs.log_invoice_event(username="paycf", domain="pay.example.com",
                                          amount_msat=2000, payment_hash="ab" * 32,
                                          details={"historical": True}))
        asyncio.run(logs.create_delivery(kind="webhook", target="https://guestlist.example.com/callback",
                                         event="invoice.settled", payload={"historical": True},
                                         address_id=original["id"], delivery_key="old-delivery"))
        before = snapshot()
        assert len(before["invoice_events"]) == len(before["webhook_deliveries"]) == 1
        persisted_before = asyncio.run(_get_ln_address_store().get_address(original["id"]))
        assert client.get(f'/api/client/v1/addresses/{original["id"]}',
                          headers={"Authorization": f'Bearer {issued["token"]}'}).status_code == 404
        adopted = client.post(path, json=body)
        assert adopted.status_code == 201
        expected = {"address_id": original["id"], "ln_address": "paycf@pay.example.com"}
        assert adopted.json() == expected
        assert adopted.headers["cache-control"] == "no-store, private"
        assert client.post(path, json=body).json() == expected
        assert snapshot() == before
        assert asyncio.run(_get_ln_address_store().get_address(original["id"])) == persisted_before
        machine = {"Authorization": f'Bearer {issued["token"]}'}
        assert client.get(f'/api/client/v1/addresses/{original["id"]}', headers=machine).json() == expected
        with sqlite_connection(get_settings().data_store_path) as db:
            assert db.execute("SELECT COUNT(*) FROM api_owned_addresses").fetchone()[0] == 1


def test_adoption_rejects_foreign_domain_remote_missing_conflicts_and_revocation():
    with SimpleTestClient() as client:
        first, second = provision(client), provision(client)
        foreign = address("foreign", "elsewhere.example.com")
        remote = address("remote", routing_mode="forward")
        own = address("own")
        another = address("another")
        path = f'/api/client-credentials/{first["client_id"]}/addresses/adopt'
        other_path = f'/api/client-credentials/{second["client_id"]}/addresses/adopt'
        body = {"address_id": own["id"], "external_user_ref": "opaque-user-00000012"}
        for target in (foreign, remote):
            assert client.post(path, json={**body, "address_id": target["id"]}).status_code == 409
        assert client.post(path, json={**body, "address_id": str(uuid4())}).status_code == 404
        assert client.post(path, json=body).status_code == 201
        foreign_machine = {"Authorization": f'Bearer {second["token"]}'}
        assert client.get(f'/api/client/v1/addresses/{own["id"]}', headers=foreign_machine).status_code == 404
        limited = provision(client, scopes=["addresses:create"])
        assert client.get(f'/api/client/v1/addresses/{own["id"]}',
                          headers={"Authorization": f'Bearer {limited["token"]}'}).status_code == 403
        assert client.post(other_path, json=body).status_code == 409
        assert client.post(path, json={**body, "external_user_ref": "opaque-user-00000015"}).status_code == 409
        assert client.post(path, json={**body, "address_id": another["id"]}).status_code == 409
        assert client.delete(f'/api/client-credentials/{first["client_id"]}').status_code == 204
        assert client.post(path, json=body).status_code == 409
        assert client.post('/api/client-credentials/' + str(uuid4()) + '/addresses/adopt', json=body).status_code == 404
        with sqlite_connection(get_settings().data_store_path) as db:
            assert db.execute("SELECT COUNT(*) FROM api_owned_addresses").fetchone()[0] == 1


@pytest.mark.parametrize("payload", [
    {"address_id": "not-a-uuid", "external_user_ref": "opaque-user-00000012"},
    {"address_id": "E755DE8B-943A-40CE-8A12-975D6D61DCEF", "external_user_ref": "opaque-user-00000012"},
    {"address_id": "e755de8b-943a-40ce-8a12-975d6d61dcef", "external_user_ref": "short"},
    {"address_id": "e755de8b-943a-40ce-8a12-975d6d61dcef", "external_user_ref": "opaque-user-00000012", "extra": 1},
])
def test_adoption_requires_exact_body(payload):
    with SimpleTestClient() as client:
        issued = provision(client)
        assert client.post(f'/api/client-credentials/{issued["client_id"]}/addresses/adopt', json=payload).status_code == 422


def test_adoption_race_serializes_conflicting_owners_and_revocation():
    with SimpleTestClient() as client:
        first, second = provision(client), provision(client)
        existing = address()
        store = ClientStore(get_settings().data_store_path, _get_connection_secret_store())
        def adopt(issued, ref):
            try:
                return store.adopt_address(issued["client_id"], existing["id"], ref)
            except HTTPException as error:
                return error.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda arg: adopt(*arg), [
                (first, "opaque-user-00000012"), (second, "opaque-user-00000015")]))
        assert sorted(isinstance(result, dict) for result in results) == [False, True]
        assert 409 in results
        winner = first if isinstance(results[0], dict) else second
        store.revoke(winner["client_id"])
        assert adopt(winner, "opaque-user-00000012") == 409


def test_adoption_operator_route_never_mounted_on_client_or_public_listener():
    with SimpleTestClient() as client:
        issued = provision(client)
        existing = address()
        path = f'/api/client-credentials/{issued["client_id"]}/addresses/adopt'
        body = {"address_id": existing["id"], "external_user_ref": "opaque-user-00000012"}
        async def check():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=admin_app, client=("8.8.8.8", 1234)), base_url="http://testserver") as remote:
                assert (await remote.post(path, json=body, headers={"Authorization": f'Bearer {issued["token"]}'})).status_code == 403
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=client_only_app, client=("192.168.1.3", 1234)), base_url="http://testserver") as machine:
                assert (await machine.post(path, json=body, headers={"Authorization": f'Bearer {issued["token"]}'})).status_code == 404
            public_app.dependency_overrides[require_configured_public_domain] = lambda: None
            try:
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=public_app, client=("192.168.1.3", 1234)), base_url="http://testserver") as public:
                    assert (await public.post(path, json=body)).status_code in (404, 405)
            finally:
                public_app.dependency_overrides.clear()
        asyncio.run(check())
        assert client.post(path, json=body, headers={"Authorization": f'Bearer {issued["token"]}'}).status_code == 201  # operator listener is network-trusted, not bearer-granted
