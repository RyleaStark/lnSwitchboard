"""Synthetic negative boundaries for the read-only authoritative lookup."""
import asyncio
import json

import httpx
import pytest

from backend.app.config import get_settings
from backend.app.ln_client import LNClient
from backend.app.sqlite_utils import sqlite_connection
from .conftest import SimpleTestClient
from .test_client_api import provision_for_test
from .test_client_invoice_lookup import make_invoice


@pytest.mark.parametrize('field,value', [
    ('r_hash', b'wrong'), ('r_hash', 'AB' * 32), ('value_msat', 2001),
    ('value_msat', True), ('value_msat', '2000'), ('value_msat', 2000.0), ('value_msat', None),
    ('creation_date', 1790000001), ('creation_date', '1790000000'), ('creation_date', None),
    ('expiry', 2592000), ('expiry', True), ('expiry', None),
    ('state', None), ('state', 'UNKNOWN'), ('settled', True), ('settled', 0),
    ('amt_paid_msat', 1), ('amt_paid_msat', False), ('amt_paid_msat', '0'),
    ('settle_date', 1), ('settle_date', False), ('settle_date', '0'),
])
def test_malformed_or_mismatched_lnd_snapshot_never_claims_payment(monkeypatch, field, value):
    with SimpleTestClient() as client:
        _, headers, _, result, node, _, path = make_invoice(client, monkeypatch)
        node[result['payment_hash']][field] = value
        response = client.get(path, headers=headers)
        assert response.status_code == 503
        assert response.json() == {'detail': 'Authoritative invoice details unavailable'}
        assert response.headers['cache-control'] == 'no-store, private'


@pytest.mark.parametrize('field,value', [
    ('amt_paid_msat', None), ('amt_paid_msat', True), ('amt_paid_msat', '2500'),
    ('amt_paid_msat', 2500.0), ('amt_paid_msat', 0), ('amt_paid_msat', -1),
    ('amt_paid_msat', 9007199254740992), ('settle_date', None), ('settle_date', True),
    ('settle_date', '1790000100'), ('settle_date', 1790000100.0), ('settle_date', 0),
    ('settle_date', 1789999999), ('settle_date', 253402300800), ('settled', False),
])
def test_settlement_requires_strict_actual_paid_and_true_lnd_date(monkeypatch, field, value):
    with SimpleTestClient() as client:
        _, headers, _, result, node, _, path = make_invoice(client, monkeypatch)
        snapshot = node[result['payment_hash']]
        snapshot.update(state='SETTLED', settled=True, amt_paid_msat=2500, settle_date=1790000100)
        if value is None:
            snapshot.pop(field)
        else:
            snapshot[field] = value
        assert client.get(path, headers=headers).status_code == 503


@pytest.mark.parametrize('paid,date', [(1, 1790000000), (1999, 1790000100), (9007199254740991, 253402300799)])
def test_actual_paid_is_not_substituted_with_face_or_capped(monkeypatch, paid, date):
    with SimpleTestClient() as client:
        _, headers, _, result, node, _, path = make_invoice(client, monkeypatch)
        node[result['payment_hash']].update(state='SETTLED', settled=True, amt_paid_msat=paid, settle_date=date)
        response = client.get(path, headers=headers)
        assert response.status_code == 200
        assert response.json()['paid_msat'] == paid
        assert response.json()['settled_at'] == date
        assert response.json()['amount_msat'] == 2000


@pytest.mark.parametrize('failure', [LookupError, TimeoutError, RuntimeError])
def test_provider_failures_are_generic_never_create_or_reflect(monkeypatch, failure):
    with SimpleTestClient() as client:
        _, headers, _, _, _, _, path = make_invoice(client, monkeypatch)

        async def broken(*args):
            raise failure('SENTINEL-provider-secret')

        monkeypatch.setattr(LNClient, 'lookup_invoice', broken)
        response = client.get(path, headers=headers)
        assert response.status_code == 503
        assert 'SENTINEL' not in response.text


def test_rpc_timeout_is_bounded_and_cancels_lookup(monkeypatch):
    from backend.app.routers import client_api
    real_wait_for = asyncio.wait_for
    canceled = []
    with SimpleTestClient() as client:
        _, headers, _, _, _, _, path = make_invoice(client, monkeypatch)

        async def blocked(*args):
            try:
                await asyncio.sleep(60)
            finally:
                canceled.append(True)

        async def bounded(awaitable, timeout):
            assert timeout == 20
            return await real_wait_for(awaitable, timeout=0.001)

        monkeypatch.setattr(LNClient, 'lookup_invoice', blocked)
        monkeypatch.setattr(client_api.asyncio, 'wait_for', bounded)
        assert client.get(path, headers=headers).status_code == 503
        assert canceled == [True]


@pytest.mark.parametrize('binding', [None, [], {}, {'version': True},
    {'version': 1, 'client_id': 'foreign', 'address_id': 'foreign', 'quote_id': 'quote-1', 'creation_pending': False}])
def test_unbound_invoice_events_are_rejected_before_rpc(monkeypatch, binding):
    with SimpleTestClient() as client:
        _, headers, _, result, _, calls, path = make_invoice(client, monkeypatch)
        with sqlite_connection(get_settings().data_store_path) as db:
            details = json.loads(db.execute('SELECT details FROM invoice_events WHERE payment_hash=?', (result['payment_hash'],)).fetchone()[0])
            details['client_invoice'] = binding
            db.execute('UPDATE invoice_events SET details=? WHERE payment_hash=?', (json.dumps(details), result['payment_hash']))
        assert client.get(path, headers=headers).status_code == 404
        assert calls == []


@pytest.mark.parametrize('field,value', [('version', True), ('quote_id', 'different'), ('client_id', 'different'),
    ('address_id', 'different'), ('creation_pending', True), ('creation_pending', 0)])
def test_exact_recorded_ownership_quote_and_completed_creation(monkeypatch, field, value):
    with SimpleTestClient() as client:
        _, headers, _, result, _, calls, path = make_invoice(client, monkeypatch)
        with sqlite_connection(get_settings().data_store_path) as db:
            details = json.loads(db.execute('SELECT details FROM invoice_events WHERE payment_hash=?', (result['payment_hash'],)).fetchone()[0])
            details['client_invoice'][field] = value
            db.execute('UPDATE invoice_events SET details=? WHERE payment_hash=?', (json.dumps(details), result['payment_hash']))
        assert client.get(path, headers=headers).status_code == 404
        assert calls == []


@pytest.mark.parametrize('field,value', [('quote_id', 'different'), ('amount_msat', 3000), ('created_at', 1790000001),
    ('expires_at', 1791209601), ('amount_msat', True), ('created_at', 'bad')])
def test_issued_request_must_match_original_fingerprint(monkeypatch, field, value):
    with SimpleTestClient() as client:
        _, headers, _, result, _, calls, path = make_invoice(client, monkeypatch)
        with sqlite_connection(get_settings().data_store_path) as db:
            saved = json.loads(db.execute('SELECT result FROM api_client_requests WHERE payment_hash=?', (result['payment_hash'],)).fetchone()[0])
            saved[field] = value
            db.execute('UPDATE api_client_requests SET result=? WHERE payment_hash=?', (json.dumps(saved), result['payment_hash']))
        assert client.get(path, headers=headers).status_code == 503
        assert calls == []


def test_authentication_scopes_foreign_hash_and_revocation(monkeypatch):
    with SimpleTestClient() as client:
        issued, headers, _, result, _, calls, path = make_invoice(client, monkeypatch)
        assert client.get(path).status_code == 401
        assert client.get(path, headers={'Authorization': 'Bearer invalid'}).status_code == 401
        _, foreign = provision_for_test(client)
        assert client.get(path, headers=foreign).status_code == 404
        _, limited = provision_for_test(client, ['addresses:read_own'])
        assert client.get(path, headers=limited).status_code == 403
        for suffix in ('ab' * 32, 'bad', result['payment_hash'].upper()):
            assert client.get(path.rsplit('/', 1)[0] + '/' + suffix, headers=headers).status_code == 404
        assert client.delete('/api/client-credentials/' + issued['client_id']).status_code == 204
        assert client.get(path, headers=headers).status_code == 401
        assert calls == []


def test_revocation_during_rpc_is_rechecked(monkeypatch):
    with SimpleTestClient() as client:
        issued, headers, _, result, node, _, path = make_invoice(client, monkeypatch)

        async def revoke_then_lookup(*args):
            with sqlite_connection(get_settings().data_store_path) as db:
                db.execute('UPDATE api_clients SET revoked=1 WHERE id=?', (issued['client_id'],))
            return node[result['payment_hash']]

        monkeypatch.setattr(LNClient, 'lookup_invoice', revoke_then_lookup)
        assert client.get(path, headers=headers).status_code == 401


def test_canceled_invoice_never_becomes_open(monkeypatch):
    with SimpleTestClient() as client:
        _, headers, _, result, node, _, path = make_invoice(client, monkeypatch)
        node[result['payment_hash']].update(state='CANCELED')
        assert client.get(path, headers=headers).status_code == 409


@pytest.mark.parametrize('field,value', [('routing_mode', 'forward'), ('domain', 'different.example'), ('local_part', 'different')])
def test_address_must_remain_exact_owned_local_route(monkeypatch, field, value):
    from backend.app.ln_address_store import LNAddressStore
    original = LNAddressStore.get_address
    with SimpleTestClient() as client:
        _, headers, _, _, _, calls, path = make_invoice(client, monkeypatch)

        async def changed(self, address_id):
            record = await original(self, address_id)
            return {**record, field: value}

        monkeypatch.setattr(LNAddressStore, 'get_address', changed)
        assert client.get(path, headers=headers).status_code == 409
        assert calls == []


def test_route_change_during_rpc_is_rechecked(monkeypatch):
    from backend.app.ln_address_store import LNAddressStore
    original = LNAddressStore.get_address
    changed = []
    with SimpleTestClient() as client:
        _, headers, _, result, node, _, path = make_invoice(client, monkeypatch)

        async def address(self, address_id):
            record = await original(self, address_id)
            return {**record, 'routing_mode': 'forward'} if changed else record

        async def lookup(*args):
            changed.append(True)
            return node[result['payment_hash']]

        monkeypatch.setattr(LNAddressStore, 'get_address', address)
        monkeypatch.setattr(LNClient, 'lookup_invoice', lookup)
        assert client.get(path, headers=headers).status_code == 409


def test_missing_event_or_incomplete_issue_is_not_queryable(monkeypatch):
    with SimpleTestClient() as client:
        _, headers, _, result, _, calls, path = make_invoice(client, monkeypatch)
        with sqlite_connection(get_settings().data_store_path) as db:
            saved = db.execute('SELECT result FROM api_client_requests WHERE payment_hash=?', (result['payment_hash'],)).fetchone()[0]
            db.execute('UPDATE api_client_requests SET result=NULL WHERE payment_hash=?', (result['payment_hash'],))
        assert client.get(path, headers=headers).status_code == 404
        with sqlite_connection(get_settings().data_store_path) as db:
            db.execute('UPDATE api_client_requests SET result=? WHERE payment_hash=?', (saved, result['payment_hash']))
            db.execute('DELETE FROM invoice_events WHERE payment_hash=?', (result['payment_hash'],))
        assert client.get(path, headers=headers).status_code == 404
        assert calls == []


def test_get_has_no_invoice_or_lease_writes_and_private_listener_isolation(monkeypatch):
    from backend.app.main import public_app, client_only_app as client_app, require_configured_public_domain
    with SimpleTestClient() as client:
        _, headers, _, _, _, _, path = make_invoice(client, monkeypatch)

        def records():
            with sqlite_connection(get_settings().data_store_path) as db:
                return {table: [tuple(row) for row in db.execute('SELECT * FROM ' + table)]
                        for table in ('api_client_requests', 'invoice_events', 'connection_secrets')}

        before = records()
        assert client.get(path, headers=headers).status_code == 200
        assert client.get(path, headers=headers).status_code == 200
        assert records() == before

        async def listeners():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=client_app, client=('192.168.1.3', 1234)), base_url='http://testserver') as private:
                assert (await private.get(path, headers=headers)).status_code == 200
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=client_app, client=('8.8.8.8', 1234)), base_url='http://testserver') as remote:
                assert (await remote.get(path, headers={**headers, 'X-Forwarded-For': '192.168.1.3'})).status_code == 403
            public_app.dependency_overrides[require_configured_public_domain] = lambda: None
            try:
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=public_app), base_url='http://testserver') as public:
                    assert (await public.get(path, headers=headers)).status_code == 404
            finally:
                public_app.dependency_overrides.clear()
        asyncio.run(listeners())
