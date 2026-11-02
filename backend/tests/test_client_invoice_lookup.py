"""Authoritative lookup uses synthetic LND only; GET never calls AddInvoice."""
import hashlib

import pytest

from backend.app.ln_client import LNClient
from .conftest import SimpleTestClient
from .test_client_api import provision_for_test


def make_invoice(client, monkeypatch):
    issued, headers = provision_for_test(client)
    address = client.post('/api/client/v1/addresses', headers=headers,
                          json={'external_user_ref': 'opaque-user-00000001'}).json()
    node = {}
    calls = []

    async def lookup(self, payment_hash):
        calls.append(payment_hash.hex())
        if payment_hash.hex() not in node:
            raise LookupError('synthetic missing')
        return node[payment_hash.hex()]

    async def add(self, *, amount_msat, memo, expiry_seconds, r_preimage):
        payment_hash = hashlib.sha256(r_preimage).hexdigest()
        node[payment_hash] = {'r_hash': bytes.fromhex(payment_hash), 'value_msat': amount_msat,
            'creation_date': 1790000000, 'expiry': expiry_seconds, 'state': 'OPEN', 'settled': False,
            'amt_paid_msat': 0, 'settle_date': 0, 'payment_request': 'lnbc1-synthetic-secret'}
        return {'r_hash': bytes.fromhex(payment_hash), 'payment_request': 'lnbc1-synthetic-secret'}

    monkeypatch.setattr(LNClient, 'lookup_invoice', lookup)
    monkeypatch.setattr(LNClient, 'create_invoice', add)
    headers['Idempotency-Key'] = 'invoice-request-1'
    path = f'/api/client/v1/addresses/{address["address_id"]}/invoices'
    created = client.post(path, headers=headers, json={'quote_id': 'quote-1', 'amount_msat': 2000, 'expiry_days': 14})
    assert created.status_code == 201
    result = created.json()

    async def forbidden(*args, **kwargs):
        raise AssertionError('GET attempted AddInvoice')

    monkeypatch.setattr(LNClient, 'create_invoice', forbidden)
    calls.clear()
    return issued, headers, address, result, node, calls, path + '/' + result['payment_hash']


def test_lookup_authoritative_settlement_exact_safe_contract(monkeypatch):
    with SimpleTestClient() as client:
        issued, headers, address, result, node, calls, path = make_invoice(client, monkeypatch)
        node[result['payment_hash']].update(state='SETTLED', settled=True, amt_paid_msat=2500, settle_date=1790000100,
                                          r_preimage=b'secret', htlcs=[{'secret': 'never'}])
        response = client.get(path, headers=headers)
        assert response.status_code == 200
        assert response.headers['cache-control'] == 'no-store, private'
        assert response.json() == {'payment_hash': result['payment_hash'], 'address_id': address['address_id'],
            'ln_address': address['ln_address'], 'client_id': issued['client_id'], 'quote_id': 'quote-1',
            'amount_msat': 2000, 'created_at': 1790000000, 'expires_at': 1791209600,
            'settled': True, 'paid_msat': 2500, 'settled_at': 1790000100}
        assert calls == [result['payment_hash']]


@pytest.mark.parametrize("state", ["OPEN", "ACCEPTED", "SETTLED"])
def test_real_protobuf_authority_snapshot(monkeypatch, state):
    from backend.app.lnrpc import Invoice
    from backend.app.deps import _get_ln_client
    with SimpleTestClient() as client:
        issued, headers, address, result, node, calls, path = make_invoice(client, monkeypatch)
        proto = Invoice(r_hash=bytes.fromhex(result["payment_hash"]), value_msat=2000,
            creation_date=1790000000, expiry=1209600, state=getattr(Invoice, state),
            settled=state == "SETTLED", amt_paid_msat=2500 if state == "SETTLED" else 0,
            settle_date=1790000100 if state == "SETTLED" else 0)
        node[result["payment_hash"]] = _get_ln_client()._build_invoice_snapshot(proto)
        response = client.get(path, headers=headers)
        assert response.status_code == 200
        assert response.json()["paid_msat"] == (2500 if state == "SETTLED" else 0)
        assert response.json()["settled_at"] == (1790000100 if state == "SETTLED" else 0)


@pytest.mark.parametrize('override', [None, [], 'invalid'])
def test_malformed_recorded_address_binding_fails_closed(monkeypatch, override):
    import json
    from backend.app.config import get_settings
    from backend.app.sqlite_utils import sqlite_connection
    with SimpleTestClient() as client:
        _, headers, _, result, _, calls, path = make_invoice(client, monkeypatch)
        with sqlite_connection(get_settings().data_store_path) as db:
            row = db.execute('SELECT details FROM invoice_events WHERE payment_hash=?', (result['payment_hash'],)).fetchone()
            details = json.loads(row['details'])
            details['address_override'] = override
            db.execute('UPDATE invoice_events SET details=? WHERE payment_hash=?', (json.dumps(details), result['payment_hash']))
        assert client.get(path, headers=headers).status_code == 404
        assert calls == []

