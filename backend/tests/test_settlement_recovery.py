"""Regression gates from independent MVP recovery/security review."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.log_storage import RequestLogStorage
from backend.app.sqlite_utils import sqlite_connection


def test_unreconciled_expired_client_invoice_and_fresh_settlement_survive_restart(tmp_path):
    path = tmp_path / 'restart.db'
    now = datetime.now(timezone.utc)

    async def exercise():
        storage = RequestLogStorage(path, retention_days=1)
        for index in (1, 2):
            await storage.log_invoice_event(username='pay', domain='example.com', amount_msat=2000,
                payment_hash=f'{index:064x}', details={'client_invoice': {'version': 1}},
                expires_at=(now - timedelta(hours=1)).isoformat())
        with sqlite_connection(path) as db:
            db.execute('UPDATE invoice_events SET created_at=?', ((now - timedelta(days=30)).isoformat(),))
            db.execute('UPDATE invoice_events SET settled=1,settled_at=? WHERE payment_hash=?',
                       (now.isoformat(), f'{2:064x}'))
        restarted = RequestLogStorage(path, retention_days=1)
        assert await restarted.get_invoice_event_by_hash(f'{1:064x}') is not None
        assert await restarted.get_invoice_event_by_hash(f'{2:064x}') is not None

    asyncio.run(exercise())


@pytest.mark.parametrize('stale_error', [False, True])
def test_settlement_commit_survives_crash_before_dispatch_and_recovers_once(tmp_path, stale_error):
    from backend.app.invoice_worker import InvoiceSubscriptionWorker
    from backend.app.ln_address_store import LNAddressStore
    from backend.app.webhook_dispatcher import WebhookDispatcher

    async def exercise():
        path = tmp_path / 'outbox.db'
        storage = RequestLogStorage(path)
        addresses = LNAddressStore(path)
        address = await addresses.add_address(local_part='pay', domain='example.com', min_sendable_sat=None,
            max_sendable_sat=None, metadata_description=None, success_message=None, webhook_urls=[],
            webhook_endpoints=[{'url': 'https://billing.example.com/bridge', 'secret': 'synthetic-only-secret'}])
        payment_hash = 'ab' * 32
        await storage.log_invoice_event(username='pay', domain='example.com', amount_msat=2000,
            payment_hash=payment_hash, details={'address_override': {'id': address['id']}, 'invoice': {}})

        class Crash:
            async def dispatch_payment_settled(self, **kwargs):
                raise asyncio.CancelledError()

        worker = InvoiceSubscriptionWorker(storage, None, webhook_dispatcher=Crash())
        with pytest.raises(asyncio.CancelledError):
            await worker._apply_snapshot({'r_hash': bytes.fromhex(payment_hash), 'state': 'SETTLED',
                                         'settled': True, 'amt_paid_msat': 2500, 'settle_date': 1790000000})
        assert (await storage.get_invoice_event_by_hash(payment_hash)).settled
        # A poll fetched this event before the subscription committed payment.
        # Its delayed OPEN / lookup-error result must not undo authoritative paid state.
        committed = await storage.get_invoice_event_by_hash(payment_hash)
        await storage.apply_invoice_event_update(event=committed,
            details={"invoice": {"state": "OPEN"}, "lookup_error": stale_error},
            settled=False, expired=True, next_check=None, expires_at=None,
            interval_seconds=60, settled_at=None)
        saved = await storage.get_invoice_event_by_hash(payment_hash)
        assert saved.settled and not saved.expired
        assert saved.details['invoice']['settlement_proof']['amount_paid_msat'] == 2500
        observed = []

        async def sender(url, payload, headers):
            observed.append(payload)

        restarted = WebhookDispatcher(address_store=LNAddressStore(path),
            delivery_storage=RequestLogStorage(path), sender=sender, max_retries=0)
        await restarted.resume_pending_retries()
        assert len(observed) == 1
        assert observed[0]['settlement_proof']['amount_paid_msat'] == 2500
        await restarted.resume_pending_retries()
        assert len(observed) == 1

    asyncio.run(exercise())


def test_outbox_pagination_filters_before_limit(tmp_path):
    async def exercise():
        path = tmp_path / 'filtered.db'
        storage = RequestLogStorage(path)
        for index in (1, 2):
            await storage.log_invoice_event(username='pay', domain='example.com', amount_msat=2000,
                payment_hash=f'{index:064x}', details={})
        with sqlite_connection(path) as db:
            db.execute('INSERT INTO settlement_outbox VALUES (1)')
            db.execute('INSERT INTO settlement_outbox VALUES (2)')
            db.execute('UPDATE invoice_events SET settled=1 WHERE id=2')
        pending = await storage.get_pending_settlement_events(limit=1)
        assert [event.id for event in pending] == [2]

    asyncio.run(exercise())
