from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlsplit

import asyncio
import httpx
import pytest

from backend.app import config
from backend.app.main import (
    admin_app,
    public_app,
    require_configured_public_domain,
)


class SimpleTestClient:
    def __init__(self):
        self.app = admin_app

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    async def _request_async(self, method: str, url: str, **kwargs):
        is_public = urlsplit(url).path.startswith("/.well-known/")
        target_app = public_app if is_public else admin_app
        client_address = ("127.0.0.1", 54321) if is_public else ("192.168.50.10", 54321)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=target_app, client=client_address),
            base_url="http://testserver",
            headers={"user-agent": "testclient"},
        ) as client:
            return await client.request(method, url, **kwargs)

    def request(self, method: str, url: str, **kwargs):
        return asyncio.run(self._request_async(method, url, **kwargs))

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs):
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self.request("DELETE", url, **kwargs)


@pytest.fixture(autouse=True)
def configure_env(tmp_path):
    macaroon = tmp_path / "macaroon.hex"
    macaroon.write_text("00", encoding="utf-8")
    tls = tmp_path / "tls.cert"
    tls.write_text("CERT")
    data_store_path = tmp_path / "lnswitchboard.db"
    env_file = tmp_path / ".env"

    os.environ["LND_HOST"] = "127.0.0.1"
    os.environ["LND_TLS_PATH"] = str(tls)
    os.environ.pop("LND_MACAROON_PATH", None)
    os.environ.pop("LND_READONLY_MACAROON_PATH", None)
    os.environ["SERVICE_PORT"] = "22121"
    os.environ.pop("DEP_ENV", None)
    os.environ["DATA_STORE_PATH"] = str(data_store_path)
    os.environ["CONNECTION_SECRET_KEY_PATH"] = str(tmp_path / "connection-secrets.key")
    os.environ.pop("CLOUDFLARED_CONNECTOR_ENABLED", None)
    os.environ["LND_GRPC_PORT"] = "10009"
    os.environ["MACAROON_STORE_PATH"] = str(macaroon)
    os.environ["LNURL_COMMENT_MAX_LENGTH"] = "120"
    os.environ["RATE_LIMIT_PER_MIN"] = "1000"
    os.environ.pop("TRUSTED_PROXY_CIDRS", None)
    os.environ["TRUSTED_HOSTS"] = "testserver,localhost,127.0.0.1,[::1]"
    os.environ.pop("ALLOW_PRIVATE_NOSTR_RELAYS", None)
    os.environ.pop("ALLOW_PRIVATE_WEBHOOKS", None)
    os.environ["LNSWITCHBOARD_ENV_FILE"] = str(env_file)

    config.get_settings.cache_clear()
    from backend.app import deps

    deps._get_log_storage.cache_clear()
    deps._get_nip05_store.cache_clear()
    deps._get_ln_address_store.cache_clear()
    deps._get_connection_store.cache_clear()
    deps._get_connection_secret_store.cache_clear()
    deps._get_cloudflare_service.cache_clear()
    deps._get_rate_limiter.cache_clear()
    deps._get_ln_client.cache_clear()
    deps._get_macaroon_store.cache_clear()
    deps._get_readonly_macaroon_store.cache_clear()
    deps._get_webhook_dispatcher.cache_clear()
    deps._get_nostr_signer_store.cache_clear()
    deps._get_zap_publisher.cache_clear()
    yield
    os.environ.pop("LND_MACAROON_PATH", None)
    os.environ.pop("LND_READONLY_MACAROON_PATH", None)
    os.environ.pop("DEP_ENV", None)
    os.environ.pop("TRUSTED_HOSTS", None)
    config.get_settings.cache_clear()
    deps._get_log_storage.cache_clear()
    deps._get_nip05_store.cache_clear()
    deps._get_ln_address_store.cache_clear()
    deps._get_connection_store.cache_clear()
    deps._get_connection_secret_store.cache_clear()
    deps._get_cloudflare_service.cache_clear()
    deps._get_rate_limiter.cache_clear()
    deps._get_ln_client.cache_clear()
    deps._get_macaroon_store.cache_clear()
    deps._get_readonly_macaroon_store.cache_clear()
    deps._get_webhook_dispatcher.cache_clear()
    deps._get_nostr_signer_store.cache_clear()
    deps._get_zap_publisher.cache_clear()


@pytest.fixture
def test_client(monkeypatch) -> SimpleTestClient:
    call_log: List[Dict[str, Any]] = []
    invoice_store: Dict[str, Dict[str, Any]] = {}

    async def fake_check_connection(self) -> Dict[str, Any]:
        return {"version": "0"}

    async def fake_create_invoice(
        self, *, amount_msat: int, memo: str, description_hash: bytes
    ) -> Dict[str, Any]:
        payment_hash = hashlib.sha256(f"{memo}:{amount_msat}".encode("utf-8")).digest()
        call_log.append(
            {
                "amount_msat": amount_msat,
                "memo": memo,
                "description_hash": description_hash,
                "amount_sat": amount_msat // 1000,
                "payment_hash": payment_hash.hex(),
            }
        )
        payment_request = f"lnbc{amount_msat}n1psample"
        created_ts = int(time.time())
        expiry_seconds = 3600
        expires_at_iso = datetime.fromtimestamp(created_ts + expiry_seconds, tz=timezone.utc).isoformat()
        invoice_store[payment_hash.hex()] = {
            "settled": False,
            "payment_request": payment_request,
            "r_preimage": b"",
            "state": "OPEN",
            "creation_date": created_ts,
            "expiry": expiry_seconds,
            "expires_at": expires_at_iso,
            "is_expired": False,
        }
        return {"payment_request": payment_request, "r_hash": payment_hash}

    async def fake_lookup_invoice(self, payment_hash):
        if isinstance(payment_hash, bytes):
            hash_hex = payment_hash.hex()
        else:
            hash_hex = payment_hash
        record = invoice_store.get(hash_hex)
        if record is None:
            raise LookupError("not found")
        result: Dict[str, Any] = {
            "settled": record["settled"],
            "payment_request": record["payment_request"],
            "r_preimage": record["r_preimage"],
            "r_hash": bytes.fromhex(hash_hex),
        }
        if "state" in record:
            result["state"] = record["state"]
        if "creation_date" in record:
            result["creation_date"] = record["creation_date"]
        if "expiry" in record:
            result["expiry"] = record["expiry"]
        if "expires_at" in record:
            result["expires_at"] = record["expires_at"]
        if "is_expired" in record:
            result["is_expired"] = record["is_expired"]
        return result

    monkeypatch.setattr(
        "backend.app.ln_client.LNClient.check_connection", fake_check_connection
    )
    monkeypatch.setattr(
        "backend.app.ln_client.LNClient.create_invoice", fake_create_invoice
    )
    monkeypatch.setattr(
        "backend.app.ln_client.LNClient.lookup_invoice", fake_lookup_invoice
    )

    async def fake_subscribe_invoices(self, **kwargs):
        if False:  # pragma: no cover - required to make this an async generator
            yield {}
        while True:
            await asyncio.sleep(3600)

    monkeypatch.setattr(
        "backend.app.ln_client.LNClient.subscribe_invoices", fake_subscribe_invoices
    )

    async def fake_list_channels(self, public_only=True):
        return [
            {
                "active": True,
                "private": False,
                "capacity_sat": 2000,
                "local_balance_sat": 1000,
                "remote_balance_sat": 1000,
                "receiving_capacity_sat": 1000,
                "channel_point": "abc:0",
                "remote_pubkey": "deadbeef",
            }
        ]

    monkeypatch.setattr(
        "backend.app.ln_client.LNClient.list_channels", fake_list_channels
    )

    public_app.dependency_overrides[require_configured_public_domain] = lambda: None
    try:
        with SimpleTestClient() as client:
            client.app.state.test_invoice_calls = call_log
            client.app.state.invoice_store = invoice_store
            yield client
    finally:
        public_app.dependency_overrides.pop(require_configured_public_domain, None)
