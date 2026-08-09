"""Basic LNURL endpoint tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

from fastapi.testclient import TestClient

from ..app import config, deps
from backend.app.invoice_worker import refresh_invoice_statuses
from backend.app.lnurl_forwarding import ForwardingTarget, ForwardingTargetError
from backend.app.nostr_crypto import event_id, generate_private_key_hex, public_key_from_private_hex, sign_event
from backend.app.tls_status import TlsCertStatus


def https_to_http(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        return url
    return urlunsplit(("http", parsed.netloc, parsed.path, parsed.query, parsed.fragment))


def refresh_invoices_once():
    storage = deps._get_log_storage()
    ln_client = deps._get_ln_client()
    asyncio.run(
        refresh_invoice_statuses(
            storage,
            ln_client,
            batch_size=100,
        )
    )


def forwarding_target(address: str = "bones@walletofsatoshi.com") -> ForwardingTarget:
    local_part, domain = address.split("@", 1)
    return ForwardingTarget(
        address=address,
        local_part=local_part,
        domain=domain,
        discovery_url=f"https://{domain}/.well-known/lnurlp/{local_part}",
        payload={
            "callback": "https://livingroomofsatoshi.com/api/v1/lnurl/payreq/forwarded",
            "maxSendable": 100000000000,
            "minSendable": 1000,
            "metadata": '[[\"text/plain\",\"Pay to Wallet of Satoshi user: bones\"],[\"text/identifier\",\"bones@walletofsatoshi.com\"]]',
            "commentAllowed": 255,
            "tag": "payRequest",
        },
    )


def test_lnurl_metadata(test_client: TestClient):
    response = test_client.get("/.well-known/lnurlp/bones")
    assert response.status_code == 200
    data = response.json()
    assert data["tag"] == "payRequest"
    assert "callback" in data
    assert data["callback"] == "http://testserver/.well-known/lnurlp/bones"
    assert data["minSendable"] > 0
    assert data["maxSendable"] >= data["minSendable"]
    assert data["commentAllowed"] == config.get_settings().comment_max_length


def test_untrusted_forwarding_headers_cannot_spoof_public_urls(test_client: TestClient):
    response = test_client.get(
        "/.well-known/lnurlp/bones",
        headers={
            "X-Forwarded-For": "198.51.100.99",
            "X-Forwarded-Host": "evil.example",
            "X-Forwarded-Proto": "https",
            "True-Client-IP": "198.51.100.100",
        },
    )

    assert response.status_code == 200
    assert response.json()["callback"] == "http://testserver/.well-known/lnurlp/bones"


def _create_nostr_identity(client: TestClient, *, local_part: str = "bones", pubkey: str = "b0" * 32):
    response = client.post(
        "/api/nip05/identities",
        json={
            "local_part": local_part,
            "domain": "testserver",
            "npub": pubkey,
            "relays": ["wss://relay.example.com"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["item"]


def _sign_zap_request(*, recipient_pubkey: str, amount_msat: int = 1000, lnurl: str = "lnurlp://testserver/.well-known/lnurlp/bones"):
    private_key = generate_private_key_hex()
    event = {
        "kind": 9734,
        "created_at": 1_714_566_896,
        "tags": [
            ["p", recipient_pubkey],
            ["amount", str(amount_msat)],
            ["relays", "wss://relay.example.com"],
            ["lnurl", lnurl],
        ],
        "content": "",
    }
    return sign_event(event, private_key)


def _zap_raw(event: dict) -> str:
    return json.dumps(event, separators=(",", ":"))


def test_lnurl_advertises_nip57_when_identity_and_signer_exist(test_client: TestClient):
    _create_nostr_identity(test_client)
    signer_response = test_client.post("/api/nostr/zap-signer/generate")
    assert signer_response.status_code == 200
    signer_pubkey = signer_response.json()["pubkey"]

    response = test_client.get("/.well-known/lnurlp/bones")
    assert response.status_code == 200
    data = response.json()
    assert data["allowsNostr"] is True
    assert data["nostrPubkey"] == signer_pubkey


def test_lnurl_nip57_invoice_hashes_raw_zap_request(test_client: TestClient):
    identity = _create_nostr_identity(test_client)
    test_client.post("/api/nostr/zap-signer/generate")
    zap_event = _sign_zap_request(recipient_pubkey=identity["pubkey_hex"])
    raw = _zap_raw(zap_event)

    response = test_client.get(
        "/.well-known/lnurlp/bones",
        params={"amount": 1000, "nostr": raw},
    )
    assert response.status_code == 200
    assert response.json()["pr"].startswith("lnbc")
    call = test_client.app.state.test_invoice_calls[-1]
    assert call["description_hash"] == hashlib.sha256(raw.encode("utf-8")).digest()

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 50})
    invoice_entry = next(item for item in logs_resp.json()["items"] if item["event"] == "invoice")
    assert "zap_request" not in invoice_entry["details"]
    assert raw not in json.dumps(invoice_entry, sort_keys=True)


def test_lnurl_nip57_rejects_invalid_zap_requests(test_client: TestClient):
    identity = _create_nostr_identity(test_client)
    test_client.post("/api/nostr/zap-signer/generate")

    mismatched = _sign_zap_request(recipient_pubkey=identity["pubkey_hex"], amount_msat=2000)
    response = test_client.get("/.well-known/lnurlp/bones", params={"amount": 1000, "nostr": _zap_raw(mismatched)})
    assert response.status_code == 200
    assert response.json() == {"status": "ERROR", "reason": "nostr zap request amount does not match requested invoice amount"}

    duplicate_p = _sign_zap_request(recipient_pubkey=identity["pubkey_hex"])
    duplicate_p["tags"].append(["p", public_key_from_private_hex(generate_private_key_hex())])
    duplicate_p["id"] = event_id(duplicate_p)
    response = test_client.get("/.well-known/lnurlp/bones", params={"amount": 1000, "nostr": _zap_raw(duplicate_p)})
    assert response.status_code == 200
    assert response.json() == {"status": "ERROR", "reason": "nostr zap request must include exactly one p tag"}


def test_lnurl_lud17_lnurlp_scheme_is_recorded(test_client: TestClient):
    response = test_client.get("/.well-known/lnurlp/bones")
    assert response.status_code == 200
    data = response.json()
    assert data["callback"] == "http://testserver/.well-known/lnurlp/bones"

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 10})
    assert logs_resp.status_code == 200
    entry = next(
        (
            item
            for item in logs_resp.json()["items"]
            if item["event"] == "discovery" and item["username"] == "bones"
        ),
        None,
    )
    assert entry is not None
    assert "callback_lnurl" not in entry["details"]


def test_lnurl_invoice(test_client: TestClient):
    response = test_client.get(
        "/.well-known/lnurlp/bones",
        params={"amount": 1000, "comment": "Thanks for your work!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["pr"].startswith("lnbc")
    assert data["successAction"] == {
        "tag": "message",
        "message": "Your payment hit faster than a Lightning bolt — bones@testserver stacked your sats!",
    }
    assert "/.well-known/lnurlp/bones/verify/" in data["verify"]
    assert data["verify"].startswith("https://")
    call_log = test_client.app.state.test_invoice_calls
    assert call_log
    call = call_log[-1]
    expected_metadata = json.dumps(
        [
            ["text/plain", "Pay bones@testserver"],
            ["text/identifier", "bones@testserver"],
            ["text/hostname", "testserver"],
        ],
        separators=(",", ":"),
    )
    expected_hash_bytes = hashlib.sha256(expected_metadata.encode("utf-8")).digest()
    assert call["memo"] == "Pay bones@testserver | Thanks for your work!"
    assert call["description_hash"] == expected_hash_bytes
    assert call["amount_sat"] == 1

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 50})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    items = payload["items"]
    assert payload["total_items"] >= 1
    invoice_entry = next(
        (
            item
            for item in items
            if item["username"] == "bones" and item["event"] == "invoice"
        ),
        None,
    )
    assert invoice_entry is not None
    assert invoice_entry["domain"] == "testserver"
    details = invoice_entry["details"]
    assert details["invoice"]["amount_sat"] == 1
    assert "payment_hash" in details
    assert data["verify"].endswith(details["payment_hash"])
    assert details["metadata"] == expected_metadata
    assert details["metadata_entries"][1] == ["text/identifier", "bones@testserver"]
    assert details["metadata_entries"][2] == ["text/hostname", "testserver"]
    assert details["comment_length"] == len("Thanks for your work!")
    exposed = json.dumps(invoice_entry, sort_keys=True)
    for secret in (data["pr"], data["verify"], "Thanks for your work!"):
        assert secret not in exposed
    for key in (
        "callback",
        "callback_http",
        "callback_lnurl",
        "comment",
        "ln_client_response",
        "response",
        "verify_url",
        "verify_url_http",
    ):
        assert key not in details


def test_request_logs_mark_expired_invoices(test_client: TestClient):
    response = test_client.get(
        "/.well-known/lnurlp/bones",
        params={"amount": 1500},
    )
    assert response.status_code == 200
    invoice_payload = response.json()
    payment_hash = invoice_payload["verify"].rsplit("/", 1)[-1]
    store = test_client.app.state.invoice_store
    assert payment_hash in store
    record = store[payment_hash]
    record["state"] = "CANCELED"
    record["is_expired"] = True
    record["expires_at"] = datetime.now(timezone.utc).isoformat()

    refresh_invoices_once()

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 50})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    invoice_entry = next(
        (
            item
            for item in payload["items"]
            if item["username"] == "bones" and item["event"] == "invoice"
        ),
        None,
    )
    assert invoice_entry is not None
    invoice_details = invoice_entry["details"]["invoice"]
    assert invoice_details["state"] == "CANCELED"
    assert invoice_details["is_expired"] is True


def test_lnurl_verify_flow(test_client: TestClient):
    response = test_client.get(
        "/.well-known/lnurlp/bones",
        params={"amount": 2000},
    )
    assert response.status_code == 200
    invoice_data = response.json()
    verify_url = invoice_data["verify"]
    verify_resp = test_client.get(https_to_http(verify_url))
    assert verify_resp.status_code == 200
    verify_payload = verify_resp.json()
    assert verify_payload == {
        "status": "OK",
        "settled": False,
        "preimage": None,
        "pr": invoice_data["pr"],
    }

    payment_hash = verify_url.rsplit("/", 1)[-1]
    store = test_client.app.state.invoice_store
    store[payment_hash]["settled"] = True
    store[payment_hash]["r_preimage"] = bytes.fromhex("01" * 32)

    verify_resp2 = test_client.get(https_to_http(verify_url))
    assert verify_resp2.status_code == 200
    verify_payload2 = verify_resp2.json()
    assert verify_payload2["status"] == "OK"
    assert verify_payload2["settled"] is True
    assert verify_payload2["preimage"] == "01" * 32
    assert verify_payload2["pr"] == invoice_data["pr"]

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 50})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    items = payload["items"]
    assert payload["total_items"] >= 1
    verify_entries = [
        item for item in items if item["event"] == "verify" and item["username"] == "bones"
    ]
    assert verify_entries
    latest = verify_entries[0]
    assert latest["domain"] == "testserver"
    assert latest["details"]["settled"] is True
    assert latest["details"]["payment_hash"] == payment_hash
    exposed = json.dumps(latest, sort_keys=True)
    assert "01" * 32 not in exposed
    assert invoice_data["pr"] not in exposed
    for key in ("preimage", "payment_request", "response", "verify_url", "verify_url_http"):
        assert key not in latest["details"]


def test_lnurl_verify_invalid_hash(test_client: TestClient):
    response = test_client.get("/.well-known/lnurlp/bones/verify/not-a-hex")
    assert response.status_code == 200
    assert response.json() == {"status": "ERROR", "reason": "Invalid payment hash"}


def test_lnurl_verify_not_found(test_client: TestClient):
    missing_hash = "00" * 32
    response = test_client.get(f"/.well-known/lnurlp/bones/verify/{missing_hash}")
    assert response.status_code == 200
    assert response.json() == {"status": "ERROR", "reason": "Not found"}


def test_lnurl_tag_metadata(test_client: TestClient):
    response = test_client.get("/.well-known/lnurlp/bones+vip")
    assert response.status_code == 200
    data = response.json()
    metadata_entries = json.loads(data["metadata"])
    assert ["text/tag", "vip"] in metadata_entries
    expected_callback_http = "http://testserver/.well-known/lnurlp/bones+vip"
    assert data["callback"] == expected_callback_http

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 50})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    items = payload["items"]
    assert payload["total_items"] >= 1
    discovery_entry = next(
        (item for item in items if item["event"] == "discovery" and item["username"] == "bones"),
        None,
    )
    assert discovery_entry is not None
    assert discovery_entry["domain"] == "testserver"
    assert discovery_entry["details"]["tag"] == "vip"
    assert discovery_entry["details"]["ln_address"].endswith("bones+vip@testserver")
    assert discovery_entry["details"]["username_raw"] == "bones+vip"
    assert ["text/tag", "vip"] in discovery_entry["details"]["metadata_entries"]
    assert discovery_entry["details"]["domain"] == "testserver"
    for key in ("callback", "callback_http", "callback_lnurl", "response"):
        assert key not in discovery_entry["details"]


def test_lnurl_address_overrides(test_client: TestClient):
    base_payload = {
        "local_part": "bones",
        "domain": "testserver",
        "min_sats": 50,
        "max_sats": 400,
        "metadata_description": "{ln_address} is live on {domain}",
        "success_message": "{ln_address} handled {amount_sat} sats",
    }
    resp = test_client.post("/api/lnaddresses", json=base_payload)
    assert resp.status_code == 201

    discovery = test_client.get("/.well-known/lnurlp/bones")
    assert discovery.status_code == 200
    body = discovery.json()
    assert body["minSendable"] == 50 * 1000
    assert body["maxSendable"] == 400 * 1000
    assert "webhook_url" not in body
    metadata_entries = json.loads(body["metadata"])
    assert metadata_entries[0][1] == "bones@testserver is live on testserver"

    invoice_resp = test_client.get("/.well-known/lnurlp/bones", params={"amount": 120000})
    assert invoice_resp.status_code == 200
    invoice_body = invoice_resp.json()
    assert "webhook_url" not in invoice_body
    assert invoice_body["successAction"]["message"] == "bones@testserver handled 120 sats"

    vip_payload = {
        "local_part": "vipcrew",
        "domain": "testserver",
        "min_sats": 200,
        "max_sats": 250,
        "metadata_description": "{ln_address} routes VIP flow",
        "success_message": "{ln_address} stacked {amount_sat} sats",
    }
    vip_resp = test_client.post("/api/lnaddresses", json=vip_payload)
    assert vip_resp.status_code == 201

    vip_discovery = test_client.get("/.well-known/lnurlp/vipcrew")
    assert vip_discovery.status_code == 200
    vip_body = vip_discovery.json()
    assert vip_body["minSendable"] == 200 * 1000
    assert vip_body["maxSendable"] == 250 * 1000
    vip_metadata = json.loads(vip_body["metadata"])
    assert vip_metadata[0][1] == "vipcrew@testserver routes VIP flow"

    vip_invoice = test_client.get("/.well-known/lnurlp/vipcrew", params={"amount": 220000})
    assert vip_invoice.status_code == 200
    vip_invoice_body = vip_invoice.json()
    assert vip_invoice_body["successAction"]["message"] == "vipcrew@testserver stacked 220 sats"

    whale_payload = {
        "local_part": "whaleback",
        "domain": "testserver",
        "min_sats": 100,
        "max_sats": 5000,
        "metadata_description": "{ln_address} is the whale lane",
        "success_message": "{ln_address} received {amount_sat}",
    }
    whale_resp = test_client.post("/api/lnaddresses", json=whale_payload)
    assert whale_resp.status_code == 201
    whale_discovery = test_client.get("/.well-known/lnurlp/whaleback")
    assert whale_discovery.status_code == 200
    whale_body = whale_discovery.json()
    assert whale_body["minSendable"] == 100 * 1000
    # still limited by channel capacity (1000 sats)
    assert whale_body["maxSendable"] == 1000 * 1000


def test_lnurl_invoice_with_tag(test_client: TestClient):
    response = test_client.get(
        "/.well-known/lnurlp/bones+promo",
        params={"amount": 2000},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["successAction"]["tag"] == "message"
    assert data["successAction"]["message"] == (
        "Your payment hit faster than a Lightning bolt — bones+promo@testserver stacked your sats!"
    )

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 50})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    items = payload["items"]
    assert payload["total_items"] >= 1
    invoice_entry = next(
        (item for item in items if item["event"] == "invoice" and item["username"] == "bones"),
        None,
    )
    assert invoice_entry is not None
    assert invoice_entry["domain"] == "testserver"
    assert invoice_entry["details"]["tag"] == "promo"
    assert invoice_entry["details"]["ln_address"].endswith("bones+promo@testserver")
    assert ["text/tag", "promo"] in invoice_entry["details"]["metadata_entries"]
    assert invoice_entry["details"]["domain"] == "testserver"
    call_log = test_client.app.state.test_invoice_calls
    assert call_log
    call = call_log[-1]
    assert call["memo"] == "Pay bones+promo@testserver"


def test_lnurl_lud16_local_part_validation(test_client: TestClient):
    valid = test_client.get("/.well-known/lnurlp/alice.bob-01_tag+promo_2")
    assert valid.status_code == 200
    valid_payload = valid.json()
    metadata_entries = json.loads(valid_payload["metadata"])
    assert ["text/identifier", "alice.bob-01_tag+promo_2@testserver"] in metadata_entries
    assert ["text/tag", "promo_2"] in metadata_entries

    for local_part in [
        "Alice",
        "bones++vip",
        "bones+",
        "+vip",
        "bad$value",
        "bad%20value",
        "bones+VIP",
    ]:
        response = test_client.get(f"/.well-known/lnurlp/{local_part}")
        assert response.status_code == 200
        assert response.json() == {"status": "ERROR", "reason": "Invalid username"}


def test_lnurl_amount_errors_use_lnurl_shape(test_client: TestClient):
    for amount, reason in [
        (0, "Amount must be positive"),
        ("not-int", "Amount must be an integer"),
        (2_000_000, "Amount outside allowed range"),
    ]:
        response = test_client.get("/.well-known/lnurlp/bones", params={"amount": amount})
        assert response.status_code == 200
        assert response.json() == {"status": "ERROR", "reason": reason}


def test_lnurl_comment_too_long(test_client: TestClient):
    limit = config.get_settings().comment_max_length
    long_comment = "a" * (limit + 1)
    response = test_client.get(
        "/.well-known/lnurlp/bones",
        params={"amount": 1000, "comment": long_comment},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "ERROR", "reason": "Comment exceeds maximum length"}


def test_lnurl_missing_macaroon_uses_lnurl_shape(monkeypatch, test_client: TestClient):
    async def fake_is_configured(self):
        return False

    monkeypatch.setattr(
        "backend.app.macaroon_store.MacaroonStore.is_configured",
        fake_is_configured,
    )

    response = test_client.get("/.well-known/lnurlp/bones", params={"amount": 1000})
    assert response.status_code == 200
    assert response.json() == {"status": "ERROR", "reason": "Invoice macaroon not configured"}


def test_macaroon_status_endpoint(test_client: TestClient):
    response = test_client.get("/api/auth/status")
    assert response.status_code == 200
    assert response.json()["configured"] is True
    assert response.json()["source"] == "manual"
    assert response.json()["manual_entry_allowed"] is True


def test_external_macaroon_status_endpoint(test_client: TestClient, tmp_path):
    mounted_macaroon = tmp_path / "invoice.macaroon"
    mounted_macaroon.write_bytes(b"\x00\x01binary")
    os.environ["LND_MACAROON_PATH"] = str(mounted_macaroon)
    config.get_settings.cache_clear()
    deps._get_macaroon_store.cache_clear()

    response = test_client.get("/api/auth/status")
    assert response.status_code == 200
    assert response.json()["configured"] is True
    assert response.json()["source"] == "file"
    assert response.json()["manual_entry_allowed"] is False


def test_macaroon_validation(test_client: TestClient):
    response = test_client.post("/api/auth/macaroon", json={"macaroon": "not-hex"})
    assert response.status_code == 400


def test_lnd_status_endpoint_reports_connection(test_client: TestClient):
    response = test_client.get("/api/lnd/status")
    assert response.status_code == 200
    assert response.json()["connected"] is True
    assert response.json()["status"] == "connected"
    assert response.json()["tls_status"] == "invalid"


def test_lnd_status_endpoint_reports_tls_expiry(test_client: TestClient, monkeypatch):
    monkeypatch.setattr(
        "backend.app.routers.ui.inspect_tls_cert",
        lambda _: TlsCertStatus(
            status="expired",
            message="TLS certificate expired at 2026-03-23T02:47:34+00:00",
            expires_at="2026-03-23T02:47:34+00:00",
        ),
    )

    response = test_client.get("/api/lnd/status")
    data = response.json()

    assert response.status_code == 200
    assert data["connected"] is True
    assert data["tls_status"] == "expired"
    assert data["tls_expires_at"] == "2026-03-23T02:47:34+00:00"


def test_lnd_status_endpoint_reports_errors(test_client: TestClient, monkeypatch):
    async def fake_check_connection(self):
        raise RuntimeError("tls.cert missing")

    monkeypatch.setattr(
        "backend.app.ln_client.LNClient.check_connection",
        fake_check_connection,
    )

    response = test_client.get("/api/lnd/status")
    assert response.status_code == 200
    assert response.json()["connected"] is False
    assert response.json()["status"] == "error"
    assert response.json()["message"] == "tls.cert missing"


def test_callback_and_ip_respect_forwarded_headers(monkeypatch, test_client: TestClient):
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
    monkeypatch.setenv("TRUSTED_HOSTS", "testserver,wallet.example.com")
    config.get_settings.cache_clear()
    headers = {
        "Forwarded": 'for=203.0.113.10;proto=https;host=wallet.example.com',
        "X-Forwarded-For": "203.0.113.10",
        "X-Forwarded-Port": "8443",
    }
    response = test_client.get("/.well-known/lnurlp/alice", headers=headers)
    assert response.status_code == 200
    data = response.json()
    expected_callback = "https://wallet.example.com:8443/.well-known/lnurlp/alice"
    assert data["callback"] == expected_callback

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 100})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    items = payload["items"]
    assert payload["total_items"] >= 1
    entry = next(
        (item for item in items if item["username"] == "alice" and item["event"] == "discovery"),
        None,
    )
    assert entry is not None
    assert entry["ip"] == "203.0.113.10"
    for key in ("callback", "callback_http", "callback_lnurl", "proxy", "response"):
        assert key not in entry["details"]
    expected_metadata = data["metadata"]
    expected_hash = hashlib.sha256(expected_metadata.encode("utf-8")).hexdigest()
    assert entry["details"]["metadata"] == expected_metadata
    assert entry["details"]["metadata_hash"] == expected_hash
    assert entry["details"]["ln_address"] == "alice@wallet.example.com"
    assert entry["details"]["metadata_entries"][1] == ["text/identifier", "alice@wallet.example.com"]
    assert entry["details"]["metadata_entries"][2] == ["text/hostname", "wallet.example.com"]
    assert entry["details"]["metadata_entries"][0] == [
        "text/plain",
        "Pay alice@wallet.example.com",
    ]
    assert "invoice" not in entry["details"]

def test_client_ip_walks_xff_from_the_trusted_peer(monkeypatch, test_client: TestClient):
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
    monkeypatch.setenv("TRUSTED_HOSTS", "testserver,public.example.com")
    config.get_settings.cache_clear()
    headers = {
        "CF-Connecting-IP": "6.6.6.6",
        "X-Forwarded-For": "198.51.100.23",
        "Host": "public.example.com",
        "X-Forwarded-Proto": "https",
    }
    response = test_client.get("/.well-known/lnurlp/cloudflare", headers=headers)
    assert response.status_code == 200
    data = response.json()
    expected_callback = "https://public.example.com/.well-known/lnurlp/cloudflare"
    assert data["callback"] == expected_callback

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 100})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    items = payload["items"]
    assert payload["total_items"] >= 1
    entry = next(
        (
            item
            for item in items
            if item["username"] == "cloudflare" and item["event"] == "discovery"
        ),
        None,
    )
    assert entry is not None
    assert entry["ip"] == "198.51.100.23"
    for key in ("callback", "callback_http", "callback_lnurl", "proxy", "response"):
        assert key not in entry["details"]
    expected_metadata = data["metadata"]
    expected_hash = hashlib.sha256(expected_metadata.encode("utf-8")).hexdigest()
    assert entry["details"]["metadata"] == expected_metadata
    assert entry["details"]["metadata_hash"] == expected_hash
    assert entry["details"]["ln_address"] == "cloudflare@public.example.com"
    assert entry["details"]["metadata_entries"][1] == [
        "text/identifier",
        "cloudflare@public.example.com",
    ]
    assert entry["details"]["metadata_entries"][2] == [
        "text/hostname",
        "public.example.com",
    ]
    assert entry["details"]["metadata_entries"][0] == [
        "text/plain",
        "Pay cloudflare@public.example.com",
    ]
    assert "invoice" not in entry["details"]


def test_logs_pagination_and_search(test_client: TestClient):
    clear_resp = test_client.delete("/api/logs/recent")
    assert clear_resp.status_code == 200
    # Generate a handful of discovery logs.
    for idx in range(12):
        username = f"user{idx}"
        response = test_client.get(f"/.well-known/lnurlp/{username}")
        assert response.status_code == 200

    # First page should contain the most recent entries.
    first_page = test_client.get("/api/logs/recent", params={"page": 1, "page_size": 5})
    assert first_page.status_code == 200
    page_payload = first_page.json()
    assert page_payload["total_items"] == 12
    assert page_payload["total_pages"] == 3
    assert page_payload["page"] == 1
    assert len(page_payload["items"]) == 5
    # Newest username should be the last one requested.
    assert page_payload["items"][0]["username"] == "user11"

    # Third page should have the remaining two results.
    third_page = test_client.get("/api/logs/recent", params={"page": 3, "page_size": 5})
    assert third_page.status_code == 200
    third_payload = third_page.json()
    assert third_payload["page"] == 3
    assert len(third_payload["items"]) == 2

    # Searching should return just one record when filtering by username.
    search_resp = test_client.get(
        "/api/logs/recent",
        params={"q": "user7", "page_size": 10},
    )
    assert search_resp.status_code == 200
    search_payload = search_resp.json()
    assert search_payload["total_items"] == 1
    assert search_payload["total_pages"] == 1
    assert search_payload["items"][0]["username"] == "user7"


def test_lnurl_long_description_metadata(monkeypatch, test_client: TestClient):
    long_desc = "Line 1\nLine 2 details"
    monkeypatch.setenv("LNURL_METADATA_LONG_DESC", long_desc)
    config.get_settings.cache_clear()

    response = test_client.get("/.well-known/lnurlp/longdesc")
    assert response.status_code == 200
    data = response.json()
    metadata_entries = json.loads(data["metadata"])
    assert ["text/long-desc", long_desc] in metadata_entries

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 50})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    entry = next(
        (
            item
            for item in payload["items"]
            if item["event"] == "discovery" and item["username"] == "longdesc"
        ),
        None,
    )
    assert entry is not None
    assert entry["details"]["metadata_long_desc"] == long_desc
    config.get_settings.cache_clear()


def test_lnurl_payerdata_happy_path(monkeypatch, test_client: TestClient):
    monkeypatch.setenv("LNURL_PAYER_DATA", '{"identifier": true, "name": false}')
    config.get_settings.cache_clear()

    discovery = test_client.get("/.well-known/lnurlp/payer")
    assert discovery.status_code == 200
    discovery_payload = discovery.json()
    assert "payerData" in discovery_payload
    assert discovery_payload["payerData"]["identifier"]["mandatory"] is True
    base_metadata = discovery_payload["metadata"]

    payer_payload = json.dumps(
        {"identifier": "payer@example.com", "name": "Alice"},
        separators=(",", ":"),
    )
    invoice_resp = test_client.get(
        "/.well-known/lnurlp/payer",
        params={"amount": 2000, "payerdata": payer_payload},
    )
    assert invoice_resp.status_code == 200

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 100})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    entry = next(
        (
            item
            for item in payload["items"]
            if item["event"] == "invoice" and item["username"] == "payer"
        ),
        None,
    )
    assert entry is not None
    details = entry["details"]
    expected_payload = f"{base_metadata}{payer_payload}"
    assert details["metadata_hash"] == hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
    assert "payerdata" not in details
    assert "metadata_for_hash" not in details
    assert payer_payload not in json.dumps(entry, sort_keys=True)
    config.get_settings.cache_clear()


def test_lnurl_optional_payerdata_can_be_omitted(monkeypatch, test_client: TestClient):
    monkeypatch.setenv("LNURL_PAYER_DATA", '{"identifier": false, "name": false}')
    config.get_settings.cache_clear()

    discovery = test_client.get("/.well-known/lnurlp/optional_payer")
    assert discovery.status_code == 200
    discovery_payload = discovery.json()
    assert discovery_payload["payerData"]["identifier"]["mandatory"] is False
    base_metadata = discovery_payload["metadata"]

    invoice_resp = test_client.get("/.well-known/lnurlp/optional_payer", params={"amount": 1000})
    assert invoice_resp.status_code == 200
    assert invoice_resp.json()["pr"].startswith("lnbc")

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 100})
    entry = next(
        (
            item
            for item in logs_resp.json()["items"]
            if item["event"] == "invoice" and item["username"] == "optional_payer"
        ),
        None,
    )
    assert entry is not None
    details = entry["details"]
    assert details["metadata_hash"] == hashlib.sha256(base_metadata.encode("utf-8")).hexdigest()
    assert "metadata_for_hash" not in details
    assert "payerdata" not in details
    config.get_settings.cache_clear()


def test_lnurl_payerdata_appends_extra_wallet_fields(monkeypatch, test_client: TestClient):
    monkeypatch.setenv("LNURL_PAYER_DATA", '{"identifier": true}')
    config.get_settings.cache_clear()

    discovery = test_client.get("/.well-known/lnurlp/extra_payer")
    base_metadata = discovery.json()["metadata"]
    payer_payload = json.dumps(
        {"identifier": "payer@example.com", "name": "Alice", "custom": {"tier": "gold"}},
        separators=(",", ":"),
    )
    response = test_client.get(
        "/.well-known/lnurlp/extra_payer",
        params={"amount": 1000, "payerdata": payer_payload},
    )
    assert response.status_code == 200

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 100})
    entry = next(
        (
            item
            for item in logs_resp.json()["items"]
            if item["event"] == "invoice" and item["username"] == "extra_payer"
        ),
        None,
    )
    assert entry is not None
    expected_payload = f"{base_metadata}{payer_payload}"
    assert entry["details"]["metadata_hash"] == hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
    assert "payerdata" not in entry["details"]
    assert "metadata_for_hash" not in entry["details"]
    assert payer_payload not in json.dumps(entry, sort_keys=True)
    config.get_settings.cache_clear()


def test_lnurl_payerdata_missing_required(monkeypatch, test_client: TestClient):
    monkeypatch.setenv("LNURL_PAYER_DATA", '{"identifier": true}')
    config.get_settings.cache_clear()

    response = test_client.get("/.well-known/lnurlp/needs_payer", params={"amount": 1000})
    assert response.status_code == 200
    assert response.json() == {"status": "ERROR", "reason": "Missing payerdata payload"}

    incomplete_payload = json.dumps({"name": "bob"}, separators=(",", ":"))
    response = test_client.get(
        "/.well-known/lnurlp/needs_payer",
        params={"amount": 1000, "payerdata": incomplete_payload},
    )
    assert response.status_code == 200
    assert response.json() == {
        "status": "ERROR",
        "reason": "Missing mandatory payerdata fields: identifier",
    }
    config.get_settings.cache_clear()


def test_lnurl_rejects_auth_payerdata_config():
    for value in ['{"auth": true}', "!auth", {"auth": True}]:
        try:
            config.parse_payer_data_config(value)
        except ValueError as exc:
            assert "auth is not supported" in str(exc)
        else:  # pragma: no cover - assertion branch
            raise AssertionError("auth payerData config should be rejected")


def test_recent_logs_refreshes_invoice_status(test_client: TestClient):
    clear_resp = test_client.delete("/api/logs/recent")
    assert clear_resp.status_code == 200

    invoice_resp = test_client.get("/.well-known/lnurlp/statuscheck", params={"amount": 2000})
    assert invoice_resp.status_code == 200

    invoice_store = test_client.app.state.invoice_store
    assert invoice_store
    for record in invoice_store.values():
        record["settled"] = True

    refresh_invoices_once()

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 50})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    entry = next((item for item in payload["items"] if item["event"] == "invoice"), None)
    assert entry is not None
    invoice_details = entry["details"]["invoice"]
    assert invoice_details["settled"] is True


def test_env_settings_get(test_client: TestClient):
    response = test_client.get("/api/settings/env")
    assert response.status_code == 200
    payload = response.json()
    assert "settings" in payload
    keys = {item["key"] for item in payload["settings"]}
    assert "LNURL_METADATA_DESCRIPTION" in keys
    assert "RATE_LIMIT_PER_MIN" in keys
    assert "WEBHOOK_MAX_RETRIES" in keys
    assert "WEBHOOK_RETRY_WINDOW_SECONDS" in keys
    assert "SERVICE_PORT" not in keys
    assert "DEP_ENV" not in keys
    assert "REQUEST_LOG_PATH" not in keys
    assert "DATA_STORE_PATH" not in keys


def test_version_includes_deployment_environment(test_client: TestClient, monkeypatch):
    response = test_client.get("/api/version")
    assert response.status_code == 200
    assert response.json()["dep_env"] == "DOCKER"

    monkeypatch.setenv("DEP_ENV", "umbrel_dev")
    config.get_settings.cache_clear()
    response = test_client.get("/api/version")
    assert response.status_code == 200
    assert response.json()["dep_env"] == "UMBREL-DEV"


def test_env_settings_update(test_client: TestClient):
    response = test_client.put(
        "/api/settings/env",
        json={"values": {"LNURL_METADATA_DESCRIPTION": "Edit"}},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "LNURL_METADATA_DESCRIPTION" in payload["updated"]
    assert payload["restart_required"] is True

    refreshed = test_client.get("/api/settings/env").json()
    entry = next(item for item in refreshed["settings"] if item["key"] == "LNURL_METADATA_DESCRIPTION")
    assert entry["value"] == "Edit"

    retry_update = test_client.put(
        "/api/settings/env",
        json={"values": {"WEBHOOK_MAX_RETRIES": 4}},
    )
    assert retry_update.status_code == 200
    refreshed = test_client.get("/api/settings/env").json()
    retry_entry = next(item for item in refreshed["settings"] if item["key"] == "WEBHOOK_MAX_RETRIES")
    assert retry_entry["value"] == "4"

    reset = test_client.put(
        "/api/settings/env",
        json={
            "values": {
                "LNURL_METADATA_DESCRIPTION": "Pay",
                "WEBHOOK_MAX_RETRIES": 5,
            }
        },
    )
    assert reset.status_code == 200


def test_public_channels_endpoint(test_client: TestClient):
    response = test_client.get("/api/channels/public")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_receiving_capacity_sat"] == 1000
    assert len(payload["channels"]) == 1
    assert payload["channels"][0]["remote_pubkey"] == "deadbeef"


def test_stats_summary_counts_recent_activity(test_client: TestClient):
    clear_resp = test_client.delete("/api/logs/recent")
    assert clear_resp.status_code == 200

    discovery_resp = test_client.get("/.well-known/lnurlp/bones")
    assert discovery_resp.status_code == 200

    invoice_resp = test_client.get("/.well-known/lnurlp/bones", params={"amount": 2000})
    assert invoice_resp.status_code == 200

    stats_resp = test_client.get("/api/stats/summary")
    assert stats_resp.status_code == 200
    payload = stats_resp.json()
    assert payload["connected_domains"] == 1
    assert payload["requests_24h"] >= 2
    assert payload["requests_7d"] >= payload["requests_24h"]
    assert payload["invoices_total"] >= 1
    assert payload["invoices_paid"] >= 0
    assert payload["invoices_paid_24h"] >= 0
    assert payload["total_sats_routed"] >= 0
    assert payload["sats_routed_7d"] >= 0
    series = payload.get("invoice_activity")
    assert isinstance(series, list)
    assert len(series) == 14
    assert all(
        "date" in entry and "sats" in entry and "paid" in entry and "created" in entry
        for entry in series
    )
    assert series[-1]["created"] >= 1


def test_stats_summary_invoice_activity_respects_timezone_offset(test_client: TestClient):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    storage = deps._get_log_storage()

    def insert_invoice(settled_at: datetime, amount_msat: int = 2000) -> None:
        settled_iso = settled_at.isoformat()
        payment_hash = hashlib.sha256(settled_iso.encode("utf-8")).hexdigest()
        with storage._connect() as conn:
            conn.execute(
                """
                INSERT INTO invoice_events (
                    created_at,
                    username,
                    domain,
                    ip,
                    amount_msat,
                    payment_hash,
                    payment_request,
                    details,
                    request_log_id,
                    settled,
                    expired,
                    last_checked_at,
                    next_check_at,
                    expires_at,
                    settled_at,
                    check_interval_seconds
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    settled_iso,
                    "bones",
                    "testserver",
                    None,
                    amount_msat,
                    payment_hash,
                    f"lnbc{amount_msat}n1ptest",
                    None,
                    None,
                    1,
                    0,
                    settled_iso,
                    settled_iso,
                    None,
                    settled_iso,
                    60,
                ),
            )

    now = datetime.now(tz=timezone.utc)
    candidate = now.replace(hour=0, minute=30, second=0, microsecond=0)
    if candidate > now:
        candidate -= timedelta(days=1)
    insert_invoice(candidate)

    base_resp = test_client.get("/api/stats/summary")
    assert base_resp.status_code == 200
    base_series = base_resp.json()["invoice_activity"]
    base_active = [
        entry
        for entry in base_series
        if entry["sats"] > 0 or entry["paid"] > 0 or entry["created"] > 0
    ]
    assert len(base_active) == 1
    assert base_active[0]["date"] == candidate.date().isoformat()
    assert base_active[0]["created"] == 1

    offset_minutes = 300  # UTC-5
    offset_resp = test_client.get("/api/stats/summary", params={"tz_offset_minutes": offset_minutes})
    assert offset_resp.status_code == 200
    offset_series = offset_resp.json()["invoice_activity"]
    offset_active = [
        entry
        for entry in offset_series
        if entry["sats"] > 0 or entry["paid"] > 0 or entry["created"] > 0
    ]
    assert len(offset_active) == 1
    expected_local_date = (candidate - timedelta(minutes=offset_minutes)).date().isoformat()
    assert offset_active[0]["date"] == expected_local_date
    assert offset_active[0]["created"] == 1
    loop.close()


def test_stats_summary_invoice_activity_groups_current_states_by_creation_day(
    test_client: TestClient,
):
    storage = deps._get_log_storage()
    now = datetime.now(tz=timezone.utc).replace(microsecond=0)
    created_at = (now - timedelta(days=1)).isoformat()
    settled_at = now.isoformat()

    with storage._connect() as conn:
        conn.execute("DELETE FROM invoice_events")
        for index, (payment_hash, settled, expired) in enumerate(
            (
                ("state-pending", 0, 0),
                ("state-paid", 1, 0),
                ("state-expired", 0, 1),
                ("state-paid-precedence", 1, 1),
            ),
            start=1,
        ):
            conn.execute(
                """
                INSERT INTO invoice_events (
                    created_at, username, amount_msat, payment_hash,
                    settled, expired, settled_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    "bones",
                    index * 1000,
                    payment_hash,
                    settled,
                    expired,
                    settled_at if settled else None,
                ),
            )

    response = test_client.get("/api/stats/summary")

    assert response.status_code == 200
    activity = response.json()["invoice_activity"]
    creation_day = activity[-2]
    settlement_day = activity[-1]

    assert creation_day == {
        "date": (now - timedelta(days=1)).date().isoformat(),
        "sats": 0,
        "paid": 0,
        "created": 4,
        "pending": 1,
        "settled": 2,
        "expired": 1,
    }
    assert (
        creation_day["pending"] + creation_day["settled"] + creation_day["expired"]
        == creation_day["created"]
    )
    assert settlement_day == {
        "date": now.date().isoformat(),
        "sats": 6,
        "paid": 2,
        "created": 0,
        "pending": 0,
        "settled": 0,
        "expired": 0,
    }


def test_invoice_activity_created_window_boundary_and_invalid_rows(test_client: TestClient):
    storage = deps._get_log_storage()
    now = datetime.now(tz=timezone.utc)
    first_day = now.date() - timedelta(days=13)
    first_included = datetime.combine(first_day, datetime.min.time(), tzinfo=timezone.utc)

    with storage._connect() as conn:
        for created_at, payment_hash in (
            (first_included.isoformat(), "created-boundary"),
            ((first_included - timedelta(microseconds=1)).isoformat(), "created-before-boundary"),
            ("not-a-timestamp", "created-invalid"),
        ):
            conn.execute(
                """
                INSERT INTO invoice_events (created_at, username, amount_msat, payment_hash)
                VALUES (?, ?, ?, ?)
                """,
                (created_at, "bones", 2000, payment_hash),
            )

        indexes = {
            row[1] for row in conn.execute("PRAGMA index_list(invoice_events)").fetchall()
        }

    loop = asyncio.new_event_loop()
    try:
        activity = loop.run_until_complete(storage.get_invoice_activity(days=14))
        empty_activity = loop.run_until_complete(storage.get_invoice_activity(days=0))
    finally:
        loop.close()

    first_bucket = next(entry for entry in activity if entry["date"] == first_day.isoformat())
    assert first_bucket["created"] == 1
    assert sum(int(entry["created"]) for entry in activity) == 1
    assert empty_activity == []
    assert "idx_invoice_events_created_at" in indexes


def test_invoice_events_are_persisted(test_client: TestClient):
    response = test_client.get(
        "/.well-known/lnurlp/bones",
        params={"amount": 2000},
    )
    assert response.status_code == 200
    invoice_payload = response.json()
    db_path = config.get_settings().data_store_path
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT username, domain, amount_msat, payment_hash, payment_request
        FROM invoice_events
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    conn.close()
    assert row is not None
    assert row["username"] == "bones"
    assert row["domain"] == "testserver"
    assert row["amount_msat"] == 2000
    assert row["payment_request"] == invoice_payload["pr"]
    assert row["payment_hash"] == invoice_payload["verify"].split("/")[-1]


def test_forwarded_lnurl_discovery_and_invoice(monkeypatch, test_client: TestClient):
    target = forwarding_target()

    async def fake_address_validation(forward_to):
        assert forward_to == "bones@walletofsatoshi.com"
        return target

    async def fake_lnurl_discovery(forward_to):
        assert forward_to == "bones@walletofsatoshi.com"
        return target

    payment_hash = "cd" * 32

    async def fake_forwarding_invoice(callback_url, params):
        assert callback_url == target.payload["callback"]
        assert ("amount", "2200") in params
        return {
            "pr": "lnbc2200n1forward",
            "routes": [],
            "verify": f"https://livingroomofsatoshi.com/api/v1/lnurl/verify/{payment_hash}",
        }

    monkeypatch.setattr("backend.app.routers.ln_addresses.fetch_forwarding_discovery", fake_address_validation)
    create_resp = test_client.post(
        "/api/lnaddresses",
        json={
            "local_part": "tips",
            "domain": "testserver",
            "routing_mode": "forward",
            "forward_to": "bones@walletofsatoshi.com",
        },
    )
    assert create_resp.status_code == 201

    monkeypatch.setattr("backend.app.routers.lnurl.fetch_forwarding_discovery", fake_lnurl_discovery)
    monkeypatch.setattr("backend.app.routers.lnurl.fetch_forwarding_invoice", fake_forwarding_invoice)

    invoice_calls_before = len(test_client.app.state.test_invoice_calls)
    discovery = test_client.get("/.well-known/lnurlp/tips")
    assert discovery.status_code == 200
    discovery_payload = discovery.json()
    assert discovery_payload["callback"] == "http://testserver/.well-known/lnurlp/tips"
    assert discovery_payload["metadata"] == target.payload["metadata"]

    invoice_resp = test_client.get("/.well-known/lnurlp/tips", params={"amount": 2200})
    assert invoice_resp.status_code == 200
    assert invoice_resp.json()["pr"] == "lnbc2200n1forward"
    assert len(test_client.app.state.test_invoice_calls) == invoice_calls_before

    db_path = config.get_settings().data_store_path
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT username, domain, amount_msat, payment_hash, payment_request, details
        FROM invoice_events
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    conn.close()
    assert row is not None
    assert row["username"] == "tips"
    assert row["domain"] == "testserver"
    assert row["amount_msat"] == 2200
    assert row["payment_request"] == "lnbc2200n1forward"
    assert row["payment_hash"] == payment_hash
    details = json.loads(row["details"])
    assert details["forwarded"] is True
    assert details["forward_to"] == "bones@walletofsatoshi.com"
    assert details["settlement_source"] == "remote_verify"

    logs_resp = test_client.get("/api/logs/recent", params={"q": "forward"})
    assert logs_resp.status_code == 200
    logs = logs_resp.json()["items"]
    assert logs
    assert logs[0]["event"] == "forward"

    invoices_resp = test_client.get("/api/invoices", params={"q": "tips"})
    assert invoices_resp.status_code == 200
    invoices = invoices_resp.json()["items"]
    assert invoices
    assert invoices[0]["status"] == "forwarded"


def test_forwarded_lnurl_unavailable_target_uses_lnurl_shape(monkeypatch, test_client: TestClient):
    target = forwarding_target("offline@example.com")

    async def fake_address_validation(forward_to):
        return target

    async def fake_lnurl_discovery(forward_to):
        raise ForwardingTargetError("Forwarding target unavailable")

    monkeypatch.setattr("backend.app.routers.ln_addresses.fetch_forwarding_discovery", fake_address_validation)
    create_resp = test_client.post(
        "/api/lnaddresses",
        json={
            "local_part": "offline",
            "domain": "testserver",
            "routing_mode": "forward",
            "forward_to": "offline@example.com",
        },
    )
    assert create_resp.status_code == 201

    monkeypatch.setattr("backend.app.routers.lnurl.fetch_forwarding_discovery", fake_lnurl_discovery)
    response = test_client.get("/.well-known/lnurlp/offline")
    assert response.status_code == 200
    assert response.json() == {"status": "ERROR", "reason": "Forwarding target unavailable"}


def test_forwarded_invoice_without_verify_does_not_create_paid_webhook_event(monkeypatch, test_client: TestClient):
    target = forwarding_target("ivegotbones@shakepay.me")

    async def fake_address_validation(forward_to):
        return target

    async def fake_lnurl_discovery(forward_to):
        return target

    async def fake_forwarding_invoice(callback_url, params):
        return {
            "pr": "lnbc3000n1forward",
            "routes": [],
        }

    monkeypatch.setattr("backend.app.routers.ln_addresses.fetch_forwarding_discovery", fake_address_validation)
    create_resp = test_client.post(
        "/api/lnaddresses",
        json={
            "local_part": "shake",
            "domain": "testserver",
            "routing_mode": "forward",
            "forward_to": "ivegotbones@shakepay.me",
        },
    )
    assert create_resp.status_code == 201

    monkeypatch.setattr("backend.app.routers.lnurl.fetch_forwarding_discovery", fake_lnurl_discovery)
    monkeypatch.setattr("backend.app.routers.lnurl.fetch_forwarding_invoice", fake_forwarding_invoice)

    invoice_resp = test_client.get("/.well-known/lnurlp/shake", params={"amount": 3000})
    assert invoice_resp.status_code == 200

    db_path = config.get_settings().data_store_path
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM invoice_events").fetchone()[0]
    conn.close()
    assert count == 0


def test_invoice_list_endpoint(test_client: TestClient):
    response = test_client.get(
        "/.well-known/lnurlp/bones",
        params={"amount": 2100},
    )
    assert response.status_code == 200
    invoice_payload = response.json()
    refresh_invoices_once()

    list_resp = test_client.get("/api/invoices", params={"page_size": 5})
    assert list_resp.status_code == 200
    payload = list_resp.json()
    assert payload["total_items"] >= 1
    first = payload["items"][0]
    assert first["payment_request"] is None
    assert invoice_payload["pr"] not in json.dumps(first, sort_keys=True)
    assert first["payment_hash"] == invoice_payload["verify"].rsplit("/", 1)[-1]
    assert first["status"] in {"pending", "settled", "expired"}
    assert "details" in first
    assert "settled_at" in first

    search_resp = test_client.get(
        "/api/invoices",
        params={"q": "nonexistent-hash-fragment"},
    )
    assert search_resp.status_code == 200
    search_payload = search_resp.json()
    assert search_payload["total_items"] == 0
