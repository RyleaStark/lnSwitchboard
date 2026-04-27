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
    assert invoice_entry["details"]["invoice"]["payment_request"] == data["pr"]
    assert invoice_entry["details"]["response"] == data
    assert invoice_entry["details"]["ln_client_response"] == {
        "payment_request": data["pr"],
        "r_hash": invoice_entry["details"]["payment_hash"],
    }
    assert invoice_entry["details"]["response"]["successAction"]["tag"] == "message"
    assert (
        invoice_entry["details"]["response"]["successAction"]["message"]
        == "Your payment hit faster than a Lightning bolt — bones@testserver stacked your sats!"
    )
    assert (
        invoice_entry["details"]["metadata"]
        == expected_metadata
    )
    assert invoice_entry["details"]["metadata_entries"][1] == ["text/identifier", "bones@testserver"]
    assert invoice_entry["details"]["metadata_entries"][2] == ["text/hostname", "testserver"]
    assert invoice_entry["details"]["metadata_entries"][0] == [
        "text/plain",
        "Pay bones@testserver",
    ]
    assert invoice_entry["details"]["domain"] == "testserver"
    assert invoice_entry["details"]["invoice"]["amount_sat"] == 1
    assert invoice_entry["details"]["comment"] == "Thanks for your work!"
    assert invoice_entry["details"]["comment_length"] == len("Thanks for your work!")
    assert invoice_entry["details"]["invoice"]["memo"] == "Pay bones@testserver | Thanks for your work!"
    assert "payment_hash" in invoice_entry["details"]
    assert invoice_entry["details"]["verify_url"] == data["verify"]
    assert invoice_entry["details"]["verify_url_http"] == https_to_http(data["verify"])
    assert data["verify"].endswith(invoice_entry["details"]["payment_hash"])
    details = invoice_entry["details"]
    assert details.get("callback_http") == "http://testserver/.well-known/lnurlp/bones"
    callback_value = details.get("callback")
    assert callback_value in (
        None,
        "http://testserver/.well-known/lnurlp/bones",
        "lnurlp://testserver/.well-known/lnurlp/bones",
    )
    assert details.get("callback_lnurl") == "lnurlp://testserver/.well-known/lnurlp/bones"


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
    assert latest["details"]["response"]["settled"] is True
    assert latest["details"]["response"]["preimage"] == "01" * 32
    assert latest["details"]["payment_hash"] == payment_hash
    assert latest["details"]["verify_url"] == verify_url
    assert latest["details"]["verify_url_http"] == https_to_http(verify_url)
    assert latest["details"]["domain"] == "testserver"


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
    expected_callback_lnurl = "lnurlp://testserver/.well-known/lnurlp/bones+vip"
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
    assert discovery_entry["details"].get("callback_http") == expected_callback_http
    assert discovery_entry["details"].get("callback") in (None, expected_callback_http)
    assert discovery_entry["details"].get("callback_lnurl") == expected_callback_lnurl


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


def test_lnurl_comment_too_long(test_client: TestClient):
    limit = config.get_settings().comment_max_length
    long_comment = "a" * (limit + 1)
    response = test_client.get(
        "/.well-known/lnurlp/bones",
        params={"amount": 1000, "comment": long_comment},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Comment exceeds maximum length"


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


def test_callback_and_ip_respect_forwarded_headers(test_client: TestClient):
    headers = {
        "Forwarded": 'for=203.0.113.10;proto=https;host=wallet.example.com',
        "X-Forwarded-Port": "8443",
    }
    response = test_client.get("/.well-known/lnurlp/alice", headers=headers)
    assert response.status_code == 200
    data = response.json()
    expected_callback = "https://wallet.example.com:8443/.well-known/lnurlp/alice"
    expected_callback_lnurl = "lnurlp://wallet.example.com:8443/.well-known/lnurlp/alice"
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
    assert entry["details"].get("callback") in (None, expected_callback)
    assert entry["details"].get("callback_http") == expected_callback
    assert entry["details"].get("callback_lnurl") == expected_callback_lnurl
    assert entry["details"]["response"] == data
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

    proxy = entry["details"]["proxy"]
    assert proxy["resolved"]["proto"] == "https"
    assert proxy["resolved"]["netloc"] == "wallet.example.com:8443"
    assert proxy["sources"]["proto"] == "Forwarded proto"
    assert proxy["sources"]["host"] == "Forwarded host"
    assert proxy["sources"]["port"] == "x-forwarded-port"
    assert proxy["headers"]["forwarded"] == headers["Forwarded"]
    assert proxy["headers"]["x-forwarded-port"] == headers["X-Forwarded-Port"]
    assert proxy["client"]["ip"] == "203.0.113.10"
    assert proxy["client"]["source"] == "Forwarded for"


def test_client_ip_falls_back_to_cf_header(test_client: TestClient):
    headers = {
        "CF-Connecting-IP": "198.51.100.23",
        "Host": "public.example.com",
        "X-Forwarded-Proto": "https",
    }
    response = test_client.get("/.well-known/lnurlp/cloudflare", headers=headers)
    assert response.status_code == 200
    data = response.json()
    expected_callback = "https://public.example.com/.well-known/lnurlp/cloudflare"
    expected_callback_lnurl = "lnurlp://public.example.com/.well-known/lnurlp/cloudflare"
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
    assert entry["details"].get("callback") in (None, expected_callback)
    assert entry["details"].get("callback_http") == expected_callback
    assert entry["details"].get("callback_lnurl") == expected_callback_lnurl
    assert entry["details"]["response"] == data
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

    proxy = entry["details"]["proxy"]
    assert proxy["resolved"]["proto"] == "https"
    assert proxy["resolved"]["host"] == "public.example.com"
    assert proxy["sources"]["proto"] == "x-forwarded-proto"
    assert proxy["sources"]["host"] == "Host header"
    assert proxy["headers"]["cf-connecting-ip"] == "198.51.100.23"
    assert proxy["client"]["ip"] == "198.51.100.23"
    assert proxy["client"]["source"] == "cf-connecting-ip"


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
    assert details["payerdata"]["identifier"] == "payer@example.com"
    assert details["payerdata"]["name"] == "Alice"
    expected_payload = f"{base_metadata}{payer_payload}"
    assert details["metadata_for_hash"] == expected_payload
    assert details["metadata_hash"] == hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
    config.get_settings.cache_clear()


def test_lnurl_payerdata_missing_required(monkeypatch, test_client: TestClient):
    monkeypatch.setenv("LNURL_PAYER_DATA", '{"identifier": true}')
    config.get_settings.cache_clear()

    response = test_client.get("/.well-known/lnurlp/needs_payer", params={"amount": 1000})
    assert response.status_code == 400
    assert response.json()["detail"] == "Missing payerdata payload"

    incomplete_payload = json.dumps({"name": "bob"}, separators=(",", ":"))
    response = test_client.get(
        "/.well-known/lnurlp/needs_payer",
        params={"amount": 1000, "payerdata": incomplete_payload},
    )
    assert response.status_code == 400
    assert "Missing mandatory payerdata fields" in response.json()["detail"]
    config.get_settings.cache_clear()


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
    assert "REQUEST_LOG_PATH" not in keys
    assert "DATA_STORE_PATH" not in keys


def test_env_settings_update(test_client: TestClient):
    response = test_client.put(
        "/api/settings/env",
        json={"values": {"LNURL_METADATA_DESCRIPTION": "Edit"}},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "LNURL_METADATA_DESCRIPTION" in payload["updated"]

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
    assert all("date" in entry and "sats" in entry and "paid" in entry for entry in series)


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
    base_active = [entry for entry in base_series if entry["sats"] > 0 or entry["paid"] > 0]
    assert len(base_active) == 1
    assert base_active[0]["date"] == candidate.date().isoformat()

    offset_minutes = 300  # UTC-5
    offset_resp = test_client.get("/api/stats/summary", params={"tz_offset_minutes": offset_minutes})
    assert offset_resp.status_code == 200
    offset_series = offset_resp.json()["invoice_activity"]
    offset_active = [entry for entry in offset_series if entry["sats"] > 0 or entry["paid"] > 0]
    assert len(offset_active) == 1
    expected_local_date = (candidate - timedelta(minutes=offset_minutes)).date().isoformat()
    assert offset_active[0]["date"] == expected_local_date
    loop.close()


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
    assert first["payment_request"] == invoice_payload["pr"]
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
