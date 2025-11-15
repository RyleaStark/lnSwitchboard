"""Basic LNURL endpoint tests."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List
from urllib.parse import urlsplit, urlunsplit

import pytest
from fastapi.testclient import TestClient

from ..app import config
from ..app.main import app


@pytest.fixture(autouse=True)
def configure_env(tmp_path):
    macaroon = tmp_path / "macaroon.hex"
    macaroon.write_text("00", encoding="utf-8")
    tls = tmp_path / "tls.cert"
    tls.write_text("CERT")
    log_path = tmp_path / "requests.log"

    os.environ["LND_HOST"] = "127.0.0.1"
    os.environ["LND_TLS_PATH"] = str(tls)
    os.environ["SERVICE_PORT"] = "22121"
    os.environ["REQUEST_LOG_PATH"] = str(log_path)
    os.environ["LND_GRPC_PORT"] = "10009"
    os.environ["MACAROON_STORE_PATH"] = str(macaroon)
    os.environ["LNURL_COMMENT_MAX_LENGTH"] = "120"
    os.environ["RATE_LIMIT_PER_MIN"] = "1000"

    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()


@pytest.fixture
def test_client(monkeypatch) -> TestClient:
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
        invoice_store[payment_hash.hex()] = {
            "settled": False,
            "payment_request": payment_request,
            "r_preimage": b"",
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
        return {
            "settled": record["settled"],
            "payment_request": record["payment_request"],
            "r_preimage": record["r_preimage"],
            "r_hash": bytes.fromhex(hash_hex),
        }

    monkeypatch.setattr(
        "backend.app.ln_client.LNClient.check_connection", fake_check_connection
    )
    monkeypatch.setattr(
        "backend.app.ln_client.LNClient.create_invoice", fake_create_invoice
    )
    monkeypatch.setattr(
        "backend.app.ln_client.LNClient.lookup_invoice", fake_lookup_invoice
    )

    with TestClient(app) as client:
        client.app.state.test_invoice_calls = call_log
        client.app.state.invoice_store = invoice_store
        yield client


def https_to_http(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        return url
    return urlunsplit(("http", parsed.netloc, parsed.path, parsed.query, parsed.fragment))


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


def test_macaroon_validation(test_client: TestClient):
    response = test_client.post("/api/auth/macaroon", json={"macaroon": "not-hex"})
    assert response.status_code == 400


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

    logs_resp = test_client.get("/api/logs/recent", params={"page_size": 50})
    assert logs_resp.status_code == 200
    payload = logs_resp.json()
    entry = next((item for item in payload["items"] if item["event"] == "invoice"), None)
    assert entry is not None
    invoice_details = entry["details"]["invoice"]
    assert invoice_details["settled"] is True
