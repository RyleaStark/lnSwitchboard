from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from fastapi.testclient import TestClient

from ..app import config
from backend.app.nip05_utils import hex_to_npub

SAMPLE_HEX = "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"
SAMPLE_NPUB = hex_to_npub(SAMPLE_HEX)


def create_identity(client: TestClient, payload: dict):
    response = client.post("/api/nip05/identities", json=payload)
    assert response.status_code == 201, response.text
    return response.json()["item"]


def test_identity_crud_and_listing(test_client: TestClient):
    item = create_identity(
        test_client,
        {
            "local_part": "bob",
            "domain": "testserver",
            "npub": SAMPLE_NPUB,
            "relays": ["wss://relay.example.com", "relay.nostr.net"],
        },
    )
    assert item["identifier"] == "bob@testserver"
    assert item["pubkey_hex"] == SAMPLE_HEX
    assert item["relays"] == ["wss://relay.example.com", "wss://relay.nostr.net"]

    # Duplicate local-part + domain should conflict.
    dup_response = test_client.post(
        "/api/nip05/identities",
        json={
            "local_part": "bob",
            "domain": "testserver",
            "npub": SAMPLE_NPUB,
            "relays": [],
        },
    )
    assert dup_response.status_code == 409

    # Update accepts raw hex input and overwrites relays.
    update_response = test_client.put(
        f"/api/nip05/identities/{item['id']}",
        json={
            "local_part": "satoshi",
            "domain": "nostr.testserver",
            "npub": SAMPLE_HEX,
            "relays": ["wss://relay.damus.io"],
        },
    )
    assert update_response.status_code == 200
    updated = update_response.json()["item"]
    assert updated["identifier"] == "satoshi@nostr.testserver"
    assert updated["npub"].startswith("npub1")
    assert updated["relays"] == ["wss://relay.damus.io"]

    # Listing returns the single updated record.
    list_response = test_client.get("/api/nip05/identities")
    assert list_response.status_code == 200
    items = list_response.json()["items"]
    assert len(items) == 1
    assert items[0]["identifier"] == "satoshi@nostr.testserver"

    # Delete removes the record.
    delete_response = test_client.delete(f"/api/nip05/identities/{item['id']}")
    assert delete_response.status_code == 200
    post_delete_list = test_client.get("/api/nip05/identities").json()["items"]
    assert post_delete_list == []


def test_well_known_scopes_entries_by_domain(monkeypatch, test_client: TestClient):
    monkeypatch.setenv("TRUSTED_HOSTS", "testserver,nostr.example")
    config.get_settings.cache_clear()
    alice = create_identity(
        test_client,
        {
            "local_part": "alice",
            "domain": "testserver",
            "npub": SAMPLE_NPUB,
            "relays": ["wss://relay.example.com"],
        },
    )
    bob = create_identity(
        test_client,
        {
            "local_part": "bob",
            "domain": "nostr.example",
            "npub": SAMPLE_NPUB,
            "relays": ["wss://relay2.example.com"],
        },
    )

    # Default host (testserver) should only surface Alice.
    resp = test_client.get("/.well-known/nostr.json", params={"name": "alice"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["names"] == {alice["local_part"]: SAMPLE_HEX}
    assert data["relays"][SAMPLE_HEX] == ["wss://relay.example.com"]
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"

    # Override host header to fetch Bob's domain.
    resp_other = test_client.get(
        "/.well-known/nostr.json",
        headers={"host": "nostr.example"},
    )
    assert resp_other.status_code == 200
    body = resp_other.json()
    assert body["names"] == {bob["local_part"]: SAMPLE_HEX}
    assert body["relays"][SAMPLE_HEX] == ["wss://relay2.example.com"]

    # Unknown name returns empty mapping.
    resp_missing = test_client.get(
        "/.well-known/nostr.json",
        params={"name": "unknown"},
        headers={"host": "nostr.example"},
    )
    assert resp_missing.status_code == 200
    assert resp_missing.json()["names"] == {}


def test_well_known_supports_root_identifier_and_lowercase_hex(test_client: TestClient):
    item = create_identity(
        test_client,
        {
            "local_part": "_",
            "domain": "testserver",
            "npub": SAMPLE_HEX.upper(),
            "relays": ["ws://relay.example.com"],
        },
    )

    resp = test_client.get("/.well-known/nostr.json", params={"name": "_"})
    assert resp.status_code == 200
    assert "location" not in resp.headers
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"
    data = resp.json()
    assert data["names"] == {"_": SAMPLE_HEX}
    assert data["names"][item["local_part"]] == SAMPLE_HEX
    assert data["relays"][SAMPLE_HEX] == ["ws://relay.example.com"]


def test_identity_relays_must_be_websocket_urls(test_client: TestClient):
    for relay in ["http://relay.example.com", "https://relay.example.com"]:
        response = test_client.post(
            "/api/nip05/identities",
            json={
                "local_part": f"bad{relay.split(':', 1)[0]}",
                "domain": "testserver",
                "npub": SAMPLE_NPUB,
                "relays": [relay],
            },
        )
        assert response.status_code == 422
        assert "ws:// or wss://" in response.text

    item = create_identity(
        test_client,
        {
            "local_part": "validrelay",
            "domain": "testserver",
            "npub": SAMPLE_NPUB,
            "relays": ["relay.nostr.net", "wss://relay.nostr.net"],
        },
    )
    assert item["relays"] == ["wss://relay.nostr.net"]


def test_identity_rejects_reserved_local_part(test_client: TestClient):
    response = test_client.post(
        "/api/nip05/identities",
        json={
            "local_part": "nip-profile",
            "domain": "testserver",
            "npub": SAMPLE_NPUB,
            "relays": [],
        },
    )
    assert response.status_code == 422
    assert "reserved" in response.text


def test_well_known_filters_invalid_stored_relay_hints(test_client: TestClient):
    item = create_identity(
        test_client,
        {
            "local_part": "legacy",
            "domain": "testserver",
            "npub": SAMPLE_NPUB,
            "relays": ["wss://relay.example.com"],
        },
    )
    db_path = config.get_settings().data_store_path
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute(
            "UPDATE nostr_identities SET relays = ? WHERE id = ?",
            (
                json.dumps(
                    [
                        "wss://relay.example.com",
                        "https://legacy.example.com",
                        "ftp://bad.example.com",
                        123,
                    ]
                ),
                item["id"],
            ),
        )

    resp = test_client.get("/.well-known/nostr.json", params={"name": "legacy"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["names"] == {"legacy": SAMPLE_HEX}
    assert data["relays"][SAMPLE_HEX] == ["wss://relay.example.com"]


def test_public_profile_reports_ln_address_and_zap_readiness(test_client: TestClient):
    create_identity(
        test_client,
        {
            "local_part": "profile",
            "domain": "testserver",
            "npub": SAMPLE_NPUB,
            "relays": ["wss://relay.example.com"],
        },
    )
    address_response = test_client.post(
        "/api/lnaddresses",
        json={
            "local_part": "profile",
            "domain": "testserver",
            "webhook_urls": [],
            "min_sats": None,
            "max_sats": None,
            "metadata_description": None,
            "success_message": None,
        },
    )
    assert address_response.status_code == 201
    test_client.post("/api/nostr/zap-signer/generate")

    response = test_client.get("/.well-known/lnurlp/nip-profile/profile")
    assert response.status_code == 200
    data = response.json()
    assert data["identifier"] == "profile@testserver"
    assert data["ln_address"] == "profile@testserver"
    assert data["nostr"]["pubkey_hex"] == SAMPLE_HEX
    assert data["zap"]["ready"] is True
    assert data["zap"]["receipt_pubkey"]
