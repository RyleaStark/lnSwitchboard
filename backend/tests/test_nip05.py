from __future__ import annotations

from fastapi.testclient import TestClient

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


def test_well_known_scopes_entries_by_domain(test_client: TestClient):
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
