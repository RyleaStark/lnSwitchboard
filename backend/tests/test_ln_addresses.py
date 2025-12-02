from __future__ import annotations

import pytest


def test_address_crud_flow(test_client):
    list_resp = test_client.get("/api/lnaddresses")
    assert list_resp.status_code == 200
    assert list_resp.json() == {"items": []}

    create_payload = {
        "local_part": "bones",
        "domain": "testserver",
        "min_sats": 50,
        "max_sats": 400,
        "metadata_description": "Pay {ln_address} direct",
        "success_message": "Boom {ln_address}",
        "webhook_urls": [
            "https://hooks.example.com/payments",
            "https://hooks.example.com/audit",
        ],
    }
    create_resp = test_client.post("/api/lnaddresses", json=create_payload)
    assert create_resp.status_code == 201
    created = create_resp.json()["item"]
    assert created["identifier"] == "bones@testserver"
    assert created["min_sats"] == 50
    assert created["max_sats"] == 400
    assert created["webhook_urls"] == [
        "https://hooks.example.com/payments",
        "https://hooks.example.com/audit",
    ]

    list_resp = test_client.get("/api/lnaddresses")
    assert list_resp.status_code == 200
    assert list_resp.json()["items"][0]["identifier"] == "bones@testserver"

    update_payload = {
        "local_part": "vip",
        "domain": "testserver",
        "min_sats": 75,
        "max_sats": 500,
        "metadata_description": "VIP {ln_address}",
        "success_message": "Hello {local_part}",
        "webhook_urls": [
            "http://webhook.local/hooks",
            "https://example.org/notify",
        ],
    }
    update_resp = test_client.put(f"/api/lnaddresses/{created['id']}", json=update_payload)
    assert update_resp.status_code == 200
    updated = update_resp.json()["item"]
    assert updated["identifier"] == "vip@testserver"
    assert updated["min_sats"] == 75
    assert updated["webhook_urls"] == [
        "http://webhook.local/hooks",
        "https://example.org/notify",
    ]

    delete_resp = test_client.delete(f"/api/lnaddresses/{created['id']}")
    assert delete_resp.status_code == 200
    assert delete_resp.json() == {"status": "deleted"}

    list_resp = test_client.get("/api/lnaddresses")
    assert list_resp.status_code == 200
    assert list_resp.json() == {"items": []}


@pytest.mark.parametrize(
    "payload",
    [
        {"local_part": "bad value", "domain": "testserver"},
        {"local_part": "bones+vip", "domain": "testserver"},
        {"local_part": "bones", "domain": "https://example.com"},
        {"local_part": "bones", "domain": "example.com", "max_sats": 10, "min_sats": 50},
        {"local_part": "bones", "domain": "example.com", "webhook_urls": ["ftp://example.com/hook"]},
    ],
)
def test_address_validation_errors(test_client, payload):
    resp = test_client.post("/api/lnaddresses", json=payload)
    assert resp.status_code == 422


def test_address_legacy_webhook_field(test_client):
    payload = {
        "local_part": "legacy",
        "domain": "testserver",
        "webhook_url": "https://legacy.example.com/hook",
    }
    resp = test_client.post("/api/lnaddresses", json=payload)
    assert resp.status_code == 201
    data = resp.json()["item"]
    assert data["webhook_urls"] == ["https://legacy.example.com/hook"]
