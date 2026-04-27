from __future__ import annotations

import pytest

from backend.app.lnurl_forwarding import ForwardingTarget, ForwardingTargetError, validate_discovery_payload


def _forwarding_target(address: str = "bones@walletofsatoshi.com") -> ForwardingTarget:
    return ForwardingTarget(
        address=address,
        local_part=address.split("@", 1)[0],
        domain=address.split("@", 1)[1],
        discovery_url=f"https://{address.split('@', 1)[1]}/.well-known/lnurlp/{address.split('@', 1)[0]}",
        payload={
            "callback": "https://livingroomofsatoshi.com/api/v1/lnurl/payreq/tester",
            "maxSendable": 100000000000,
            "minSendable": 1000,
            "metadata": '[[\"text/plain\",\"Pay forwarded target\"]]',
            "tag": "payRequest",
        },
    )


def test_forwarding_discovery_payload_validation():
    payload = validate_discovery_payload(
        {
            "callback": "https://livingroomofsatoshi.com/api/v1/lnurl/payreq/forwarded",
            "maxSendable": 100000000000,
            "minSendable": 1000,
            "metadata": '[[\"text/plain\",\"Pay to Wallet of Satoshi user: bones\"],[\"text/identifier\",\"bones@walletofsatoshi.com\"]]',
            "commentAllowed": 255,
            "tag": "payRequest",
        }
    )
    assert payload["tag"] == "payRequest"

    with pytest.raises(ForwardingTargetError):
        validate_discovery_payload({"status": "ERROR", "reason": "Unable to find valid user wallet."})


def test_forwarding_validation_and_create(monkeypatch, test_client):
    async def fake_fetch(forward_to):
        assert forward_to == "Bones@WalletOfSatoshi.com"
        return _forwarding_target()

    monkeypatch.setattr("backend.app.routers.ln_addresses.fetch_forwarding_discovery", fake_fetch)

    validate_resp = test_client.post(
        "/api/lnaddresses/forwarding/validate",
        json={"forward_to": "Bones@WalletOfSatoshi.com"},
    )
    assert validate_resp.status_code == 200
    assert validate_resp.json()["forward_to"] == "bones@walletofsatoshi.com"

    create_resp = test_client.post(
        "/api/lnaddresses",
        json={
            "local_part": "tips",
            "domain": "testserver",
            "routing_mode": "forward",
            "forward_to": "Bones@WalletOfSatoshi.com",
        },
    )
    assert create_resp.status_code == 201
    created = create_resp.json()["item"]
    assert created["identifier"] == "tips@testserver"
    assert created["routing_mode"] == "forward"
    assert created["forward_to"] == "bones@walletofsatoshi.com"
    assert created["min_sats"] is None
    assert created["webhook_urls"] == []


def test_forwarding_validation_blocks_invalid_targets(monkeypatch, test_client):
    async def fake_fetch(forward_to):
        raise ForwardingTargetError("Unable to find valid user wallet.")

    monkeypatch.setattr("backend.app.routers.ln_addresses.fetch_forwarding_discovery", fake_fetch)

    validate_resp = test_client.post(
        "/api/lnaddresses/forwarding/validate",
        json={"forward_to": "missing@walletofsatoshi.com"},
    )
    assert validate_resp.status_code == 422
    assert "Unable to find valid user wallet" in validate_resp.json()["detail"]

    create_resp = test_client.post(
        "/api/lnaddresses",
        json={
            "local_part": "tips",
            "domain": "testserver",
            "routing_mode": "forward",
            "forward_to": "missing@walletofsatoshi.com",
        },
    )
    assert create_resp.status_code == 422

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
        {"local_part": "nip-profile", "domain": "testserver"},
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
