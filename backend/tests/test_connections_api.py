from __future__ import annotations

from backend.app import deps


def test_connections_api_lists_provider_capabilities_and_connections(test_client) -> None:
    store = deps._get_connection_store()
    connection = store.upsert_connection(
        provider="cloudflare",
        external_id="tunnel-123",
        label="Cloudflare Tunnel",
        status="connected",
        account_id="account-123",
        public_metadata={
            "origin": "http://lnswitchboard:21212",
            "tunnel_name": "lnswitchboard",
            "recovery_authorization_id": "must-not-leak",
            "connector_token": "must-not-leak-either",
        },
    )
    store.replace_domains(
        connection.id,
        [{"hostname": "alice.example.com", "status": "active", "zone_id": "zone-123"}],
    )

    response = test_client.get("/api/connections")

    assert response.status_code == 200
    payload = response.json()
    assert payload["providers"] == [
        {
            "id": "cloudflare",
            "name": "Cloudflare",
            "capability": "unavailable",
            "reason": "connector_not_installed",
        },
        {
            "id": "tailscale",
            "name": "Tailscale Funnel",
            "capability": "unavailable",
            "reason": "connector_not_installed",
        },
    ]
    assert response.json()["connections"][0]["id"] == connection.id
    metadata = response.json()["connections"][0]["public_metadata"]
    assert metadata == {
        "origin": "http://lnswitchboard:21212",
        "tunnel_name": "lnswitchboard",
    }
    assert "must-not-leak" not in response.text
    assert payload["connections"][0]["provider"] == "cloudflare"
    assert payload["connections"][0]["domains"] == [
        {
            "hostname": "alice.example.com",
            "status": "active",
            "external_id": None,
            "zone_id": "zone-123",
            "last_error": None,
        }
    ]
    serialized = response.text
    assert "access_token" not in serialized
    assert "refresh_token" not in serialized


def test_connections_api_reports_installed_connector(monkeypatch, test_client) -> None:
    monkeypatch.setenv("CLOUDFLARED_CONNECTOR_ENABLED", "true")
    from backend.app import config

    config.get_settings.cache_clear()

    response = test_client.get("/api/connections")

    assert response.status_code == 200
    assert response.json()["providers"][0] == {
        "id": "cloudflare",
        "name": "Cloudflare",
        "capability": "available",
        "reason": None,
    }
