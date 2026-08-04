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
        public_metadata={"tunnel_name": "lnswitchboard"},
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
        }
    ]
    assert payload["connections"][0]["id"] == connection.id
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
