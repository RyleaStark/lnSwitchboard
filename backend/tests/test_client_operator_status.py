"""Operator-only status reports the actual in-process listener, not configuration alone."""
from types import SimpleNamespace

from backend.app.main import admin_app, client_only_app, public_app
from .conftest import SimpleTestClient


def test_private_webhook_opt_in_is_available_in_native_environment_settings():
    with SimpleTestClient() as client:
        response = client.get("/api/settings/env")
        assert response.status_code == 200
        field = next((f for f in response.json()["settings"] if f["key"] == "ALLOW_PRIVATE_WEBHOOKS"), None)
        assert field is not None
        assert field["editable"] is True
        assert field["value"] == "false"
        assert {option["value"] for option in field["options"]} == {"true", "false"}


def test_operator_client_status_is_private_and_no_store():
    with SimpleTestClient() as client:
        response = client.get("/api/client-credentials/status")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store, private"
        assert response.json() == {"enabled": False, "listening": False,
                                   "host": "127.0.0.1", "port": 22122,
                                   "allow_private_webhooks": False}
    assert not any(getattr(route, "path", "") == "/api/client-credentials/status"
                   for app in (client_only_app, public_app) for route in app.routes)


def test_operator_client_status_requires_live_started_server(monkeypatch):
    from backend.app.config import get_settings
    monkeypatch.setattr(get_settings(), "client_api_enabled", True)
    with SimpleTestClient() as client:
        monkeypatch.setattr(admin_app.state, "client_listener", (SimpleNamespace(started=True), SimpleNamespace(done=lambda: False)), raising=False)
        assert client.get("/api/client-credentials/status").json()["listening"] is True
        monkeypatch.setattr(admin_app.state, "client_listener", (SimpleNamespace(started=True), SimpleNamespace(done=lambda: True)))
        assert client.get("/api/client-credentials/status").json()["listening"] is False
