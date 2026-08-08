from __future__ import annotations

from backend.app import deps
from backend.app.cloudflare_client import CloudflareAPIError
from backend.app.cloudflare_service import CloudflareUnavailableError
from backend.app.main import admin_app

ACCOUNT_ID = "a" * 32
TUNNEL_ID = "1" * 32
ZONE_ID = "b" * 32
SECOND_ZONE_ID = "d" * 32


class FakeCloudflareService:
    def __init__(self) -> None:
        self.authorize_request: tuple[str, str, str] | None = None
        self.provision_request: dict[str, str] | None = None

    async def authorize(self, api_token: str, account_id: str, tunnel_id: str):
        self.authorize_request = (api_token, account_id, tunnel_id)
        return {"authorization_id": "authorization-flow-id", "accounts": [{"id": account_id, "name": "Example account", "zones": [{"id": ZONE_ID, "name": "example.com"}]}]}

    async def provision(self, *, authorization_id: str, account_id: str, tunnel_id: str, zone_id: str, hostname: str):
        self.provision_request = {"authorization_id": authorization_id, "account_id": account_id, "tunnel_id": tunnel_id, "zone_id": zone_id, "hostname": hostname}
        store = deps._get_connection_store()
        connection = store.upsert_connection(provider="cloudflare", external_id=tunnel_id, label="Cloudflare Tunnel", status="provisioning", account_id=account_id, public_metadata={"origin": "http://lnswitchboard:21212"})
        store.replace_domains(connection.id, [{"hostname": hostname, "status": "pending", "zone_id": zone_id}])
        return store.get_connection(connection.id)

    async def refresh_status(self, connection_id: str):
        return deps._get_connection_store().get_connection(connection_id)

    async def available_zones(self, _connection_id: str):
        return [{"id": SECOND_ZONE_ID, "name": "example.net"}]

    async def add_domain(self, connection_id: str, zone_id: str, hostname: str):
        store = deps._get_connection_store()
        connection = store.get_connection(connection_id)
        assert connection is not None
        store.replace_domains(connection_id, [
            {"hostname": domain.hostname, "status": domain.status, "zone_id": domain.zone_id}
            for domain in connection.domains
        ] + [{"hostname": hostname, "status": "pending", "zone_id": zone_id}])
        return store.get_connection(connection_id)

    async def remove_domain(self, connection_id: str, hostname: str):
        store = deps._get_connection_store()
        connection = store.get_connection(connection_id)
        assert connection is not None
        store.replace_domains(connection_id, [
            {"hostname": domain.hostname, "status": domain.status, "zone_id": domain.zone_id}
            for domain in connection.domains if domain.hostname != hostname
        ])
        return store.get_connection(connection_id)

    async def disconnect(self, _connection_id: str) -> bool:
        return True


class UnavailableCloudflareService(FakeCloudflareService):
    async def authorize(self, api_token: str, account_id: str, tunnel_id: str):
        raise CloudflareUnavailableError("not installed")


class ExplodingCloudflareService(FakeCloudflareService):
    async def authorize(self, api_token: str, account_id: str, tunnel_id: str):
        raise RuntimeError("unexpected sensitive failure")


class ConflictingCloudflareService(FakeCloudflareService):
    async def authorize(self, api_token: str, account_id: str, tunnel_id: str):
        raise CloudflareAPIError(409)


def test_cloudflare_configuration_conflict_is_returned_as_retryable_409(test_client) -> None:
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = (
        lambda: ConflictingCloudflareService()
    )
    try:
        response = test_client.post(
            "/api/connections/cloudflare/authorize",
            json={"api_token": "secret", "account_id": ACCOUNT_ID, "tunnel_id": TUNNEL_ID},
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)

    assert response.status_code == 409
    assert response.headers["cache-control"] == "no-store, private"
    assert response.json() == {
        "detail": "Cloudflare configuration changed; retry the operation"
    }


def test_unhandled_cloudflare_error_is_sanitized_and_never_cached(test_client, caplog) -> None:
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = (
        lambda: ExplodingCloudflareService()
    )
    try:
        response = test_client.post(
            "/api/connections/cloudflare/authorize",
            json={"api_token": "secret", "account_id": ACCOUNT_ID, "tunnel_id": TUNNEL_ID},
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)

    assert response.status_code == 500
    assert response.headers["cache-control"] == "no-store, private"
    assert response.json() == {"detail": "Cloudflare operation failed"}
    assert "unexpected sensitive failure" not in response.text
    assert "unexpected sensitive failure" not in caplog.text


def test_cloudflare_setup_documents_current_dashboard_permissions(test_client) -> None:
    response = test_client.get("/api/connections/cloudflare/setup")
    assert response.status_code == 200
    assert response.json()["required_permissions"] == [
        "Account / Cloudflare One Connectors / Edit",
        "Zone / DNS / Edit",
        "Zone / Zone / Read",
    ]
    assert "Cloudflare Tunnel" not in response.text


def test_cloudflare_api_collects_write_only_token_and_explicit_existing_tunnel_ids(test_client) -> None:
    service = FakeCloudflareService()
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = lambda: service
    secret = "do-not-return-api-token"
    try:
        authorized = test_client.post("/api/connections/cloudflare/authorize", json={"api_token": secret, "account_id": ACCOUNT_ID, "tunnel_id": TUNNEL_ID})
        provisioned = test_client.post("/api/connections/cloudflare/provision", json={"account_id": ACCOUNT_ID, "tunnel_id": TUNNEL_ID, "zone_id": ZONE_ID, "hostname": "pay.example.com"}, cookies={"lnswitchboard_cloudflare_authorization": "authorization-flow-id"})
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)
    assert authorized.status_code == 200
    assert authorized.headers["cache-control"] == "no-store, private"
    assert authorized.json() == {"accounts": [{"id": ACCOUNT_ID, "name": "Example account", "zones": [{"id": ZONE_ID, "name": "example.com"}]}]}
    assert service.authorize_request == (secret, ACCOUNT_ID, TUNNEL_ID)
    assert secret not in authorized.text
    assert provisioned.status_code == 201
    assert provisioned.headers["cache-control"] == "no-store, private"
    assert service.provision_request and service.provision_request["tunnel_id"] == TUNNEL_ID
    assert secret not in provisioned.text


def test_cloudflare_authorize_requires_explicit_existing_tunnel_ids(test_client) -> None:
    response = test_client.post("/api/connections/cloudflare/authorize", json={"api_token": "secret"})
    assert response.status_code == 422
    assert response.headers["cache-control"] == "no-store, private"
    assert "secret" not in response.text


def test_cloudflare_api_lists_adds_and_removes_authorized_domains(test_client) -> None:
    service = FakeCloudflareService()
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = lambda: service
    try:
        provisioned = test_client.post(
            "/api/connections/cloudflare/provision",
            json={"account_id": ACCOUNT_ID, "tunnel_id": TUNNEL_ID, "zone_id": ZONE_ID, "hostname": "example.com"},
            cookies={"lnswitchboard_cloudflare_authorization": "authorization-flow-id"},
        )
        connection_id = provisioned.json()["id"]
        available = test_client.get(
            f"/api/connections/cloudflare/{connection_id}/domains/available"
        )
        added = test_client.post(
            f"/api/connections/cloudflare/{connection_id}/domains",
            json={"zone_id": SECOND_ZONE_ID, "hostname": "pay.example.net"},
        )
        removed = test_client.delete(
            f"/api/connections/cloudflare/{connection_id}/domains/pay.example.net"
        )
        refreshed = test_client.post(
            f"/api/connections/cloudflare/{connection_id}/status"
        )
        disconnected = test_client.delete(
            f"/api/connections/cloudflare/{connection_id}"
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)

    assert available.status_code == 200
    assert available.json() == {
        "zones": [{"id": SECOND_ZONE_ID, "name": "example.net"}]
    }
    assert available.headers["cache-control"] == "no-store, private"
    assert added.status_code == 201
    assert added.headers["cache-control"] == "no-store, private"
    assert [domain["hostname"] for domain in added.json()["domains"]] == [
        "example.com",
        "pay.example.net",
    ]
    assert removed.status_code == 200
    assert removed.headers["cache-control"] == "no-store, private"
    assert [domain["hostname"] for domain in removed.json()["domains"]] == [
        "example.com"
    ]
    assert refreshed.headers["cache-control"] == "no-store, private"
    assert disconnected.headers["cache-control"] == "no-store, private"


def test_cloudflare_unavailable_maps_to_conflict_without_secret_echo(test_client) -> None:
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = UnavailableCloudflareService
    try:
        response = test_client.post("/api/connections/cloudflare/authorize", json={"api_token": "secret", "account_id": ACCOUNT_ID, "tunnel_id": TUNNEL_ID})
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)
    assert response.status_code == 409
    assert response.headers["cache-control"] == "no-store, private"
    assert "secret" not in response.text
