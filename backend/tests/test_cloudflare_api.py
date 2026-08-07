from __future__ import annotations

from backend.app import deps
from backend.app.cloudflare_service import CloudflareUnavailableError
from backend.app.main import admin_app

ACCOUNT_ID = "a" * 32
TUNNEL_ID = "1" * 32
ZONE_ID = "b" * 32


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

    async def disconnect(self, _connection_id: str) -> bool:
        return True


class UnavailableCloudflareService(FakeCloudflareService):
    async def authorize(self, api_token: str, account_id: str, tunnel_id: str):
        raise CloudflareUnavailableError("not installed")


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
    assert authorized.json() == {"accounts": [{"id": ACCOUNT_ID, "name": "Example account", "zones": [{"id": ZONE_ID, "name": "example.com"}]}]}
    assert service.authorize_request == (secret, ACCOUNT_ID, TUNNEL_ID)
    assert secret not in authorized.text
    assert provisioned.status_code == 201
    assert service.provision_request and service.provision_request["tunnel_id"] == TUNNEL_ID
    assert secret not in provisioned.text


def test_cloudflare_authorize_requires_explicit_existing_tunnel_ids(test_client) -> None:
    response = test_client.post("/api/connections/cloudflare/authorize", json={"api_token": "secret"})
    assert response.status_code == 422
    assert "secret" not in response.text


def test_cloudflare_unavailable_maps_to_conflict_without_secret_echo(test_client) -> None:
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = UnavailableCloudflareService
    try:
        response = test_client.post("/api/connections/cloudflare/authorize", json={"api_token": "secret", "account_id": ACCOUNT_ID, "tunnel_id": TUNNEL_ID})
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)
    assert response.status_code == 409
    assert "secret" not in response.text
