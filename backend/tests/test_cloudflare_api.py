from __future__ import annotations

from backend.app import deps
from backend.app.cloudflare_service import CloudflareUnavailableError
from backend.app.main import admin_app
from backend.app.routers.connections import require_authenticated_cloudflare_admin


class FakeCloudflareService:
    def __init__(self) -> None:
        self.authorized_token: str | None = None
        self.provision_request: dict[str, str] | None = None
        self.disconnected_id: str | None = None

    async def authorize(self, api_token: str):
        self.authorized_token = api_token
        return {
            "authorization_id": "authorization-flow-id",
            "accounts": [
                {
                    "id": "a" * 32,
                    "name": "Example Account",
                    "zones": [{"id": "b" * 32, "name": "example.com"}],
                }
            ],
        }

    async def provision(
        self, *, authorization_id: str, account_id: str, zone_id: str, hostname: str
    ):
        self.provision_request = {
            "authorization_id": authorization_id,
            "account_id": account_id,
            "zone_id": zone_id,
            "hostname": hostname,
        }
        store = deps._get_connection_store()
        connection = store.upsert_connection(
            provider="cloudflare",
            external_id="tunnel-id",
            label="Cloudflare Tunnel",
            status="provisioning",
            account_id=account_id,
            public_metadata={"origin": "http://lnswitchboard:21212"},
        )
        store.replace_domains(
            connection.id,
            [{"hostname": hostname, "status": "pending", "zone_id": zone_id}],
        )
        return store.get_connection(connection.id)

    async def refresh_status(self, connection_id: str):
        return deps._get_connection_store().get_connection(connection_id)

    async def disconnect(self, connection_id: str) -> bool:
        self.disconnected_id = connection_id
        return True


class UnavailableCloudflareService(FakeCloudflareService):
    async def authorize(self, api_token: str):
        raise CloudflareUnavailableError("not installed")


def test_cloudflare_setup_documents_exact_permissions_and_public_origin(
    test_client,
) -> None:
    response = test_client.get("/api/connections/cloudflare/setup")

    assert response.status_code == 200
    assert response.json() == {
        "available": False,
        "origin": "http://lnswitchboard:21212",
        "required_permissions": [
            "Account / Cloudflare Tunnel / Edit",
            "Account / Account Settings / Read",
            "Zone / DNS / Edit",
            "Zone / Zone / Read",
        ],
        "authorization_method": "api_token",
    }
    assert "22121" not in response.text


def test_cloudflare_authorize_and_provision_never_return_credentials(
    test_client,
) -> None:
    service = FakeCloudflareService()
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = lambda: service
    admin_app.dependency_overrides[require_authenticated_cloudflare_admin] = lambda: None
    api_token = "do-not-return-api-token"
    try:
        authorized = test_client.post(
            "/api/connections/cloudflare/authorize",
            json={"api_token": api_token},
        )
        provisioned = test_client.post(
            "/api/connections/cloudflare/provision",
            json={
                "account_id": "a" * 32,
                "zone_id": "b" * 32,
                "hostname": "pay.example.com",
            },
            cookies={"lnswitchboard_cloudflare_authorization": "authorization-flow-id"},
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)
        admin_app.dependency_overrides.pop(require_authenticated_cloudflare_admin, None)

    assert authorized.status_code == 200
    assert service.authorized_token == api_token
    assert api_token not in authorized.text
    assert "authorization_id" not in authorized.text
    assert authorized.json()["accounts"][0]["name"] == "Example Account"
    cookie = authorized.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie
    assert provisioned.status_code == 201
    assert provisioned.json()["status"] == "provisioning"
    assert provisioned.json()["domains"][0]["hostname"] == "pay.example.com"
    assert api_token not in provisioned.text
    assert "connector_token" not in provisioned.text


def test_cloudflare_unavailable_maps_to_conflict_without_secret_echo(
    test_client,
) -> None:
    service = UnavailableCloudflareService()
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = lambda: service
    admin_app.dependency_overrides[require_authenticated_cloudflare_admin] = lambda: None
    try:
        response = test_client.post(
            "/api/connections/cloudflare/authorize",
            json={"api_token": "secret"},
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)
        admin_app.dependency_overrides.pop(require_authenticated_cloudflare_admin, None)

    assert response.status_code == 409
    assert response.json() == {"detail": "Cloudflare connector is not installed"}
    assert "secret" not in response.text


def test_malformed_authorization_never_echoes_secret_input(test_client) -> None:
    malformed_secret = "super-secret-malformed"
    admin_app.dependency_overrides[require_authenticated_cloudflare_admin] = lambda: None
    try:
        wrong_type = test_client.post(
            "/api/connections/cloudflare/authorize",
            json={"api_token": [malformed_secret]},
        )
        oversized = test_client.post(
            "/api/connections/cloudflare/authorize",
            json={"api_token": malformed_secret * 300},
        )
    finally:
        admin_app.dependency_overrides.pop(require_authenticated_cloudflare_admin, None)

    assert wrong_type.status_code == 422
    assert oversized.status_code == 422
    assert malformed_secret not in wrong_type.text
    assert malformed_secret not in oversized.text
    assert wrong_type.json() == {"detail": "Invalid Cloudflare authorization request"}


def test_cloudflare_authorization_rejects_direct_http_administration(test_client) -> None:
    response = test_client.post(
        "/api/connections/cloudflare/authorize",
        json={"api_token": "token"},
    )

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Cloudflare onboarding requires an authenticated HTTPS admin proxy"
    }
