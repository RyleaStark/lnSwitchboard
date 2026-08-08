from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import HTTPException

from backend.app import deps
from backend.app.cloudflare_client import CloudflareAPIError
from backend.app.cloudflare_oauth import CloudflareOAuthGrantNotFoundError
from backend.app.cloudflare_service import CloudflareUnavailableError
from backend.app.main import admin_app
from backend.app.routers import connections as connections_router

ACCOUNT_ID = "a" * 32
ZONE_ID = "b" * 32
SECOND_ZONE_ID = "d" * 32


class FakeCloudflareService:
    def __init__(self) -> None:
        self.authorize_request: tuple[str, str] | None = None
        self.discover_grant_request: str | None = None
        self.reauthorize_request: tuple[str, str] | None = None
        self.provision_request: dict[str, str] | None = None

    async def authorize_grant(self, grant_id: str, account_id: str):
        self.authorize_request = (grant_id, account_id)
        return {"authorization_id": "authorization-flow-id", "accounts": [{"id": account_id, "name": "Example account", "zones": [{"id": ZONE_ID, "name": "example.com"}]}]}

    async def discover_grant_accounts(self, grant_id: str):
        self.discover_grant_request = grant_id
        return [{"id": ACCOUNT_ID, "name": "Example account"}]

    async def provision(self, *, authorization_id: str, account_id: str, zone_id: str, hostname: str):
        self.provision_request = {"authorization_id": authorization_id, "account_id": account_id, "zone_id": zone_id, "hostname": hostname}
        store = deps._get_connection_store()
        connection = store.upsert_connection(provider="cloudflare", external_id="lnswitchboard-mesh-node", label="Cloudflare", status="provisioning", account_id=account_id, public_metadata={"origin": "http://lnswitchboard:21212"})
        store.replace_domains(connection.id, [{"hostname": hostname, "status": "pending", "zone_id": zone_id}])
        return store.get_connection(connection.id)

    async def reauthorize(self, connection_id: str, authorization_id: str):
        self.reauthorize_request = (connection_id, authorization_id)
        connection = deps._get_connection_store().get_connection(connection_id)
        assert connection is not None
        return connection

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
    async def authorize_grant(self, grant_id: str, account_id: str):
        raise CloudflareUnavailableError("not installed")


class ExplodingCloudflareService(FakeCloudflareService):
    async def authorize_grant(self, grant_id: str, account_id: str):
        raise RuntimeError("unexpected sensitive failure")


class ConflictingCloudflareService(FakeCloudflareService):
    async def authorize_grant(self, grant_id: str, account_id: str):
        raise CloudflareAPIError(409)


def test_cloudflare_configuration_conflict_is_returned_as_retryable_409(test_client) -> None:
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = (
        lambda: ConflictingCloudflareService()
    )
    try:
        response = test_client.post(
            "/api/connections/cloudflare/authorize",
            json={"grant_id": "test-grant", "account_id": ACCOUNT_ID},
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
            json={"grant_id": "test-grant", "account_id": ACCOUNT_ID},
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
    assert response.headers["cache-control"] == "no-store, private"
    assert response.json()["oauth_configured"] is False
    assert response.json()["available"] is False
    assert response.json()["configuration_error"] == (
        "Cloudflare OAuth client, callback, and approved scope IDs are not "
        "configured for this deployment."
    )
    assert response.json()["required_permissions"] == [
        "Account Settings Read (account-settings.read)",
        "Zone Read (zone.read)",
        "DNS Read and Write (dns.read, dns.write)",
        "Workers Scripts Read, Write, and Bind (workers-scripts.read, workers-scripts.write, workers-scripts.bind)",
        "Connectivity Directory Bind (connectivity-directory.bind)",
        "Workers Routes Read and Write (workers-routes.read, workers-routes.write)",
        "Cloudflare One Connector: WARP Read and Write (teams-connector-warp.read, teams-connector-warp.write)",
        "Zero Trust Read and Write (teams.read, teams.write)",
        "Access: Apps and Policies Read and Write (access.read, access.write)",
    ]
    assert response.json()["authorization_method"] == "oauth"


def test_cloudflare_oauth_validation_never_reflects_code_and_is_private(
    test_client,
) -> None:
    sentinel = "oauth-code-must-not-be-reflected-" * 100

    response = test_client.post(
        "/api/cloudflare/oauth/complete",
        json={"code": sentinel, "state": "valid-looking-state"},
    )

    assert response.status_code == 422
    assert sentinel not in response.text
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"


def test_cloudflare_grant_validation_never_reflects_grant_and_is_private(
    test_client,
) -> None:
    sentinel = "oauth-grant-must-not-be-reflected-" * 100

    response = test_client.post(
        "/api/connections/cloudflare/authorize",
        json={"grant_id": sentinel, "account_id": ACCOUNT_ID},
    )

    assert response.status_code == 422
    assert sentinel not in response.text
    assert response.json() == {"detail": "Invalid Cloudflare request"}
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"


def test_cloudflare_oauth_landing_route_is_served_by_the_spa(test_client) -> None:
    response = test_client.get(
        "/connections/cloudflare/?cloudflare=connected",
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")


def test_oauth_grant_in_use_by_connection_cannot_be_deleted(test_client) -> None:
    store = deps._get_connection_store()
    connection = store.upsert_connection(
        provider="cloudflare",
        external_id="lnswitchboard-test-mesh",
        label="Cloudflare Mesh",
        status="connected",
        account_id=ACCOUNT_ID,
        public_metadata={},
    )
    deps._get_connection_secret_store().set(
        connection.id,
        {"grant_id": "grant-in-use", "mesh_ingress_key": "test-key"},
    )

    response = test_client.delete(
        "/api/cloudflare/oauth/grants/grant-in-use"
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "Cloudflare OAuth grant is in use by a connection; reconnect or disconnect it first"
    )
    assert response.headers["cache-control"] == "no-store, private"


def test_oauth_grant_in_use_by_pending_authorization_cannot_be_deleted(
    test_client,
) -> None:
    deps._get_connection_secret_store().set(
        "cloudflare-authorization:" + "a" * 32,
        {"grant_id": "grant-in-use", "created_at": 1.0},
    )

    response = test_client.delete(
        "/api/cloudflare/oauth/grants/grant-in-use"
    )

    assert response.status_code == 409
    assert response.headers["cache-control"] == "no-store, private"


@pytest.mark.anyio
async def test_missing_referenced_oauth_grant_maps_to_reconnect_contract() -> None:
    async def missing_grant() -> None:
        raise CloudflareOAuthGrantNotFoundError

    with pytest.raises(HTTPException) as exc_info:
        await connections_router._cloudflare_call(missing_grant)

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == (
        "Cloudflare authorization expired; reconnect Cloudflare"
    )


@pytest.mark.anyio
async def test_unexpected_oauth_error_is_sanitized_and_private() -> None:
    marker = "authorization-code-must-not-be-reflected"

    class ExplodingOAuthManager:
        async def complete_flow(self, *, state: str, code: str):
            del state, code
            raise RuntimeError(marker)

    admin_app.dependency_overrides[deps.get_cloudflare_oauth_manager_dep] = (
        ExplodingOAuthManager
    )
    try:
        transport = ASGITransport(
            app=admin_app,
            raise_app_exceptions=False,
            client=("192.168.1.10", 50000),
        )
        async with AsyncClient(
            transport=transport,
            base_url="http://localhost",
        ) as client:
            response = await client.post(
                "/api/cloudflare/oauth/complete",
                json={"state": "valid-state", "code": marker},
                headers={"host": "localhost", "origin": "http://localhost"},
            )
    finally:
        admin_app.dependency_overrides.pop(
            deps.get_cloudflare_oauth_manager_dep, None
        )

    assert response.status_code == 500
    assert marker not in response.text
    assert response.headers["cache-control"] == "no-store, private"


def test_cloudflare_api_authorizes_with_grant_and_provisions_without_tunnel_ids(test_client) -> None:
    service = FakeCloudflareService()
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = lambda: service
    secret = "do-not-return-api-token"
    try:
        authorized = test_client.post("/api/connections/cloudflare/authorize", json={"grant_id": secret, "account_id": ACCOUNT_ID})
        provisioned = test_client.post("/api/connections/cloudflare/provision", json={"account_id": ACCOUNT_ID, "zone_id": ZONE_ID, "hostname": "pay.example.com"}, cookies={"lnswitchboard_cloudflare_authorization": "authorization-flow-id"})
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)
    assert authorized.status_code == 200
    assert authorized.headers["cache-control"] == "no-store, private"
    assert authorized.json() == {"accounts": [{"id": ACCOUNT_ID, "name": "Example account", "zones": [{"id": ZONE_ID, "name": "example.com"}]}]}
    assert service.authorize_request == (secret, ACCOUNT_ID)
    assert secret not in authorized.text
    assert provisioned.status_code == 201
    assert provisioned.headers["cache-control"] == "no-store, private"
    assert service.provision_request and "tunnel_id" not in service.provision_request
    assert secret not in provisioned.text


def test_cloudflare_api_reauthorizes_existing_connection_without_reprovisioning(
    test_client,
) -> None:
    service = FakeCloudflareService()
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = lambda: service
    try:
        provisioned = test_client.post(
            "/api/connections/cloudflare/provision",
            json={
                "account_id": ACCOUNT_ID,
                "zone_id": ZONE_ID,
                "hostname": "pay.example.com",
            },
            cookies={"lnswitchboard_cloudflare_authorization": "initial-flow"},
        )
        connection_id = provisioned.json()["id"]
        response = test_client.post(
            f"/api/connections/cloudflare/{connection_id}/reauthorize",
            cookies={
                "lnswitchboard_cloudflare_authorization": "replacement-flow"
            },
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private"
    assert service.reauthorize_request == (connection_id, "replacement-flow")
    assert "lnswitchboard_cloudflare_authorization=\"\"" in response.headers[
        "set-cookie"
    ]


def test_cloudflare_authorize_discovers_oauth_selected_accounts_without_account_id(test_client) -> None:
    service = FakeCloudflareService()
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = lambda: service
    try:
        response = test_client.post(
            "/api/connections/cloudflare/authorize", json={"grant_id": "test-grant"}
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private"
    assert response.json() == {
        "accounts": [{"id": ACCOUNT_ID, "name": "Example account", "zones": []}]
    }
    assert service.discover_grant_request == "test-grant"
    assert "set-cookie" not in response.headers


def test_cloudflare_api_lists_adds_and_removes_authorized_domains(test_client) -> None:
    service = FakeCloudflareService()
    admin_app.dependency_overrides[deps.get_cloudflare_service_dep] = lambda: service
    try:
        provisioned = test_client.post(
            "/api/connections/cloudflare/provision",
            json={"account_id": ACCOUNT_ID, "zone_id": ZONE_ID, "hostname": "example.com"},
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
        response = test_client.post("/api/connections/cloudflare/authorize", json={"grant_id": "test-grant", "account_id": ACCOUNT_ID})
    finally:
        admin_app.dependency_overrides.pop(deps.get_cloudflare_service_dep, None)
    assert response.status_code == 409
    assert response.headers["cache-control"] == "no-store, private"
    assert "secret" not in response.text
