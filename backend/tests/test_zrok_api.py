from __future__ import annotations

import asyncio

import httpx
from backend.app import deps
from backend.app.main import admin_app, public_app


class FakeZrokService:
    def __init__(self) -> None:
        self.provisioned: list[dict[str, str]] = []
        self.refreshed: list[str] = []
        self.disconnected: list[str] = []

    def setup(self):
        return {
            "available": True,
            "modes": ["cloud", "self_hosted"],
            "cloud_api_endpoint": "https://api-v2.zrok.io",
            "default_namespace": "public",
            "public_origin": "http://public:21212",
            "cloud_interstitial_warning": True,
        }

    async def provision(self, *, mode, account_token, api_endpoint, namespace, name):
        self.provisioned.append(
            {
                "mode": mode,
                "account_token": account_token,
                "api_endpoint": api_endpoint,
                "namespace": namespace,
                "name": name,
            }
        )
        return {
            "id": "zrok-connection",
            "provider": "zrok",
            "external_id": "public:pay-bones",
            "label": "zrok Cloud",
            "status": "connected",
            "account_id": None,
            "public_metadata": {"mode": mode, "namespace": namespace, "name": name},
            "last_error": None,
            "created_at": "2026-08-12T00:00:00+00:00",
            "updated_at": "2026-08-12T00:00:00+00:00",
            "domains": [
                {
                    "hostname": "pay-bones.share.zrok.io",
                    "status": "active",
                    "external_id": "public:pay-bones",
                    "zone_id": None,
                    "last_error": None,
                }
            ],
        }

    async def refresh(self, connection_id):
        self.refreshed.append(connection_id)
        return await self.provision(
            mode="cloud",
            account_token="not-returned",
            api_endpoint="https://api-v2.zrok.io",
            namespace="public",
            name="pay-bones",
        )

    async def disconnect(self, connection_id):
        self.disconnected.append(connection_id)
        return True


def test_zrok_setup_and_cloud_provision_are_private_and_token_is_not_returned(test_client) -> None:
    service = FakeZrokService()
    admin_app.dependency_overrides[deps.get_zrok_service_dep] = lambda: service
    try:
        setup = test_client.get("/api/connections/zrok/setup")
        response = test_client.post(
            "/api/connections/zrok/provision",
            json={
                "mode": "cloud",
                "account_token": "secret-account-token",
                "namespace": "public",
                "name": "pay-bones",
            },
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_zrok_service_dep, None)

    assert setup.status_code == 200
    assert setup.json()["modes"] == ["cloud", "self_hosted"]
    assert setup.json()["cloud_api_endpoint"] == "https://api-v2.zrok.io"
    assert setup.headers["cache-control"] == "no-store, private"
    assert response.status_code == 201
    assert response.json()["provider"] == "zrok"
    assert response.json()["domains"][0]["hostname"] == "pay-bones.share.zrok.io"
    assert "secret-account-token" not in response.text
    assert service.provisioned == [
        {
            "mode": "cloud",
            "account_token": "secret-account-token",
            "api_endpoint": "https://api-v2.zrok.io",
            "namespace": "public",
            "name": "pay-bones",
        }
    ]


def test_zrok_self_hosted_requires_explicit_https_endpoint(test_client) -> None:
    service = FakeZrokService()
    admin_app.dependency_overrides[deps.get_zrok_service_dep] = lambda: service
    try:
        missing = test_client.post(
            "/api/connections/zrok/provision",
            json={
                "mode": "self_hosted",
                "account_token": "secret-account-token",
                "namespace": "public",
                "name": "pay-bones",
            },
        )
        insecure = test_client.post(
            "/api/connections/zrok/provision",
            json={
                "mode": "self_hosted",
                "account_token": "secret-account-token",
                "api_endpoint": "http://zrok.example.com",
                "namespace": "public",
                "name": "pay-bones",
            },
        )
        private = test_client.post(
            "/api/connections/zrok/provision",
            json={
                "mode": "self_hosted",
                "account_token": "secret-account-token",
                "api_endpoint": "https://localhost",
                "namespace": "public",
                "name": "pay-bones",
            },
        )
        valid = test_client.post(
            "/api/connections/zrok/provision",
            json={
                "mode": "cloud",
                "account_token": "secret-account-token",
                "api_endpoint": "https://zrok.example.com",
                "namespace": "public",
                "name": "pay-bones",
            },
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_zrok_service_dep, None)

    assert missing.status_code == 422
    assert insecure.status_code == 422
    assert private.status_code == 422
    assert valid.status_code == 201
    assert service.provisioned[-1]["api_endpoint"] == "https://api-v2.zrok.io"


def test_zrok_request_forbids_generic_target_and_extra_provider_authority(test_client) -> None:
    service = FakeZrokService()
    admin_app.dependency_overrides[deps.get_zrok_service_dep] = lambda: service
    try:
        response = test_client.post(
            "/api/connections/zrok/provision",
            json={
                "mode": "cloud",
                "account_token": "secret-account-token",
                "namespace": "public",
                "name": "pay-bones",
                "target": "http://admin:22121",
            },
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_zrok_service_dep, None)

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid zrok request"}
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
    assert "secret-account-token" not in response.text
    assert service.provisioned == []


def test_public_listener_has_no_zrok_onboarding_route() -> None:
    async def request_public():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=public_app, client=("203.0.113.10", 54321)),
            base_url="http://testserver",
        ) as client:
            return await client.get("/api/connections/zrok/setup")

    response = asyncio.run(request_public())
    assert response.status_code == 404
