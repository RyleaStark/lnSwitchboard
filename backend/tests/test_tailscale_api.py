from __future__ import annotations

import asyncio

import httpx
import pytest

from backend.app import deps
from backend.app.main import admin_app, public_app
from backend.app.routers import connections as connections_router


def _auth_url() -> str:
    return "https://" + "login.tailscale.com" + "/a/" + "TEST_ONLY_TOKEN"


@pytest.fixture(autouse=True)
def bypass_authenticated_proxy_gate():
    admin_app.dependency_overrides[
        connections_router.require_authenticated_tailscale_admin
    ] = lambda: None
    yield
    admin_app.dependency_overrides.pop(
        connections_router.require_authenticated_tailscale_admin, None
    )


class FakeTailscaleService:
    login_ttl_seconds = 300

    def __init__(self) -> None:
        self.device_names: list[str | None] = []
        self.flow_ids: list[str] = []
        self.disconnected: list[str] = []

    def setup(self):
        return {
            "available": True,
            "authorization_method": "web_login",
            "default_device_name": "lns",
            "device_name_max_length": 63,
            "public_origin": "http://127.0.0.1:21212",
            "public_port": 443,
            "required_tag": "tag:lnswitchboard",
            "prerequisites": [
                "magic_dns",
                "https_certificates",
                "funnel_node_attribute",
                "funnel_port_443",
            ],
        }

    async def begin_login(self, device_name):
        self.device_names.append(device_name)
        return "private-flow-id", {
            "state": "needs_login",
            "device_name": "lns",
            "auth_url": _auth_url(),
            "expires_in_seconds": 300,
        }

    async def poll_login(self, flow_id):
        self.flow_ids.append(flow_id)
        return {
            "state": "needs_login",
            "device_name": "lns",
            "auth_url": _auth_url(),
            "expires_in_seconds": 299,
        }

    async def cancel_login(self, flow_id):
        self.flow_ids.append(flow_id)
        return True

    async def disconnect(self, connection_id):
        self.disconnected.append(connection_id)
        return True


def test_tailscale_setup_and_begin_login_use_lns_default_and_private_cookie(
    test_client,
) -> None:
    service = FakeTailscaleService()
    admin_app.dependency_overrides[deps.get_tailscale_service_dep] = lambda: service
    try:
        setup = test_client.get("/api/connections/tailscale/setup")
        login = test_client.post(
            "/api/connections/tailscale/login", json={"device_name": "lns"}
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_tailscale_service_dep, None)

    assert setup.status_code == 200
    assert setup.json()["default_device_name"] == "lns"
    assert setup.json()["public_port"] == 443
    assert service.device_names == ["lns"]
    assert login.status_code == 200
    assert login.json()["auth_url"] == _auth_url()
    assert "flow" not in login.text.lower()
    cookie = login.headers["set-cookie"]
    assert "lnswitchboard_tailscale_login=" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie
    assert "Path=/api/connections/tailscale" in cookie
    assert "Max-Age=300" in cookie


def test_tailscale_login_status_requires_private_flow_cookie(test_client) -> None:
    service = FakeTailscaleService()
    admin_app.dependency_overrides[deps.get_tailscale_service_dep] = lambda: service
    try:
        missing = test_client.get("/api/connections/tailscale/login")
        found = test_client.get(
            "/api/connections/tailscale/login",
            cookies={"lnswitchboard_tailscale_login": "private-flow-id"},
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_tailscale_service_dep, None)

    assert missing.status_code == 404
    assert found.status_code == 200
    assert found.json()["state"] == "needs_login"
    assert service.flow_ids == ["private-flow-id"]


def test_tailscale_login_request_accepts_only_bounded_device_name(test_client) -> None:
    service = FakeTailscaleService()
    admin_app.dependency_overrides[deps.get_tailscale_service_dep] = lambda: service
    try:
        extra = test_client.post(
            "/api/connections/tailscale/login",
            json={"device_name": "lns", "domain": "must-not-be-accepted.example"},
        )
        oversized = test_client.post(
            "/api/connections/tailscale/login", json={"device_name": "a" * 64}
        )
    finally:
        admin_app.dependency_overrides.pop(deps.get_tailscale_service_dep, None)

    assert extra.status_code == 422
    assert oversized.status_code == 422
    assert service.device_names == []


def test_tailscale_disconnect_deletes_only_after_service_success(test_client) -> None:
    service = FakeTailscaleService()
    admin_app.dependency_overrides[deps.get_tailscale_service_dep] = lambda: service
    try:
        response = test_client.delete("/api/connections/tailscale/connection-123")
    finally:
        admin_app.dependency_overrides.pop(deps.get_tailscale_service_dep, None)

    assert response.status_code == 200
    assert response.json() == {"disconnected": True}
    assert service.disconnected == ["connection-123"]


def test_public_listener_has_no_tailscale_onboarding_route() -> None:
    async def request_public():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(
                app=public_app, client=("203.0.113.10", 54321)
            ),
            base_url="http://testserver",
        ) as client:
            return await client.get("/api/connections/tailscale/setup")

    response = asyncio.run(request_public())
    assert response.status_code == 404
