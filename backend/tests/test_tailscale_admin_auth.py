from __future__ import annotations

import asyncio

import httpx

from backend.app import deps
from backend.app.config import get_settings
from backend.app.main import admin_app


def _request_setup(*, peer: str, headers: dict[str, str], base_url: str) -> int:
    async def request() -> int:
        transport = httpx.ASGITransport(app=admin_app, client=(peer, 12345))
        async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
            response = await client.get(
                "/api/connections/tailscale/setup", headers=headers
            )
            return response.status_code

    return asyncio.run(request())


def _reset_settings() -> None:
    get_settings.cache_clear()
    deps._get_tailscale_service.cache_clear()


def test_tailscale_onboarding_rejects_direct_lan_without_authenticated_proxy(
    monkeypatch,
) -> None:
    monkeypatch.setenv("DEP_ENV", "DOCKER")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "")
    monkeypatch.setenv("TRUSTED_HOSTS", "admin.test")
    _reset_settings()

    assert (
        _request_setup(
            peer="192.168.1.50",
            headers={"host": "admin.test"},
            base_url="http://admin.test",
        )
        == 403
    )


def test_tailscale_onboarding_requires_authenticated_https_trusted_proxy(
    monkeypatch,
) -> None:
    monkeypatch.setenv("DEP_ENV", "DOCKER")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "10.0.0.2/32")
    monkeypatch.setenv("TRUSTED_HOSTS", "admin.test")
    _reset_settings()
    forwarded = {
        "host": "admin.test",
        "x-forwarded-for": "192.168.1.50",
        "x-forwarded-proto": "https",
    }

    assert (
        _request_setup(peer="10.0.0.2", headers=forwarded, base_url="http://admin.test")
        == 403
    )
    assert (
        _request_setup(
            peer="10.0.0.2",
            headers={
                **forwarded,
                "x-forwarded-user": "bones",
                "x-forwarded-proto": "http",
            },
            base_url="http://admin.test",
        )
        == 403
    )
    assert (
        _request_setup(
            peer="10.0.0.2",
            headers={**forwarded, "x-forwarded-user": "bones"},
            base_url="http://admin.test",
        )
        == 200
    )
