from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from backend.app import config, main, server


class AppClient:
    def __init__(self, app: Any, *, port: int, client_host: str = "127.0.0.1") -> None:
        self.app = app
        self.base_url = f"http://testserver:{port}"
        self.client_host = client_host

    async def _request_async(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app, client=(self.client_host, 54321)),
            base_url=self.base_url,
        ) as client:
            return await client.request(method, path, **kwargs)

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return asyncio.run(self._request_async(method, path, **kwargs))

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", path, **kwargs)


@pytest.fixture
def listener_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[AppClient, AppClient]:
    async def fake_list_channels(self: Any, public_only: bool = True) -> list[dict[str, Any]]:
        del self, public_only
        return [{"active": True, "private": False, "receiving_capacity_sat": 1000}]

    monkeypatch.setattr("backend.app.ln_client.LNClient.list_channels", fake_list_channels)
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
    monkeypatch.setenv("TRUSTED_HOSTS", "*")
    config.get_settings.cache_clear()

    return (
        AppClient(main.app, port=22121, client_host="192.168.50.10"),
        AppClient(main.app, port=21212),
    )


def test_listener_route_tables_are_separate(listener_clients: tuple[AppClient, AppClient]) -> None:
    admin, public = listener_clients

    assert admin.get("/api/health").status_code == 200
    assert admin.get("/.well-known/nostr.json").status_code == 404
    assert public.get("/api/health").status_code == 404
    assert public.get("/").status_code == 404
    assert public.get("/docs").status_code == 404


def test_dispatcher_uses_configured_public_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PUBLIC_SERVICE_PORT", "31212")
    config.get_settings.cache_clear()

    configured_public = AppClient(main.app, port=31212)
    old_default = AppClient(main.app, port=21212)

    assert configured_public.get("/api/health").status_code == 404
    assert old_default.get("/api/health").status_code == 200


def test_server_uses_configured_bind_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SERVICE_HOST", "127.0.0.2")
    monkeypatch.setenv("SERVICE_PORT", "32121")
    monkeypatch.setenv("PUBLIC_SERVICE_HOST", "127.0.0.3")
    monkeypatch.setenv("PUBLIC_SERVICE_PORT", "31212")
    config.get_settings.cache_clear()
    created: list[tuple[str, int]] = []

    class FakeListener:
        def close(self) -> None:
            pass

    class FakeServer:
        def __init__(self, uvicorn_config: Any) -> None:
            self.config = uvicorn_config

        def run(self, *, sockets: list[FakeListener]) -> None:
            assert len(sockets) == 2

    def fake_listener(host: str, port: int) -> FakeListener:
        created.append((host, port))
        return FakeListener()

    monkeypatch.setattr(server, "_listener", fake_listener)
    monkeypatch.setattr(server.uvicorn, "Server", FakeServer)

    server.main()

    assert created == [("127.0.0.2", 32121), ("127.0.0.3", 31212)]


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "::ffff:192.168.50.10",
        "::1",
        "fd00::1",
        "fe80::1",
    ],
)
def test_admin_lan_address_ranges(address: str) -> None:
    assert main._is_lan_address(address)


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "100.64.0.1",
        "198.51.100.10",
        "::ffff:100.64.0.1",
        "::ffff:198.51.100.10",
        "2001:4860:4860::8888",
    ],
)
def test_admin_rejects_non_lan_address_ranges(address: str) -> None:
    assert not main._is_lan_address(address)


def test_admin_listener_allows_direct_lan_and_rejects_direct_wan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEP_ENV", "DOCKER")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "")
    monkeypatch.setenv("TRUSTED_HOSTS", "*")
    config.get_settings.cache_clear()

    lan = AppClient(main.app, port=22121, client_host="192.168.50.10")
    wan = AppClient(main.app, port=22121, client_host="198.51.100.10")

    assert lan.get("/api/health").status_code == 200
    assert wan.get("/api/health").status_code == 403


def test_wan_peer_cannot_spoof_lan_forwarding_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEP_ENV", "DOCKER")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "192.168.50.0/24")
    monkeypatch.setenv("TRUSTED_HOSTS", "*")
    config.get_settings.cache_clear()
    wan = AppClient(main.app, port=22121, client_host="198.51.100.10")

    response = wan.get(
        "/api/health",
        headers={"X-Forwarded-For": "192.168.50.10"},
    )

    assert response.status_code == 403


def test_generic_proxy_allows_lan_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEP_ENV", "DOCKER")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "192.168.50.2/32")
    monkeypatch.setenv("TRUSTED_HOSTS", "*")
    config.get_settings.cache_clear()
    proxy = AppClient(main.app, port=22121, client_host="192.168.50.2")

    response = proxy.get(
        "/api/health",
        headers={"X-Forwarded-For": "192.168.50.10"},
    )

    assert response.status_code == 200


def test_generic_proxy_rejects_prepended_spoofed_lan_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEP_ENV", "DOCKER")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "192.168.50.2/32")
    monkeypatch.setenv("TRUSTED_HOSTS", "*")
    config.get_settings.cache_clear()
    proxy = AppClient(main.app, port=22121, client_host="192.168.50.2")

    response = proxy.get(
        "/api/health",
        headers={"X-Forwarded-For": "192.168.50.10, 198.51.100.10"},
    )

    assert response.status_code == 403


def test_generic_proxy_cannot_forward_wan_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEP_ENV", "DOCKER")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "192.168.50.2/32")
    monkeypatch.setenv("TRUSTED_HOSTS", "*")
    config.get_settings.cache_clear()
    proxy = AppClient(main.app, port=22121, client_host="192.168.50.2")

    response = proxy.get(
        "/api/health",
        headers={"X-Forwarded-For": "198.51.100.10"},
    )

    assert response.status_code == 403


def test_ipv4_mapped_proxy_preserves_wan_client_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEP_ENV", "DOCKER")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "192.168.50.2/32")
    monkeypatch.setenv("TRUSTED_HOSTS", "*")
    config.get_settings.cache_clear()
    proxy = AppClient(main.app, port=22121, client_host="::ffff:192.168.50.2")

    response = proxy.get(
        "/api/health",
        headers={"X-Forwarded-For": "198.51.100.10"},
    )

    assert response.status_code == 403


def test_umbrel_app_proxy_can_forward_authenticated_wan_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEP_ENV", "UMBREL")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "10.21.0.0/16")
    monkeypatch.setenv("TRUSTED_HOSTS", "*")
    config.get_settings.cache_clear()
    app_proxy = AppClient(main.app, port=22121, client_host="10.21.0.2")

    response = app_proxy.get(
        "/api/health",
        headers={"X-Forwarded-For": "198.51.100.10"},
    )

    assert response.status_code == 200


def test_umbrel_mode_does_not_treat_public_trusted_peer_as_app_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEP_ENV", "UMBREL")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "0.0.0.0/0")
    monkeypatch.setenv("TRUSTED_HOSTS", "*")
    config.get_settings.cache_clear()
    public_peer = AppClient(main.app, port=22121, client_host="198.51.100.10")

    response = public_peer.get(
        "/api/health",
        headers={"X-Forwarded-For": "192.168.50.10"},
    )

    assert response.status_code == 403


def test_public_listener_rejects_unconfigured_forwarded_domain(
    listener_clients: tuple[AppClient, AppClient],
) -> None:
    _admin, public = listener_clients

    response = public.get(
        "/.well-known/nostr.json",
        headers={"X-Forwarded-Host": "unconfigured.example"},
    )

    assert response.status_code == 404


def test_lightning_address_domain_allows_public_listener(
    listener_clients: tuple[AppClient, AppClient],
) -> None:
    admin, public = listener_clients
    created = admin.post(
        "/api/lnaddresses",
        json={"local_part": "alice", "domain": "pay.example"},
    )
    assert created.status_code == 201, created.text

    response = public.get(
        "/.well-known/lnurlp/alice",
        headers={"Host": "pay.example"},
    )

    assert response.status_code == 200
    assert response.json()["callback"].startswith("http://pay.example/")


def test_trusted_forwarded_header_domain_allows_public_listener(
    listener_clients: tuple[AppClient, AppClient],
) -> None:
    admin, public = listener_clients
    created = admin.post(
        "/api/lnaddresses",
        json={"local_part": "alice", "domain": "pay.example"},
    )
    assert created.status_code == 201, created.text

    response = public.get(
        "/.well-known/lnurlp/alice",
        headers={
            "Forwarded": "for=198.51.100.10;proto=https;host=pay.example",
        },
    )

    assert response.status_code == 200


def test_untrusted_peer_cannot_authorize_configured_forwarded_domain(
    listener_clients: tuple[AppClient, AppClient],
) -> None:
    admin, _public = listener_clients
    created = admin.post(
        "/api/lnaddresses",
        json={"local_part": "alice", "domain": "pay.example"},
    )
    assert created.status_code == 201, created.text
    untrusted_public = AppClient(main.app, port=21212, client_host="198.51.100.10")

    response = untrusted_public.get(
        "/.well-known/lnurlp/alice",
        headers={"X-Forwarded-Host": "pay.example"},
    )

    assert response.status_code == 404


def test_nostr_identity_domain_allows_public_listener(
    listener_clients: tuple[AppClient, AppClient],
) -> None:
    admin, public = listener_clients
    pubkey = "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"
    created = admin.post(
        "/api/nip05/identities",
        json={
            "local_part": "alice",
            "domain": "nostr.example",
            "npub": pubkey,
            "relays": [],
        },
    )
    assert created.status_code == 201, created.text

    response = public.get(
        "/.well-known/nostr.json",
        params={"name": "alice"},
        headers={"X-Forwarded-Host": "nostr.example"},
    )

    assert response.status_code == 200
    assert response.json()["names"] == {"alice": pubkey}
