from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ..app import deps
from ..app.config import Settings, get_settings, parse_trusted_hosts, parse_trusted_proxy_cidrs
from ..app.outbound_security import UnsafeOutboundTarget, ensure_public_endpoint, post_to_pinned_endpoint


def test_admin_api_does_not_allow_cross_origin_reads(test_client) -> None:
    response = test_client.get(
        "/api/health",
        headers={"Origin": "https://untrusted.example"},
    )

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_untrusted_host_header_is_rejected(test_client) -> None:
    response = test_client.get("/api/health", headers={"Host": "attacker.example"})

    assert response.status_code == 400
    assert response.text == "Invalid host header"


@pytest.mark.parametrize(
    "host_header",
    [
        "evil@testserver",
        "testserver/path",
        "testserver?query",
        "testserver#fragment",
        "testserver:bad",
        "testserver,attacker.example",
        "test server",
        "testserver..",
        "testserver...",
    ],
)
def test_malformed_authority_cannot_match_a_trusted_host(test_client, host_header: str) -> None:
    response = test_client.get("/api/health", headers={"Host": host_header})

    assert response.status_code == 400
    assert response.text == "Invalid host header"


@pytest.mark.parametrize(
    "host_header",
    [
        " pay.example.com ",
        "evil@pay.example.com",
        "pay.example.com/path",
        "pay.example.com..",
    ],
)
def test_malformed_authority_cannot_match_a_registered_domain(
    test_client, host_header: str
) -> None:
    store = deps._get_connection_store()
    connection = store.upsert_connection(
        provider="cloudflare",
        external_id="dynamic-host-test",
        label="Cloudflare Tunnel",
        status="connected",
    )
    store.replace_domains(
        connection.id,
        [{"hostname": "pay.example.com", "status": "active"}],
    )

    response = test_client.get("/api/health", headers={"Host": host_header})

    assert response.status_code == 400
    assert response.text == "Invalid host header"


def test_trusted_host_wildcard_allows_only_subdomains(monkeypatch, test_client) -> None:
    monkeypatch.setenv("TRUSTED_HOSTS", "*.example.com")
    get_settings.cache_clear()
    try:
        assert test_client.get("/api/health", headers={"Host": "pay.example.com"}).status_code == 200
        assert test_client.get("/api/health", headers={"Host": "example.com"}).status_code == 400
    finally:
        get_settings.cache_clear()


def test_trusted_proxy_cannot_forward_an_untrusted_host(monkeypatch, test_client) -> None:
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "192.168.50.10/32")
    monkeypatch.setenv("TRUSTED_HOSTS", "testserver")
    get_settings.cache_clear()
    try:
        response = test_client.get(
            "/api/health",
            headers={
                "Host": "testserver",
                "X-Forwarded-For": "192.168.50.20",
                "X-Forwarded-Host": "attacker.example",
            },
        )
        assert response.status_code == 400
    finally:
        get_settings.cache_clear()


def test_trusted_proxy_networks_are_explicit_and_validated() -> None:
    networks = parse_trusted_proxy_cidrs("127.0.0.1, 172.18.0.0/16")

    assert [str(network) for network in networks] == ["127.0.0.1/32", "172.18.0.0/16"]
    with pytest.raises(ValueError):
        parse_trusted_proxy_cidrs("not-a-network")


def test_trusted_hosts_support_exact_and_wildcard_entries() -> None:
    assert parse_trusted_hosts("localhost, *.example.com, [::1]") == (
        "localhost",
        "*.example.com",
        "::1",
    )


def test_invalid_trusted_proxy_setting_is_rejected(monkeypatch) -> None:
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "not-a-network")

    with pytest.raises(ValueError):
        Settings()


def test_outbound_endpoint_validation_returns_a_pinned_public_address() -> None:
    address = asyncio.run(
        ensure_public_endpoint(
            "https://8.8.8.8/hook",
            allowed_schemes=("https",),
        )
    )

    assert address == "8.8.8.8"
    with pytest.raises(UnsafeOutboundTarget, match="credentials"):
        asyncio.run(
            ensure_public_endpoint(
                "https://user:password@example.com/hook",
                allowed_schemes=("https",),
            )
        )


def test_pinned_webhook_connection_preserves_host_and_path() -> None:
    received: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            received.update(
                host=self.headers["Host"],
                path=self.path,
                body=self.rfile.read(length).decode(),
            )
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        asyncio.run(
            post_to_pinned_endpoint(
                f"http://webhook.example:{port}/payments?id=1",
                connect_host="127.0.0.1",
                body=b'{"ok":true}',
                headers={"Content-Type": "application/json"},
                timeout=2,
            )
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert received == {
        "host": f"webhook.example:{port}",
        "path": "/payments?id=1",
        "body": '{"ok":true}',
    }


@pytest.mark.parametrize(
    "path",
    [
        "/invoices/",
        "/liquidity/",
        "/logs/",
        "/addresses/",
        "/identities/",
        "/settings/",
        "/webhooks/",
        "/connections/cloudflare/",
    ],
)
def test_spa_routes_serve_frontend_entrypoint(test_client, path: str) -> None:
    response = test_client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<title>lnSwitchboard</title>" in response.text
