from __future__ import annotations

import asyncio
import ast
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from pydantic import ValidationError

from ..app import deps
from ..app.config import Settings, get_settings, parse_trusted_hosts, parse_trusted_proxy_cidrs
from ..app.outbound_security import UnsafeOutboundTarget, ensure_public_endpoint, post_to_pinned_endpoint


def _is_exception_type_name(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "__name__"
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "type"
        and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Name)
        and node.value.args[0].id == "exc"
    )


def _contains_raw_caught_exception(node: ast.AST) -> bool:
    if _is_exception_type_name(node):
        return False
    if isinstance(node, ast.Name) and node.id == "exc":
        return True
    return any(_contains_raw_caught_exception(child) for child in ast.iter_child_nodes(node))


def test_cached_settings_load_the_configured_writable_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / "runtime.env"
    env_file.write_text(
        "PUBLIC_FALLBACK_MODE=redirect\n"
        "PUBLIC_FALLBACK_REDIRECT_URL=https://example.com/payments\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("LNSWITCHBOARD_ENV_FILE", str(env_file))
    monkeypatch.delenv("PUBLIC_FALLBACK_MODE", raising=False)
    monkeypatch.delenv("PUBLIC_FALLBACK_REDIRECT_URL", raising=False)
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.public_fallback_mode == "redirect"
    assert settings.public_fallback_redirect_url == "https://example.com/payments"


def test_runtime_logging_never_interpolates_raw_caught_exceptions() -> None:
    app_root = Path(__file__).resolve().parents[1] / "app"
    violations: list[str] = []
    for path in sorted(app_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"debug", "info", "warning", "error", "exception", "critical"}:
                continue
            if node.func.attr == "exception" or any(
                _contains_raw_caught_exception(argument) for argument in (*node.args, *[kw.value for kw in node.keywords])
            ):
                violations.append(f"{path.relative_to(app_root)}:{node.lineno}")
    assert violations == []


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


@pytest.mark.parametrize(
    "host_header",
    [
        ".example.com",
        "foo..example.com",
        "-pay.example.com",
        "pay-.example.com",
        "pay.ex_ample.com",
    ],
)
def test_malformed_authority_cannot_match_wildcard_trusted_host(
    monkeypatch, test_client, host_header: str
) -> None:
    monkeypatch.setenv("TRUSTED_HOSTS", "*.example.com")
    get_settings.cache_clear()
    try:
        response = test_client.get("/api/health", headers={"Host": host_header})
        assert response.status_code == 400
        assert response.text == "Invalid host header"
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


def test_sensitive_config_path_preserves_final_symlink_for_store_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "outside.hex"
    target.write_text("outside", encoding="utf-8")
    configured = tmp_path / "configured-macaroon-alias.hex"
    configured.symlink_to(target)
    monkeypatch.setenv("MACAROON_STORE_PATH", str(configured))

    resolved = Settings().macaroon_store_path

    assert resolved == configured.absolute()
    assert resolved.is_symlink()


def test_sensitive_config_path_rejects_symlinked_parent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target_parent = tmp_path / "target"
    target_parent.mkdir()
    alias_parent = tmp_path / "alias"
    alias_parent.symlink_to(target_parent, target_is_directory=True)
    monkeypatch.setenv("DATA_STORE_PATH", str(alias_parent / "lnswitchboard.db"))

    with pytest.raises(ValidationError, match="parent must not be a symbolic link"):
        Settings()


def test_invalid_trusted_proxy_setting_is_rejected(monkeypatch) -> None:
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "not-a-network")

    with pytest.raises(ValueError):
        Settings()


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://admin.example/api/cloudflare/oauth/callback",
        "http://192.168.1.10:22121/api/cloudflare/oauth/callback",
        "http://localhost:22121/api/cloudflare/oauth/callback",
        "http://[::ffff:127.0.0.1]:22121/api/cloudflare/oauth/callback",
        "http://127.0.0.1:22121/api/cloudflare/oauth/callback?forward=1",
        "http://user@127.0.0.1:22121/api/cloudflare/oauth/callback",
        "http://127.0.0.1:22121/not-the-oauth-callback",
        " http://127.0.0.1:22121/api/cloudflare/oauth/callback",
        "http://127.0.0.1:22121/api/cloudflare/oauth/callback\n",
        "\thttp://127.0.0.1:22121/api/cloudflare/oauth/callback",
        "\x01http://127.0.0.1:22121/api/cloudflare/oauth/callback",
        "\x7fhttp://127.0.0.1:22121/api/cloudflare/oauth/callback",
        "http://127.0.0.1:0/api/cloudflare/oauth/callback",
        "http://[0:0:0:0:0:0:0:1]:22121/api/cloudflare/oauth/callback",
    ],
)
def test_cloudflare_query_callback_is_restricted_to_the_exact_loopback_endpoint(
    monkeypatch: pytest.MonkeyPatch, redirect_uri: str
) -> None:
    monkeypatch.setenv("CLOUDFLARE_OAUTH_REDIRECT_LOOPBACK", redirect_uri)

    with pytest.raises(ValueError, match="loopback"):
        Settings()


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://127.0.0.1:22121/api/cloudflare/oauth/callback",
        "http://[::1]:22121/api/cloudflare/oauth/callback",
    ],
)
def test_cloudflare_query_callback_accepts_ipv4_and_ipv6_loopback(
    monkeypatch: pytest.MonkeyPatch, redirect_uri: str
) -> None:
    monkeypatch.setenv("CLOUDFLARE_OAUTH_REDIRECT_LOOPBACK", redirect_uri)

    assert Settings().cloudflare_oauth_redirect_loopback == redirect_uri


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://oauth.example/callback/",
        "https://user@oauth.example/callback/",
        "https://oauth.example/callback/?next=admin",
        "https://oauth.example/callback/#fragment",
        "https:///callback/",
        " https://oauth.example/callback/",
        "https://oauth.example/callback/\t",
        "\x01https://oauth.example/callback/",
        "\x7fhttps://oauth.example/callback/",
        "https://oauth.example\\@evil.example/callback/",
        "https://foo..example/callback/",
        "https://-foo.example/callback/",
        "https://foo-.example/callback/",
        "https://%65xample.com/callback/",
        "https://oauth.example:0/callback/",
        "https://[fe80::1%25lo]/callback/",
        "https://oauth.example/callbäck/",
        "https://127.000.000.001/callback/",
        "https://127.1/callback/",
        "https://2130706433/callback/",
        "https://0x7f000001/callback/",
        "https://09.0.0.1/callback/",
        "https://oauth.1/callback/",
        "https://oauth.0x1/callback/",
        "https://oauth.example:/callback/",
        "https://oauth.example/callback/?",
        "https://oauth.example/callback/#",
        "https://127.0.0.1/callback/",
        "https://oauth.example:00443/callback/",
        "https://oauth.example:443/callback/",
        "https://OAUTH.EXAMPLE/callback/",
        "https://XN--BCHER-KVA.example/callback/",
        "https://xn--a.example/callback/",
        "https://0x/callback/",
        "https://0X/callback/",
        "https://oauth.0x/callback/",
        "https://oauth.0X/callback/",
        "https://[2001:DB8::1]/callback/",
        "https://oauth.example/a/../callback/",
        "https://oauth.example/a/%2e%2e/callback/",
        "https://oauth.example/a/./callback/",
        "https://oauth.example",
        "https://oauth.example:00444/callback/",
        "https://oauth.example:00001/callback/",
        "https://192.0.2.1:443/callback/",
        "https://[2001:db8::1]:443/callback/",
        "https://oauth.example/a/%2e/callback/",
        "https://oauth.example/a/%2E./callback/",
        "https://oauth.example/a/%2E%2E/callback/",
        "https://xn--0.example/callback/",
        "https://xn--abc.example/callback/",
        "https://xn--bbd.example/callback/",
        "https://xn--ls8h.example/callback/",
        "https://oauth.example/%/",
        "https://oauth.example/%zz/",
    ],
)
def test_cloudflare_remote_callback_requires_a_clean_https_page(
    monkeypatch: pytest.MonkeyPatch, redirect_uri: str
) -> None:
    monkeypatch.setenv("CLOUDFLARE_OAUTH_REDIRECT_PAGE", redirect_uri)

    with pytest.raises(ValueError, match="HTTPS"):
        Settings()


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://oauth.lnswitchboard.app/callback/",
        "https://oauth.example/",
        "https://oauth.example:444/callback/",
        "https://xn--bcher-kva.example/callback/",
        "https://oauth.0xg/callback/",
        "https://192.0.2.1/callback/",
        "https://[2001:db8::1]/callback/",
    ],
)
def test_cloudflare_remote_callback_accepts_a_clean_https_page(
    monkeypatch: pytest.MonkeyPatch, redirect_uri: str
) -> None:
    monkeypatch.setenv("CLOUDFLARE_OAUTH_REDIRECT_PAGE", redirect_uri)

    assert Settings().cloudflare_oauth_redirect_page == redirect_uri


def test_default_cloudflare_oauth_scope_matches_registered_capabilities(
    monkeypatch,
) -> None:
    monkeypatch.delenv("CLOUDFLARE_OAUTH_SCOPE", raising=False)

    scopes = set(Settings().cloudflare_oauth_scope.split())

    assert scopes == {
        "offline_access",
        "account-settings.read",
        "zone.read",
        "dns.read",
        "dns.write",
        "workers-scripts.read",
        "workers-scripts.write",
        "workers-scripts.bind",
        "connectivity-directory.bind",
        "workers-routes.read",
        "workers-routes.write",
        "teams-connector-warp.read",
        "teams-connector-warp.write",
        "teams.read",
        "teams.write",
        "access.read",
        "access.write",
    }


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
