"""Forwarding outbound requests must pass the pinned public-endpoint policy."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from ..app.config import get_settings
from ..app.lnurl_forwarding import (
    ForwardingTargetError,
    fetch_forwarding_discovery,
    fetch_forwarding_invoice,
    fetch_forwarding_verify,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_forwarding_callback_to_cloud_metadata_is_rejected() -> None:
    with pytest.raises(ForwardingTargetError, match="not an allowed public endpoint"):
        await fetch_forwarding_invoice("http://169.254.169.254/latest/meta-data", [])


@pytest.mark.anyio
async def test_forwarding_callback_to_loopback_is_rejected() -> None:
    with pytest.raises(ForwardingTargetError, match="not an allowed public endpoint"):
        await fetch_forwarding_invoice("http://127.0.0.1:22121/api/health", [("amount", "1000")])


@pytest.mark.anyio
async def test_forwarding_callback_with_embedded_credentials_is_rejected() -> None:
    with pytest.raises(ForwardingTargetError, match="not an allowed public endpoint"):
        await fetch_forwarding_invoice("http://user:secret@203.0.113.10/callback", [])


@pytest.mark.anyio
async def test_forwarding_discovery_to_private_address_is_rejected() -> None:
    with pytest.raises(ForwardingTargetError, match="not an allowed public endpoint"):
        await fetch_forwarding_discovery("bones@10.0.0.5")


@pytest.mark.anyio
async def test_forwarding_verify_to_private_address_is_rejected() -> None:
    with pytest.raises(ForwardingTargetError, match="not an allowed public endpoint"):
        await fetch_forwarding_verify("https://192.168.1.10/verify/" + "ab" * 32)


class _JsonHandler(BaseHTTPRequestHandler):
    body = b"{}"
    status = 200
    last_path = ""

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        type(self).last_path = self.path
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *_args) -> None:
        return


@pytest.fixture
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _JsonHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def allow_private(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ALLOW_PRIVATE_FORWARDING", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.anyio
async def test_pinned_fetch_returns_json_and_encodes_params(local_server, allow_private) -> None:
    _JsonHandler.body = json.dumps({"pr": "lnbc1test", "verify": "https://x.example/v"}).encode()
    _JsonHandler.status = 200
    url = f"http://127.0.0.1:{local_server.server_port}/callback?existing=1"
    result = await fetch_forwarding_invoice(url, [("amount", "21000"), ("comment", "hi there")])
    assert result["pr"] == "lnbc1test"
    assert "existing=1" in _JsonHandler.last_path
    assert "amount=21000" in _JsonHandler.last_path
    assert "comment=hi+there" in _JsonHandler.last_path


@pytest.mark.anyio
async def test_pinned_fetch_rejects_oversized_responses(local_server, allow_private) -> None:
    _JsonHandler.body = b" " * 70000
    _JsonHandler.status = 200
    with pytest.raises(ForwardingTargetError, match="not an allowed public endpoint"):
        await fetch_forwarding_invoice(f"http://127.0.0.1:{local_server.server_port}/big", [])


@pytest.mark.anyio
async def test_pinned_fetch_does_not_follow_redirects(local_server, allow_private) -> None:
    _JsonHandler.body = b"{}"
    _JsonHandler.status = 302
    with pytest.raises(ForwardingTargetError, match="HTTP 302"):
        await fetch_forwarding_invoice(f"http://127.0.0.1:{local_server.server_port}/redirect", [])
    _JsonHandler.status = 200
