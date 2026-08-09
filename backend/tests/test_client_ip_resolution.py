"""Client-IP resolution must walk proxy chains right-to-left across trusted hops."""

from __future__ import annotations

import pytest
from starlette.requests import Request

from ..app.config import get_settings
from ..app.request_utils import get_client_ip


def _request(peer: str | None, headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [
            (name.lower().encode(), value.encode()) for name, value in (headers or {}).items()
        ],
        "client": (peer, 4321) if peer else None,
        "server": ("testserver", 80),
    }
    return Request(scope)


@pytest.fixture
def trusted_cidrs(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8,172.16.0.0/12")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_leftmost_client_supplied_xff_entry_cannot_spoof_identity(trusted_cidrs) -> None:
    # Cloudflare preserves client-supplied XFF entries (left) and appends the
    # real client IP (right). The walk must stop at the first untrusted hop
    # from the right, ignoring the spoofed leftmost entry.
    request = _request(
        "10.0.0.2",
        {"x-forwarded-for": "6.6.6.6, 203.0.113.7"},
    )
    assert get_client_ip(request) == "203.0.113.7"


def test_walk_continues_through_multiple_trusted_hops(trusted_cidrs) -> None:
    request = _request(
        "10.0.0.2",
        {"x-forwarded-for": "198.51.100.9, 172.16.0.9, 10.0.0.9"},
    )
    assert get_client_ip(request) == "198.51.100.9"


def test_malformed_hop_stops_the_walk(trusted_cidrs) -> None:
    request = _request(
        "10.0.0.2",
        {"x-forwarded-for": "not-an-ip, 203.0.113.7"},
    )
    assert get_client_ip(request) == "203.0.113.7"


def test_peer_is_used_without_forwarding_headers(trusted_cidrs) -> None:
    assert get_client_ip(_request("10.0.0.2")) == "10.0.0.2"


def test_internal_gateway_peer_still_walks_the_trusted_proxy_chain(trusted_cidrs) -> None:
    request = _request(
        None,
        {"x-forwarded-for": "198.51.100.9, 10.0.0.9"},
    )
    request.state.internal_client_ip = "10.0.0.2"

    assert get_client_ip(request) == "198.51.100.9"


def test_internal_loopback_gateway_walks_tailscale_forwarding(trusted_cidrs) -> None:
    request = _request(None, {"x-forwarded-for": "198.51.100.9"})
    request.state.internal_client_ip = "127.0.0.1"

    assert get_client_ip(request) == "198.51.100.9"


def test_edge_headers_no_longer_override_the_chain(trusted_cidrs) -> None:
    request = _request(
        "10.0.0.2",
        {
            "forwarded": 'for="6.6.6.6"',
            "cf-connecting-ip": "6.6.6.6",
            "true-client-ip": "6.6.6.6",
            "x-real-ip": "6.6.6.6",
        },
    )
    assert get_client_ip(request) == "10.0.0.2"


def test_untrusted_peer_chain_is_not_walked() -> None:
    # The middleware strips these headers for untrusted peers in production;
    # even if they arrive, an untrusted peer must not extend the chain.
    get_settings.cache_clear()
    try:
        request = _request(
            "203.0.113.50",
            {"x-forwarded-for": "6.6.6.6"},
        )
        assert get_client_ip(request) == "203.0.113.50"
    finally:
        get_settings.cache_clear()
