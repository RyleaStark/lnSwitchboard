"""Outbound network destination validation."""

from __future__ import annotations

import asyncio
import http.client
import socket
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit, urlunsplit


class UnsafeOutboundTarget(ValueError):
    """Raised when an outbound URL can reach a non-public network."""


class OutboundHTTPStatusError(RuntimeError):
    """Raised when a pinned outbound HTTP request returns an error."""

    def __init__(self, status_code: int, response_body: str) -> None:
        super().__init__(f"outbound request returned HTTP {status_code}")
        self.status_code = status_code
        self.response_body = response_body


async def ensure_public_endpoint(
    url: str,
    *,
    allowed_schemes: tuple[str, ...],
    allow_private: bool = False,
) -> str:
    """Resolve a URL and reject credentials or non-global destination addresses."""

    parsed = urlsplit(url)
    if parsed.scheme not in allowed_schemes or not parsed.hostname:
        raise UnsafeOutboundTarget("unsupported outbound URL")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeOutboundTarget("outbound URLs cannot contain credentials")
    if allow_private:
        return parsed.hostname

    try:
        addresses = [ip_address(parsed.hostname)]
    except ValueError:
        port = parsed.port or (443 if parsed.scheme in {"https", "wss"} else 80)
        try:
            records = await asyncio.get_running_loop().getaddrinfo(
                parsed.hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise UnsafeOutboundTarget("outbound hostname could not be resolved") from exc
        addresses = list({ip_address(str(record[4][0]).split("%", 1)[0]) for record in records})

    if not addresses or any(not address.is_global for address in addresses):
        raise UnsafeOutboundTarget("outbound URL resolves to a non-public network")
    return str(addresses[0])


async def post_to_pinned_endpoint(
    url: str,
    *,
    connect_host: str,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
) -> None:
    """POST without redirects or a second DNS lookup while preserving TLS SNI."""

    parsed = urlsplit(url)
    hostname = parsed.hostname
    if hostname is None:
        raise UnsafeOutboundTarget("outbound URL is missing a hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))

    def send() -> None:
        connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_class(hostname, port, timeout=timeout)

        def connect_pinned(
            _address: tuple[str, int],
            connection_timeout: Any = None,
            source_address: tuple[str, int] | None = None,
        ) -> socket.socket:
            return socket.create_connection(
                (connect_host, port),
                connection_timeout,
                source_address,
            )

        setattr(connection, "_create_connection", connect_pinned)
        try:
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(16_384).decode("utf-8", errors="replace")
            if response.status >= 300:
                raise OutboundHTTPStatusError(response.status, response_body)
        finally:
            connection.close()

    await asyncio.to_thread(send)
