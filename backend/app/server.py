"""Launch the configured lnSwitchboard HTTP listener set."""

from __future__ import annotations

import asyncio
import os
import socket

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from .config import get_settings
from .main import admin_app, app
from .public_proxy import app as public_proxy_app

_MAX_REQUEST_TARGET_BYTES = 8 * 1024
_MAX_REQUEST_HEADER_LINE_BYTES = 8 * 1024
_MAX_REQUEST_HEADER_BYTES = 16 * 1024
_MAX_REQUEST_HEADER_COUNT = 100
_MAX_REQUEST_HEAD_BUFFER = _MAX_REQUEST_TARGET_BYTES + _MAX_REQUEST_HEADER_BYTES + 16
_MAX_RAW_CONNECTIONS = 64
_MAX_ACTIVE_REQUESTS = 8
_REQUEST_HEAD_TIMEOUT_SECONDS = 5.0


def _request_head_rejection(data: bytes) -> int | None:
    """Return a static status for an over-limit raw HTTP/1 request head."""

    request_line_end = data.find(b"\r\n")
    if request_line_end < 0:
        return 414 if len(data) > _MAX_REQUEST_TARGET_BYTES else None
    request_line = data[:request_line_end]
    parts = request_line.split(b" ")
    if len(request_line) > _MAX_REQUEST_TARGET_BYTES or (
        len(parts) >= 2 and len(parts[1]) > _MAX_REQUEST_TARGET_BYTES
    ):
        return 414

    header_block = data[request_line_end + 2 :]
    header_end = header_block.find(b"\r\n\r\n")
    bounded_headers = header_block if header_end < 0 else header_block[:header_end]
    if len(bounded_headers) > _MAX_REQUEST_HEADER_BYTES:
        return 431
    lines = bounded_headers.split(b"\r\n") if bounded_headers else []
    if len(lines) > _MAX_REQUEST_HEADER_COUNT or any(
        len(line) > _MAX_REQUEST_HEADER_LINE_BYTES for line in lines
    ):
        return 431
    return None


class BoundedH11Protocol(H11Protocol):
    """Reject oversized request heads before h11 or ASGI materializes them."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._raw_request_head = bytearray()
        self._raw_request_head_complete = False
        self._holds_request_slot = False
        self._request_head_timeout: asyncio.TimerHandle | None = None
        self._close_after_response = os.environ.get("LISTENER_MODE", "both").strip().lower() in {
            "both",
            "public",
        }

    def connection_made(self, transport: asyncio.Transport) -> None:
        super().connection_made(transport)
        if len(self.connections) > _MAX_RAW_CONNECTIONS:
            self._reject(503, b"Service Unavailable", b"Connection limit reached")
            return
        self._arm_request_head_timeout()

    def connection_lost(self, exc: Exception | None) -> None:
        self._cancel_request_head_timeout()
        self._holds_request_slot = False
        super().connection_lost(exc)

    def _arm_request_head_timeout(self) -> None:
        self._cancel_request_head_timeout()
        self._request_head_timeout = self.loop.call_later(
            _REQUEST_HEAD_TIMEOUT_SECONDS,
            self._request_head_timed_out,
        )

    def _cancel_request_head_timeout(self) -> None:
        if self._request_head_timeout is not None:
            self._request_head_timeout.cancel()
            self._request_head_timeout = None

    def _request_head_timed_out(self) -> None:
        self._request_head_timeout = None
        if not self._raw_request_head_complete and not self.transport.is_closing():
            self._reject(408, b"Request Timeout", b"Request headers timed out")

    def _reject(self, status: int, reason: bytes, body: bytes) -> None:
        self._cancel_request_head_timeout()
        if self.transport.is_closing():
            return
        self.transport.write(
            b"HTTP/1.1 "
            + str(status).encode("ascii")
            + b" "
            + reason
            + b"\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\n\r\n"
            + body
        )
        self.transport.close()

    def data_received(self, data: bytes) -> None:
        if not self._raw_request_head_complete:
            remaining = _MAX_REQUEST_HEAD_BUFFER + 1 - len(self._raw_request_head)
            if remaining > 0:
                self._raw_request_head.extend(data[:remaining])
            rejection = _request_head_rejection(bytes(self._raw_request_head))
            if rejection is not None:
                reason = b"URI Too Long" if rejection == 414 else b"Request Header Fields Too Large"
                body = b"Request target too large" if rejection == 414 else b"Request headers too large"
                self._reject(rejection, reason, body)
                return
            self._raw_request_head_complete = b"\r\n\r\n" in self._raw_request_head
            if self._raw_request_head_complete:
                self._cancel_request_head_timeout()
                active_requests = sum(
                    bool(getattr(connection, "_holds_request_slot", False))
                    for connection in self.connections
                )
                if active_requests >= _MAX_ACTIVE_REQUESTS:
                    self._reject(503, b"Service Unavailable", b"Request limit reached")
                    return
                self._holds_request_slot = True
        super().data_received(data)

    def on_response_complete(self) -> None:
        self._raw_request_head.clear()
        self._raw_request_head_complete = False
        self._holds_request_slot = False
        if self._close_after_response:
            # Prevent a pipelined second request from bypassing raw-head checks
            # after h11 has buffered it behind the first request.
            self.transport.close()
        super().on_response_complete()
        if not self._close_after_response and not self.transport.is_closing():
            self._arm_request_head_timeout()


def _listener(host: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.create_server(
        (host, port),
        family=family,
        reuse_port=False,
    )
    listener.set_inheritable(True)
    return listener


def main() -> None:
    requested_mode = os.environ.get("LISTENER_MODE", "both").strip().lower()
    if requested_mode == "public":
        endpoints = [
            (
                os.environ.get("PUBLIC_SERVICE_HOST", "127.0.0.1"),
                int(os.environ.get("PUBLIC_SERVICE_PORT", "21212")),
            )
        ]
        target_app = public_proxy_app
    else:
        settings = get_settings()
        if settings.listener_mode == "both" and settings.service_port == settings.public_service_port:
            raise ValueError("SERVICE_PORT and PUBLIC_SERVICE_PORT must be different")
        endpoints = {
            "admin": [(settings.service_host, settings.service_port)],
            "both": [
                (settings.service_host, settings.service_port),
                (settings.public_service_host, settings.public_service_port),
            ],
        }[settings.listener_mode]
        target_app = {
            "admin": admin_app,
            "both": app,
        }[settings.listener_mode]
    listeners = [_listener(host, port) for host, port in endpoints]
    try:
        config = uvicorn.Config(
            app=target_app,
            host=endpoints[0][0],
            port=endpoints[0][1],
            proxy_headers=False,
            access_log=False,
            http=BoundedH11Protocol,
            h11_max_incomplete_event_size=16 * 1024,
        )
        uvicorn.Server(config).run(sockets=listeners)
    finally:
        for listener in listeners:
            listener.close()


if __name__ == "__main__":
    main()
