"""Launch the configured lnSwitchboard HTTP listener set."""

from __future__ import annotations

import socket
import os

import uvicorn

from .config import get_settings
from .main import admin_app, app
from .public_proxy import app as public_proxy_app


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
            http="h11",
            h11_max_incomplete_event_size=16 * 1024,
        )
        uvicorn.Server(config).run(sockets=listeners)
    finally:
        for listener in listeners:
            listener.close()


if __name__ == "__main__":
    main()
