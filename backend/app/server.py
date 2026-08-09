"""Launch the configured lnSwitchboard HTTP listener set."""

from __future__ import annotations

import socket

import uvicorn

from .config import get_settings
from .main import app


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
    settings = get_settings()
    if settings.listener_mode == "both" and settings.service_port == settings.public_service_port:
        raise ValueError("SERVICE_PORT and PUBLIC_SERVICE_PORT must be different")
    endpoints = {
        "admin": [(settings.service_host, settings.service_port)],
        "public": [(settings.public_service_host, settings.public_service_port)],
        "both": [
            (settings.service_host, settings.service_port),
            (settings.public_service_host, settings.public_service_port),
        ],
    }[settings.listener_mode]
    listeners = [_listener(host, port) for host, port in endpoints]
    try:
        config = uvicorn.Config(
            app=app,
            host=endpoints[0][0],
            port=endpoints[0][1],
            proxy_headers=False,
            access_log=False,
        )
        uvicorn.Server(config).run(sockets=listeners)
    finally:
        for listener in listeners:
            listener.close()


if __name__ == "__main__":
    main()
