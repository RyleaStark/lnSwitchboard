"""Launch both lnSwitchboard HTTP listeners in one Uvicorn process."""

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
    if settings.service_port == settings.public_service_port:
        raise ValueError("SERVICE_PORT and PUBLIC_SERVICE_PORT must be different")

    listeners = [
        _listener(settings.service_host, settings.service_port),
        _listener(settings.public_service_host, settings.public_service_port),
    ]
    try:
        config = uvicorn.Config(
            app=app,
            host=settings.service_host,
            port=settings.service_port,
            proxy_headers=False,
            access_log=False,
        )
        uvicorn.Server(config).run(sockets=listeners)
    finally:
        for listener in listeners:
            listener.close()


if __name__ == "__main__":
    main()
