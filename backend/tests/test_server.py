from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.app import server


def test_production_server_disables_query_bearing_access_logs(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class Listener:
        def close(self) -> None:
            pass

    class Config:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

    class UvicornServer:
        def __init__(self, _config) -> None:
            pass

        def run(self, *, sockets) -> None:
            assert len(sockets) == 2

    monkeypatch.setenv("LISTENER_MODE", "both")
    monkeypatch.setattr(
        server,
        "get_settings",
        lambda: SimpleNamespace(
            listener_mode="both",
            service_host="127.0.0.1",
            service_port=22121,
            public_service_host="127.0.0.1",
            public_service_port=21212,
        ),
    )
    monkeypatch.setattr(server, "_listener", lambda _host, _port: Listener())
    monkeypatch.setattr(server.uvicorn, "Config", Config)
    monkeypatch.setattr(server.uvicorn, "Server", UvicornServer)

    server.main()

    assert captured["access_log"] is False
    assert captured["http"] == "h11"
    assert captured["h11_max_incomplete_event_size"] == 16 * 1024


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("admin", [("127.0.0.1", 22121)]),
        ("public", [("127.0.0.1", 21212)]),
    ],
)
def test_server_can_bind_one_listener_mode(monkeypatch, mode, expected) -> None:
    listeners: list[tuple[str, int]] = []

    class Listener:
        def close(self) -> None:
            pass

    class UvicornServer:
        def __init__(self, _config) -> None:
            pass

        def run(self, *, sockets) -> None:
            assert len(sockets) == 1

    monkeypatch.setenv("LISTENER_MODE", mode)
    monkeypatch.setattr(
        server,
        "get_settings",
        lambda: SimpleNamespace(
            listener_mode=mode,
            service_host="127.0.0.1",
            service_port=22121,
            public_service_host="127.0.0.1",
            public_service_port=21212,
        ),
    )

    def listener(host, port):
        listeners.append((host, port))
        return Listener()

    monkeypatch.setattr(server, "_listener", listener)
    monkeypatch.setattr(server.uvicorn, "Server", UvicornServer)

    server.main()

    assert listeners == expected