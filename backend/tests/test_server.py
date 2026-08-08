from __future__ import annotations

from types import SimpleNamespace

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

    monkeypatch.setattr(
        server,
        "get_settings",
        lambda: SimpleNamespace(
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