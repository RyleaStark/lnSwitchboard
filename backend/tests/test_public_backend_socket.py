from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
from fastapi import FastAPI

from backend.app import main


def test_internal_public_backend_uses_a_unix_socket(tmp_path, monkeypatch) -> None:
    test_app = FastAPI()

    @test_app.get("/probe")
    async def probe():
        return {"ok": True}

    monkeypatch.setattr(main, "public_app", test_app)
    socket_path = tmp_path / "public.sock"

    async def exercise() -> None:
        server, task = await main._start_public_backend(socket_path)
        try:
            transport = httpx.AsyncHTTPTransport(uds=str(socket_path))
            async with httpx.AsyncClient(
                transport=transport, base_url="http://internal"
            ) as client:
                response = await client.get("/probe")
            assert response.json() == {"ok": True}
        finally:
            server.should_exit = True
            await task

    asyncio.run(exercise())


def test_internal_public_backend_rejects_a_stale_regular_leaf(
    tmp_path: Path, monkeypatch
) -> None:
    socket_path = tmp_path / "public.sock"
    socket_path.write_bytes(b"attacker")
    monkeypatch.setattr(main, "public_app", FastAPI())

    async def exercise() -> None:
        try:
            await main._start_public_backend(socket_path)
        except OSError as exc:
            assert "unsafe" in str(exc)
        else:  # pragma: no cover - defensive
            raise AssertionError("unsafe socket leaf was accepted")

    asyncio.run(exercise())
    assert socket_path.read_bytes() == b"attacker"
