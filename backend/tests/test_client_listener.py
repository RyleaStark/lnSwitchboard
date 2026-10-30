"""Client integration transport must never expose operator routes."""
import asyncio

import httpx


def test_client_only_listener_binds_tcp_and_excludes_operator_routes():
    from backend.app.main import _start_client_backend

    async def exercise():
        server, task = await _start_client_backend(host="127.0.0.1", port=0)
        try:
            port = server.servers[0].sockets[0].getsockname()[1]
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", trust_env=False) as client:
                assert (await client.get("/api/client/v1/addresses/missing")).status_code == 401
                for path in ("/", "/api/client-credentials", "/api/health", "/api/settings", "/openapi.json",
                             "/.well-known/lnurlp/pay", "/api/client/v1/../../client-credentials",
                             "/api/client/v1/%2e%2e/%2e%2e/%2e%2e/index.html",
                             "/api/client/v1/%2e%2e/%2e%2e/%2e%2e/"):
                    assert (await client.get(path)).status_code == 404
                    assert (await client.post(path, json={})).status_code == 404
        finally:
            server.should_exit = True
            await task

    asyncio.run(exercise())


def test_client_listener_preserves_lan_guard_and_rejects_forged_forwarding():
    from backend.app.main import client_only_app

    async def exercise():
        for peer, expected in (("8.8.8.8", 403), ("192.168.1.5", 401)):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=client_only_app, client=(peer, 1234)),
                                         base_url="http://testserver") as client:
                response = await client.get("/api/client/v1/addresses/missing",
                                            headers={"X-Forwarded-For": "127.0.0.1"})
                assert response.status_code == expected

    asyncio.run(exercise())


def test_client_listener_shutdown_bounds_incomplete_request():
    from backend.app.main import _start_client_backend

    async def exercise():
        server, task = await _start_client_backend(host="127.0.0.1", port=0)
        port = server.servers[0].sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"POST /api/client/v1/addresses HTTP/1.1\r\nHost: testserver\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\n{")
        await writer.drain()
        await asyncio.sleep(0.05)
        try:
            server.should_exit = True
            await asyncio.wait_for(task, timeout=4)
        finally:
            writer.close()
            await writer.wait_closed()

    asyncio.run(exercise())


def test_client_start_failure_rolls_back_public_backend_and_workers(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    import pytest
    from backend.app import main
    from backend.app.config import Settings

    settings = Settings(listener_mode="admin", client_api_enabled=True,
                        cloudflared_connector_enabled=False, tailscale_connector_enabled=False,
                        zrok_connector_enabled=False)
    lnd = SimpleNamespace(check_connection=AsyncMock(return_value={}), close=AsyncMock())
    dispatcher = SimpleNamespace(resume_pending_retries=AsyncMock())
    workers = []

    class Worker:
        def __init__(self, *args, **kwargs):
            self.start = AsyncMock()
            self.stop = AsyncMock()
            workers.append(self)

    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "configure_logging", lambda *args: None)
    monkeypatch.setattr(main, "get_ln_client_dep", AsyncMock(return_value=lnd))
    monkeypatch.setattr(main, "get_log_storage_dep", AsyncMock(return_value=object()))
    monkeypatch.setattr(main, "get_webhook_dispatcher_dep", AsyncMock(return_value=dispatcher))
    monkeypatch.setattr(main, "InvoiceSubscriptionWorker", Worker)
    monkeypatch.setattr(main, "InvoiceFullRefreshWorker", Worker)
    monkeypatch.setattr(main, "_start_client_backend", AsyncMock(side_effect=OSError("synthetic bind failure")))
    public = SimpleNamespace(should_exit=False)
    tasks = []

    async def public_start(*args):
        async def run():
            while not public.should_exit:
                await asyncio.sleep(0.01)
        task = asyncio.create_task(run())
        tasks.append(task)
        return public, task

    monkeypatch.setattr(main, "_start_public_backend", public_start)

    async def exercise():
        with pytest.raises(OSError):
            async with main.lifespan(main.admin_app):
                pytest.fail("startup must fail")
        assert public.should_exit
        assert tasks[0].done()
        assert all(worker.stop.await_count == 1 for worker in workers)
        assert lnd.close.await_count == 1

    asyncio.run(exercise())


def test_client_start_cancellation_cleans_up_unreturned_server(monkeypatch):
    from backend.app import main
    import pytest

    async def exercise():
        bound = asyncio.Event()
        closed = asyncio.Event()

        class DelayedServer:
            started = False
            should_exit = False

            def __init__(self, config):
                pass

            async def serve(self):
                # Hold the helper in readiness while a real socket is already bound.
                listener = await asyncio.start_server(lambda r, w: w.close(), '127.0.0.1', 0)
                bound.set()
                try:
                    while not self.should_exit:
                        await asyncio.sleep(0.01)
                finally:
                    listener.close()
                    await listener.wait_closed()
                    closed.set()

        monkeypatch.setattr(main.uvicorn, 'Server', DelayedServer)
        startup = asyncio.create_task(main._start_client_backend(host='127.0.0.1', port=0))
        await asyncio.wait_for(bound.wait(), 2)
        startup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await startup
        assert closed.is_set()

    asyncio.run(exercise())
