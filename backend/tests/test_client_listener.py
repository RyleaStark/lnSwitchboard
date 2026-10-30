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
                             "/.well-known/lnurlp/pay", "/api/client/v1/../../client-credentials"):
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
