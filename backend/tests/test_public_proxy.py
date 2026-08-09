from __future__ import annotations

import asyncio

import httpx

from backend.app.public_proxy import app


class BackendClient:
    def __init__(self) -> None:
        self.request_details = None

    async def request(self, method, target, *, content, headers):
        self.request_details = (method, target, content, headers)
        return httpx.Response(
            201,
            content=b"proxied",
            headers={"content-type": "text/plain", "connection": "close"},
        )


def test_public_gateway_forwards_only_to_the_private_backend() -> None:
    async def exercise():
        backend = BackendClient()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app, client=("203.0.113.7", 1234))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://public.example",
        ) as client:
            response = await client.post(
                "/.well-known/lnurlp/alice?amount=1000",
                content=b"payload",
                headers={"x-lns-internal-client-ip": "198.51.100.9"},
            )
        return backend, response

    backend, response = asyncio.run(exercise())

    assert response.status_code == 201
    assert response.content == b"proxied"
    method, target, body, headers = backend.request_details
    assert method == "POST"
    assert target == "/.well-known/lnurlp/alice?amount=1000"
    assert body == b"payload"
    internal = [value for name, value in headers if name == b"x-lns-internal-client-ip"]
    assert internal == [b"203.0.113.7"]
    assert all(name != b"connection" for name, _value in response.headers.raw)


def test_public_gateway_rejects_oversized_bodies_without_backend_access() -> None:
    async def exercise():
        backend = BackendClient()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://public.example"
        ) as client:
            response = await client.post("/", content=b"x" * (1024 * 1024 + 1))
        return backend, response

    backend, response = asyncio.run(exercise())

    assert response.status_code == 413
    assert backend.request_details is None
