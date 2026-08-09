from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import httpx

from backend.app.public_proxy import app


class BackendClient:
    def __init__(self) -> None:
        self.request_details = None

    @asynccontextmanager
    async def stream(self, method, target, *, content, headers):
        self.request_details = (method, target, content, headers)
        yield httpx.Response(
            201,
            content=b"proxied",
            headers={"content-type": "text/plain", "connection": "close"},
        )


def test_public_gateway_forwards_only_gets_to_the_private_backend() -> None:
    async def exercise():
        backend = BackendClient()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app, client=("203.0.113.7", 1234))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://public.example",
        ) as client:
            response = await client.get(
                "/.well-known/lnurlp/alice?amount=1000",
                headers={"x-lns-internal-client-ip": "198.51.100.9"},
            )
        return backend, response

    backend, response = asyncio.run(exercise())

    assert response.status_code == 201
    assert response.content == b"proxied"
    method, target, body, headers = backend.request_details
    assert method == "GET"
    assert target == "/.well-known/lnurlp/alice?amount=1000"
    assert body == b""
    internal = [value for name, value in headers if name == b"x-lns-internal-client-ip"]
    assert internal == [b"203.0.113.7"]
    assert all(name != b"connection" for name, _value in response.headers.raw)


def test_public_gateway_rejects_all_request_bodies_without_backend_access() -> None:
    async def exercise():
        backend = BackendClient()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://public.example"
        ) as client:
            response = await client.post("/", content=b"x")
        return backend, response

    backend, response = asyncio.run(exercise())

    assert response.status_code == 405
    assert backend.request_details is None


def test_public_gateway_removes_connection_nominated_headers_both_directions() -> None:
    async def exercise():
        class HopBackend(BackendClient):
            @asynccontextmanager
            async def stream(self, method, target, *, content, headers):
                self.request_details = (method, target, content, headers)
                yield httpx.Response(
                    200,
                    content=b"ok",
                    headers=[("connection", "x-response-hop"), ("x-response-hop", "secret")],
                )

        backend = HopBackend()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://public.example"
        ) as client:
            response = await client.get(
                "/.well-known/nostr.json",
                headers={"connection": "x-request-hop", "x-request-hop": "attacker"},
            )
        return backend, response

    backend, response = asyncio.run(exercise())
    forwarded = {name.lower() for name, _value in backend.request_details[3]}
    assert b"x-request-hop" not in forwarded
    assert "x-response-hop" not in response.headers


def test_public_gateway_rejects_excessive_request_headers() -> None:
    async def exercise():
        backend = BackendClient()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app)
        headers = [(f"x-header-{index}", "value") for index in range(101)]
        async with httpx.AsyncClient(
            transport=transport, base_url="http://public.example"
        ) as client:
            response = await client.get("/", headers=headers)
        return backend, response

    backend, response = asyncio.run(exercise())

    assert response.status_code == 431
    assert backend.request_details is None


def test_public_gateway_rejects_excessive_request_header_bytes() -> None:
    async def exercise():
        backend = BackendClient()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://public.example"
        ) as client:
            response = await client.get("/", headers={"x-large": "x" * (16 * 1024)})
        return backend, response

    backend, response = asyncio.run(exercise())

    assert response.status_code == 431
    assert backend.request_details is None


def test_public_gateway_rejects_oversized_backend_responses() -> None:
    async def exercise():
        class LargeBackend(BackendClient):
            @asynccontextmanager
            async def stream(self, method, target, *, content, headers):
                self.request_details = (method, target, content, headers)
                yield httpx.Response(200, content=b"x" * (1024 * 1024 + 1))

        backend = LargeBackend()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://public.example"
        ) as client:
            return await client.get("/.well-known/lnurlp/alice")

    response = asyncio.run(exercise())

    assert response.status_code == 502
    assert response.content == b"Public backend response too large"


def test_public_gateway_rejects_excessive_backend_response_headers() -> None:
    async def exercise():
        class LargeHeadersBackend(BackendClient):
            @asynccontextmanager
            async def stream(self, method, target, *, content, headers):
                self.request_details = (method, target, content, headers)
                response_headers = [(f"x-header-{index}", "value") for index in range(101)]
                yield httpx.Response(200, content=b"ok", headers=response_headers)

        backend = LargeHeadersBackend()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://public.example"
        ) as client:
            return await client.get("/.well-known/lnurlp/alice")

    response = asyncio.run(exercise())

    assert response.status_code == 502
    assert response.content == b"Public backend response headers too large"
