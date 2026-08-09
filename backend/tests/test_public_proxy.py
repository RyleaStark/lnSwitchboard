from __future__ import annotations

import asyncio
import gzip
from contextlib import asynccontextmanager

import httpx
from starlette.requests import Request

from backend.app.public_proxy import app, proxy_public_request


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


def test_public_gateway_translates_head_to_backend_get_without_returning_a_body() -> None:
    async def exercise():
        backend = BackendClient()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://public.example"
        ) as client:
            response = await client.head("/.well-known/lnurlp/alice")
        return backend, response

    backend, response = asyncio.run(exercise())

    assert response.status_code == 201
    assert response.content == b""
    assert response.headers["content-length"] == str(len(b"proxied"))
    assert backend.request_details is not None
    assert backend.request_details[0] == "GET"


def test_public_gateway_counts_generated_head_framing_header() -> None:
    async def exercise():
        class ManyHeaderBackend(BackendClient):
            @asynccontextmanager
            async def stream(self, method, target, *, content, headers):
                self.request_details = (method, target, content, headers)
                yield httpx.Response(
                    200,
                    headers=[(f"x-field-{index}", "value") for index in range(100)],
                    stream=httpx.ByteStream(b"ok"),
                )

        backend = ManyHeaderBackend()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://public.example"
        ) as client:
            return await client.head("/.well-known/nostr.json")

    response = asyncio.run(exercise())
    assert response.status_code == 502
    assert response.text == ""
    assert response.headers["content-length"] == str(
        len(b"Public backend response headers too large")
    )


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


def test_public_gateway_counts_internal_identity_header_before_forwarding() -> None:
    async def exercise():
        backend = BackendClient()
        app.state.backend_client = backend
        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"host", b"public.example")]
            + [(f"x-field-{index}".encode(), b"value") for index in range(99)],
            "client": ("203.0.113.7", 1234),
            "server": ("127.0.0.1", 21212),
            "app": app,
        }
        response = await proxy_public_request(Request(scope), "")
        return backend, response

    backend, response = asyncio.run(exercise())
    assert response.status_code == 431
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


def test_public_gateway_decodes_backend_content_before_removing_encoding_header() -> None:
    async def exercise():
        class CompressedBackend(BackendClient):
            @asynccontextmanager
            async def stream(self, method, target, *, content, headers):
                self.request_details = (method, target, content, headers)
                yield httpx.Response(
                    200,
                    content=gzip.compress(b"decoded"),
                    headers={"content-encoding": "gzip"},
                )

        backend = CompressedBackend()
        app.state.backend_client = backend
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://public.example"
        ) as client:
            return await client.get("/.well-known/nostr.json")

    response = asyncio.run(exercise())
    assert response.content == b"decoded"
    assert "content-encoding" not in response.headers


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
