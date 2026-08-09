"""Secretless TCP gateway for the public lnSwitchboard surface."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response

_MAX_PUBLIC_REQUEST_BYTES = 1024 * 1024
_MAX_PUBLIC_RESPONSE_BYTES = 1024 * 1024
_MAX_PUBLIC_HEADER_COUNT = 100
_MAX_PUBLIC_HEADER_BYTES = 16 * 1024
_HOP_BY_HOP = {
    b"connection",
    b"keep-alive",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"upgrade",
}
_INTERNAL_CLIENT_HEADER = b"x-lns-internal-client-ip"


@asynccontextmanager
async def lifespan(app: FastAPI):
    socket_path = Path(
        os.environ.get(
            "PUBLIC_BACKEND_SOCKET_PATH",
            "/run/lnswitchboard-public/public.sock",
        )
    )
    transport = httpx.AsyncHTTPTransport(uds=str(socket_path))
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://lnswitchboard.internal",
        follow_redirects=False,
        timeout=30.0,
    ) as client:
        for _ in range(500):
            try:
                await client.get("/", headers={"host": "localhost"})
                break
            except (httpx.ConnectError, httpx.ConnectTimeout):
                await asyncio.sleep(0.01)
        else:
            raise RuntimeError("Public backend socket did not become reachable")
        app.state.backend_client = client
        yield


app = FastAPI(
    title="lnSwitchboard Public Gateway",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


@app.api_route(
    "/{path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    include_in_schema=False,
)
async def proxy_public_request(request: Request, path: str) -> Response:
    raw_headers = request.scope["headers"]
    if len(raw_headers) > _MAX_PUBLIC_HEADER_COUNT or sum(
        len(name) + len(value) for name, value in raw_headers
    ) > _MAX_PUBLIC_HEADER_BYTES:
        return PlainTextResponse("Request headers too large", status_code=431)
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_PUBLIC_REQUEST_BYTES:
            return PlainTextResponse("Request body too large", status_code=413)
        body.extend(chunk)

    headers = [
        (name, value)
        for name, value in request.scope["headers"]
        if name.lower() not in _HOP_BY_HOP
        and name.lower() != b"content-length"
        and name.lower() != _INTERNAL_CLIENT_HEADER
    ]
    if request.client is not None:
        headers.append((_INTERNAL_CLIENT_HEADER, request.client.host.encode("ascii")))
    target = request.url.path
    if request.url.query:
        target = f"{target}?{request.url.query}"
    try:
        async with request.app.state.backend_client.stream(
            request.method, target, content=bytes(body), headers=headers
        ) as backend:
            raw_response_headers = backend.headers.raw
            if len(raw_response_headers) > _MAX_PUBLIC_HEADER_COUNT or sum(
                len(name) + len(value) for name, value in raw_response_headers
            ) > _MAX_PUBLIC_HEADER_BYTES:
                return PlainTextResponse(
                    "Public backend response headers too large", status_code=502
                )
            response_body = bytearray()
            async for chunk in backend.aiter_bytes(chunk_size=64 * 1024):
                if len(response_body) + len(chunk) > _MAX_PUBLIC_RESPONSE_BYTES:
                    return PlainTextResponse(
                        "Public backend response too large", status_code=502
                    )
                response_body.extend(chunk)
            response_headers = [
                (name, value)
                for name, value in backend.headers.raw
                if name.lower() not in _HOP_BY_HOP
                and name.lower() != b"content-length"
            ]
            response_status = backend.status_code
    except httpx.HTTPError:
        return PlainTextResponse("Public backend unavailable", status_code=503)

    response = Response(
        content=bytes(response_body),
        status_code=response_status,
    )
    response.raw_headers = response_headers
    return response
