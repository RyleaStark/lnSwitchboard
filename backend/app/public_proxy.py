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
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_PUBLIC_REQUEST_BYTES:
            return PlainTextResponse("Request body too large", status_code=413)

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
        backend = await request.app.state.backend_client.request(
            request.method,
            target,
            content=bytes(body),
            headers=headers,
        )
    except httpx.HTTPError:
        return PlainTextResponse("Public backend unavailable", status_code=503)

    response_headers = [
        (name, value)
        for name, value in backend.headers.raw
        if name.lower() not in _HOP_BY_HOP and name.lower() != b"content-length"
    ]
    response = Response(
        content=backend.content,
        status_code=backend.status_code,
    )
    response.raw_headers = response_headers
    return response
