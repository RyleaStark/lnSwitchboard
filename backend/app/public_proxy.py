"""Secretless TCP gateway for the public lnSwitchboard surface."""

from __future__ import annotations

import asyncio
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response

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
_HEADER_NAME_PATTERN = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def sanitize_hop_by_hop_headers(
    headers: list[tuple[bytes, bytes]], *, excluded: set[bytes] | None = None
) -> list[tuple[bytes, bytes]]:
    """Validate names and remove fixed and Connection-nominated hop fields."""
    nominated: set[bytes] = set()
    for name, value in headers:
        if _HEADER_NAME_PATTERN.fullmatch(name) is None:
            raise ValueError("Invalid HTTP field name")
        if name.lower() == b"connection":
            for raw_token in value.split(b","):
                token = raw_token.strip()
                if not token or _HEADER_NAME_PATTERN.fullmatch(token) is None:
                    raise ValueError("Invalid Connection field-name token")
                nominated.add(token.lower())
    removed = _HOP_BY_HOP | nominated | (excluded or set())
    return [(name, value) for name, value in headers if name.lower() not in removed]


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
    if request.method not in {"GET", "HEAD"}:
        return PlainTextResponse("Method not allowed", status_code=405)
    if any(
        name.lower() == b"transfer-encoding"
        or (name.lower() == b"content-length" and value.strip() not in {b"", b"0"})
        for name, value in raw_headers
    ):
        return PlainTextResponse("Request body not permitted", status_code=413)

    try:
        headers = sanitize_hop_by_hop_headers(
            raw_headers,
            excluded={b"content-length", _INTERNAL_CLIENT_HEADER},
        )
    except ValueError:
        return PlainTextResponse("Malformed Connection header", status_code=400)
    if request.client is not None:
        headers.append((_INTERNAL_CLIENT_HEADER, request.client.host.encode("ascii")))
    target = request.url.path
    if request.url.query:
        target = f"{target}?{request.url.query}"
    try:
        backend_method = "GET" if request.method == "HEAD" else request.method
        async with request.app.state.backend_client.stream(
            backend_method, target, content=b"", headers=headers
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
            try:
                response_headers = sanitize_hop_by_hop_headers(
                    raw_response_headers,
                    excluded={b"content-length", b"content-encoding"},
                )
            except ValueError:
                return PlainTextResponse(
                    "Malformed public backend response headers", status_code=502
                )
            response_status = backend.status_code
    except httpx.HTTPError:
        return PlainTextResponse("Public backend unavailable", status_code=503)

    if request.method == "HEAD":
        response_headers.append((b"content-length", str(len(response_body)).encode("ascii")))
    if len(response_headers) > _MAX_PUBLIC_HEADER_COUNT or sum(
        len(name) + len(value) for name, value in response_headers
    ) > _MAX_PUBLIC_HEADER_BYTES:
        return PlainTextResponse("Public backend response headers too large", status_code=502)
    response = Response(
        content=b"" if request.method == "HEAD" else bytes(response_body),
        status_code=response_status,
    )
    response.raw_headers = response_headers
    return response
