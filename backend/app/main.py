"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import grpc
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings, parse_trusted_hosts, parse_trusted_proxy_cidrs
from .deps import get_ln_client_dep, get_log_storage_dep, get_webhook_dispatcher_dep
from .logging_utils import configure_logging
from .request_utils import get_public_host
from .routers import ln_addresses as ln_addresses_router
from .routers import lnurl as lnurl_router
from .routers import nip05 as nip05_router
from .routers import ui as ui_router
from .routers import webhooks as webhooks_router
from .macaroon_store import MacaroonNotConfiguredError
from .invoice_worker import InvoiceSubscriptionWorker, InvoiceFullRefreshWorker
from .version import get_version

LOGGER = logging.getLogger("lnswitchboard")
BASE_DIR = Path(__file__).resolve().parents[2]
STATIC_DIR = BASE_DIR / "frontend" / "static"
SPA_ROUTES = ("/logs/", "/liquidity/", "/settings/", "/identities/", "/addresses/", "/invoices/", "/webhooks/")
FORWARDED_HEADERS = frozenset(
    {
        b"cf-connecting-ip",
        b"forwarded",
        b"true-client-ip",
        b"x-forwarded-for",
        b"x-forwarded-host",
        b"x-forwarded-port",
        b"x-forwarded-proto",
        b"x-real-ip",
    }
)


def _host_is_trusted(host_header: str, trusted_hosts: tuple[str, ...]) -> bool:
    hostname = (urlsplit(f"//{host_header}").hostname or "").lower().rstrip(".")
    return any(
        pattern == "*"
        or hostname == pattern
        or (pattern.startswith("*.") and hostname.endswith(pattern[1:]) and hostname != pattern[2:])
        for pattern in trusted_hosts
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.data_store_path.parent)
    ln_client = await get_ln_client_dep()
    storage = await get_log_storage_dep()
    webhook_dispatcher = await get_webhook_dispatcher_dep()
    invoice_subscription_worker = InvoiceSubscriptionWorker(
        storage=storage,
        ln_client=ln_client,
        webhook_dispatcher=webhook_dispatcher,
    )
    invoice_full_refresh_worker = InvoiceFullRefreshWorker(
        storage=storage,
        ln_client=ln_client,
        webhook_dispatcher=webhook_dispatcher,
    )
    await webhook_dispatcher.resume_pending_retries()
    await invoice_subscription_worker.start()
    await invoice_full_refresh_worker.start()
    app.state.invoice_subscription_worker = invoice_subscription_worker
    app.state.invoice_full_refresh_worker = invoice_full_refresh_worker
    app.state.webhook_dispatcher = webhook_dispatcher
    try:
        connection_info = await ln_client.check_connection()
        if connection_info.get("info_permission", True):
            LOGGER.info("Connected to LND at %s", settings.lnd_host)
        else:
            LOGGER.info(
                "Connected to LND at %s (macaroon missing GetInfo permission)",
                settings.lnd_host,
            )
    except MacaroonNotConfiguredError:
        LOGGER.info("Macaroon not yet configured; LND connectivity check skipped")
    except grpc.aio.AioRpcError as exc:  # pragma: no cover - network runtime
        details = (exc.details() or "").lower()
        if exc.code() == grpc.StatusCode.PERMISSION_DENIED or "permission denied" in details:
            LOGGER.info(
                "Skipping LND connection check (macaroon lacks GetInfo permission): %s",
                exc.details() or exc,
            )
        else:
            LOGGER.warning("Unable to verify LND connection: %s", exc)
    except Exception as exc:  # pragma: no cover - network runtime
        LOGGER.warning("Unable to verify LND connection: %s", exc)
    yield
    await invoice_full_refresh_worker.stop()
    await invoice_subscription_worker.stop()
    await ln_client.close()


app = FastAPI(
    title="lnSwitchboard",
    version=get_version(),
    lifespan=lifespan,
)


@app.middleware("http")
async def discard_untrusted_proxy_headers(request: Request, call_next):
    """Honor forwarding headers only when the immediate peer is trusted."""

    settings = get_settings()
    trusted_networks = parse_trusted_proxy_cidrs(settings.trusted_proxy_cidrs)
    client_host = request.client.host if request.client else ""
    try:
        client_ip = ip_address(client_host)
    except ValueError:
        client_ip = None
    if client_ip is None or not any(client_ip in network for network in trusted_networks):
        request.scope["headers"] = [
            (name, value)
            for name, value in request.scope["headers"]
            if name.lower() not in FORWARDED_HEADERS
        ]
    trusted_hosts = parse_trusted_hosts(settings.trusted_hosts)
    if not _host_is_trusted(request.headers.get("host", ""), trusted_hosts) or not _host_is_trusted(
        get_public_host(request), trusted_hosts
    ):
        return PlainTextResponse("Invalid host header", status_code=400)
    return await call_next(request)

app.include_router(ui_router.router)
app.include_router(webhooks_router.router)
app.include_router(ln_addresses_router.api_router)
app.include_router(nip05_router.api_router)
app.include_router(nip05_router.public_router)
app.include_router(lnurl_router.router)

def _register_client_redirect(path: str) -> None:
    target = f"{path.strip('/')}/"
    target = f"/{target}" if not target.startswith("/") else target

    @app.get(path, include_in_schema=False)
    async def _redirect_to_trailing_slash() -> RedirectResponse:
        return RedirectResponse(url=target, status_code=307)


for _client_path in ("/logs", "/liquidity", "/settings", "/identities", "/addresses", "/invoices", "/webhooks"):
    _register_client_redirect(_client_path)

if STATIC_DIR.exists():
    @app.get("/", include_in_schema=False)
    async def _spa_root() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    for _spa_path in SPA_ROUTES:
        @app.get(_spa_path, include_in_schema=False)
        async def _spa_route() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
