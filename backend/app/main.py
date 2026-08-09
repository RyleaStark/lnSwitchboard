"""FastAPI applications for the administrative and public listeners."""

from __future__ import annotations

import asyncio
import secrets
import logging
from contextlib import asynccontextmanager, suppress
from ipaddress import IPv6Address, ip_address, ip_network
from pathlib import Path
from urllib.parse import urlsplit

import grpc
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import get_settings, parse_trusted_hosts, parse_trusted_proxy_cidrs
from .deps import (
    get_cloudflare_oauth_manager_dep,
    get_cloudflare_service_dep,
    get_connection_secret_store_dep,
    get_connection_store_dep,
    get_ln_address_store_dep,
    get_ln_client_dep,
    get_log_storage_dep,
    get_nip05_store_dep,
    get_tailscale_service_dep,
    get_webhook_dispatcher_dep,
)
from .invoice_worker import InvoiceFullRefreshWorker, InvoiceSubscriptionWorker
from .connection_store import ConnectionStore
from .ln_address_store import LNAddressStore
from .logging_utils import configure_logging
from .macaroon_store import MacaroonNotConfiguredError
from .nip05_store import NostrIdentityStore
from .request_utils import get_public_domain, get_public_host
from .routers import connections as connections_router
from .routers import cloudflare_oauth as cloudflare_oauth_router
from .routers import ln_addresses as ln_addresses_router
from .routers import lnurl as lnurl_router
from .routers import nip05 as nip05_router
from .routers import ui as ui_router
from .routers import webhooks as webhooks_router
from .version import get_version

LOGGER = logging.getLogger("lnswitchboard")
BASE_DIR = Path(__file__).resolve().parents[2]
STATIC_DIR = BASE_DIR / "frontend" / "static"
SPA_ROUTES = (
    "/logs/",
    "/liquidity/",
    "/settings/",
    "/identities/",
    "/addresses/",
    "/invoices/",
    "/webhooks/",
    "/connections/cloudflare/",
    "/connections/tailscale/",
)
FORWARDED_HEADERS = frozenset(
    {
        b"cf-connecting-ip",
        b"forwarded",
        b"true-client-ip",
        b"x-forwarded-for",
        b"x-forwarded-host",
        b"x-forwarded-port",
        b"x-forwarded-proto",
        b"x-forwarded-user",
        b"x-real-ip",
    }
)
ADMIN_LAN_NETWORKS = tuple(
    ip_network(network)
    for network in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def _valid_host_grammar(hostname: str) -> bool:
    """Strict DNS-label or IP-literal grammar for an authority hostname.

    urlsplit().hostname is not a validator: authorities such as `.example.com`
    or `foo..example.com` parse cleanly and would otherwise satisfy wildcard
    suffix matching in _host_is_trusted.
    """
    if not hostname or not hostname.isascii():
        return False
    try:
        ip_address(hostname)
        return True
    except ValueError:
        pass
    return all(
        0 < len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in hostname.split(".")
    )


def _normalized_authority_hostname(host_header: str) -> str | None:
    if (
        not host_header
        or any(character.isspace() for character in host_header)
        or any(character in host_header for character in "@/?#\\,")
    ):
        return None
    try:
        parsed = urlsplit(f"//{host_header}")
        hostname = (parsed.hostname or "").lower()
        if hostname.endswith(".."):
            return None
        hostname = hostname.removesuffix(".")
        _ = parsed.port
    except ValueError:
        return None
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not _valid_host_grammar(hostname)
    ):
        return None
    return hostname


def _host_is_trusted(host_header: str, trusted_hosts: tuple[str, ...]) -> bool:
    hostname = _normalized_authority_hostname(host_header)
    if hostname is None:
        return False
    return any(
        pattern == "*"
        or hostname == pattern
        or (pattern.startswith("*.") and hostname.endswith(pattern[1:]) and hostname != pattern[2:])
        for pattern in trusted_hosts
    )


def _normalized_address(value: str):
    address = ip_address(value)
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _is_lan_address(value: str) -> bool:
    try:
        address = _normalized_address(value)
    except ValueError:
        return False
    return any(
        address in network
        for network in ADMIN_LAN_NETWORKS
        if address.version == network.version
    )


def _is_trusted_proxy(value: str, cidrs: str) -> bool:
    try:
        address = _normalized_address(value)
    except ValueError:
        return False
    return any(
        address in network
        for network in parse_trusted_proxy_cidrs(cidrs)
        if address.version == network.version
    )


def _parse_forwarded_ip(value: str):
    cleaned = value.strip().strip('"')
    if cleaned.startswith("[") and "]" in cleaned:
        cleaned = cleaned[1 : cleaned.index("]")]
    elif cleaned.count(":") == 1:
        host, maybe_port = cleaned.rsplit(":", 1)
        if maybe_port.isdigit():
            cleaned = host
    return _normalized_address(cleaned)


def _get_admin_proxy_client(request: Request, cidrs: str) -> str | None:
    """Resolve X-Forwarded-For from right to left across local trusted proxies."""

    raw_chain = request.headers.get("x-forwarded-for")
    peer = request.client.host if request.client else ""
    if not raw_chain or not _is_trusted_proxy(peer, cidrs) or not _is_lan_address(peer):
        return None
    try:
        current = _normalized_address(peer)
        for raw_candidate in reversed(raw_chain.split(",")):
            if not _is_trusted_proxy(str(current), cidrs) or not _is_lan_address(str(current)):
                break
            current = _parse_forwarded_ip(raw_candidate)
    except ValueError:
        return None
    return str(current)


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
    cloudflare_authorization_cleanup_task: asyncio.Task[None] | None = None
    if settings.cloudflared_connector_enabled:
        try:
            cloudflare_service = await get_cloudflare_service_dep()
            await cloudflare_service.recover_incomplete_provisioning()
        except Exception:  # pragma: no cover - network runtime
            LOGGER.error("Unable to recover incomplete Cloudflare provisioning")
            raise
        else:
            (await get_cloudflare_oauth_manager_dep()).purge_expired_flows()

            async def purge_expired_cloudflare_authorizations() -> None:
                while True:
                    await asyncio.sleep(60)
                    try:
                        cloudflare_service.purge_expired_authorizations()
                    except Exception:  # pragma: no cover - storage runtime
                        LOGGER.warning(
                            "Unable to purge expired Cloudflare authorizations"
                        )

            cloudflare_authorization_cleanup_task = asyncio.create_task(
                purge_expired_cloudflare_authorizations()
            )
    if settings.tailscale_connector_enabled:
        try:
            tailscale_service = await get_tailscale_service_dep()
            await tailscale_service.recover_incomplete_provisioning()
        except Exception:  # pragma: no cover - private runtime
            LOGGER.warning("Unable to recover incomplete Tailscale provisioning")
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
                "Skipping LND connection check (macaroon lacks GetInfo permission)"
            )
        else:
            LOGGER.warning(
                "Unable to verify LND connection (error_type=%s)",
                type(exc).__name__,
            )
    except Exception as exc:  # pragma: no cover - network runtime
        LOGGER.warning(
            "Unable to verify LND connection (error_type=%s)",
            type(exc).__name__,
        )
    yield
    if cloudflare_authorization_cleanup_task is not None:
        cloudflare_authorization_cleanup_task.cancel()
        with suppress(asyncio.CancelledError):
            await cloudflare_authorization_cleanup_task
    await invoice_full_refresh_worker.stop()
    await invoice_subscription_worker.stop()
    await ln_client.close()


def _add_request_security(target_app: FastAPI) -> None:
    @target_app.middleware("http")
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
        request_host = request.headers.get("host", "")
        mesh_public_host: str | None = None
        mesh_candidate = request.headers.get("x-lns-public-host", "")
        mesh_key = request.headers.get("x-lns-mesh-key", "")
        if _normalized_authority_hostname(request_host) == "lns.internal":
            candidate_hostname = _normalized_authority_hostname(mesh_candidate)
            if candidate_hostname is not None:
                connection_store = await get_connection_store_dep()
                secret_store = await get_connection_secret_store_dep()
                for connection in connection_store.list_connections():
                    if connection.provider != "cloudflare":
                        continue
                    if not any(
                        domain.hostname == candidate_hostname
                        and domain.status in {"pending", "active"}
                        for domain in connection.domains
                    ):
                        continue
                    credential = secret_store.get(connection.id) or {}
                    expected_key = credential.get("mesh_ingress_key")
                    if (
                        isinstance(expected_key, str)
                        and expected_key
                        and secrets.compare_digest(mesh_key, expected_key)
                    ):
                        mesh_public_host = candidate_hostname
                    break
        if mesh_public_host is not None:
            request.state.mesh_public_host = mesh_public_host
        public_host = get_public_host(request)
        request_hostname = _normalized_authority_hostname(request_host)
        public_hostname = _normalized_authority_hostname(public_host)
        if request_hostname is None or public_hostname is None:
            return PlainTextResponse("Invalid host header", status_code=400)
        connection_store = await get_connection_store_dep()
        if not (
            _host_is_trusted(request_host, trusted_hosts)
            or connection_store.has_public_domain(request_hostname)
            or mesh_public_host is not None
        ) or not (
            _host_is_trusted(public_host, trusted_hosts)
            or connection_store.has_public_domain(public_hostname)
        ):
            return PlainTextResponse("Invalid host header", status_code=400)
        return await call_next(request)


def _add_admin_access_control(target_app: FastAPI) -> None:
    @target_app.middleware("http")
    async def restrict_admin_to_lan_or_umbrel_proxy(request: Request, call_next):
        """Keep administration off WAN while allowing Umbrel's authenticated proxy."""

        settings = get_settings()
        peer = request.client.host if request.client else ""
        peer_is_proxy = _is_trusted_proxy(peer, settings.trusted_proxy_cidrs)
        request.state.authenticated_admin_proxy = False
        request.state.authenticated_admin_https = False
        forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
        proxy_is_https = peer_is_proxy and forwarded_proto == "https"

        if (
            settings.dep_env.upper() in {"UMBREL", "UMBREL-DEV"}
            and peer_is_proxy
            and _is_lan_address(peer)
        ):
            request.state.authenticated_admin_proxy = True
            request.state.authenticated_admin_https = proxy_is_https
            return await call_next(request)
        if peer_is_proxy:
            proxy_client = _get_admin_proxy_client(request, settings.trusted_proxy_cidrs)
            if proxy_client is not None and _is_lan_address(proxy_client):
                request.state.authenticated_admin_proxy = bool(
                    request.headers.get("x-forwarded-user", "").strip()
                )
                request.state.authenticated_admin_https = proxy_is_https
                return await call_next(request)
            return PlainTextResponse("Forbidden", status_code=status.HTTP_403_FORBIDDEN)
        if _is_lan_address(peer):
            return await call_next(request)
        return PlainTextResponse("Forbidden", status_code=status.HTTP_403_FORBIDDEN)


def _add_cloudflare_response_privacy(target_app: FastAPI) -> None:
    @target_app.middleware("http")
    async def prevent_cloudflare_admin_caching(request: Request, call_next):
        is_cloudflare_admin = request.url.path.startswith(
            ("/api/connections/cloudflare", "/api/cloudflare/oauth")
        )
        try:
            response = await call_next(request)
        except Exception:
            if not is_cloudflare_admin:
                raise
            LOGGER.error("Unhandled Cloudflare administration request failure")
            response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Cloudflare operation failed"},
            )
        if is_cloudflare_admin:
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"
        return response


async def require_configured_public_domain(
    request: Request,
    address_store: LNAddressStore = Depends(get_ln_address_store_dep),
    identity_store: NostrIdentityStore = Depends(get_nip05_store_dep),
    connection_store: ConnectionStore = Depends(get_connection_store_dep),
) -> None:
    """Require the resolved public domain to exist in a public registry."""

    domain = get_public_domain(request)
    if domain and (
        await address_store.has_domain(domain)
        or await identity_store.has_domain(domain)
        or connection_store.has_public_domain(domain)
    ):
        return
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


admin_app = FastAPI(
    title="lnSwitchboard",
    version=get_version(),
    lifespan=lifespan,
)
public_app = FastAPI(
    title="lnSwitchboard Public",
    version=get_version(),
    dependencies=[Depends(require_configured_public_domain)],
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@admin_app.exception_handler(RequestValidationError)
async def sanitize_cloudflare_oauth_validation(
    request: Request, exc: RequestValidationError
):
    if request.url.path.startswith(
        ("/api/cloudflare/oauth", "/api/connections/cloudflare")
    ):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": "Invalid Cloudflare request"},
        )
    return await request_validation_exception_handler(request, exc)


_add_admin_access_control(admin_app)
_add_request_security(admin_app)
_add_cloudflare_response_privacy(admin_app)
_add_request_security(public_app)

admin_app.include_router(ui_router.router)
admin_app.include_router(cloudflare_oauth_router.router)
admin_app.include_router(connections_router.router)
admin_app.include_router(webhooks_router.router)
admin_app.include_router(ln_addresses_router.api_router)
admin_app.include_router(nip05_router.api_router)

public_app.include_router(nip05_router.public_router)
public_app.include_router(lnurl_router.router)


def _register_client_redirect(path: str) -> None:
    target = f"{path.strip('/')}/"
    target = f"/{target}" if not target.startswith("/") else target

    @admin_app.get(path, include_in_schema=False)
    async def _redirect_to_trailing_slash() -> RedirectResponse:
        return RedirectResponse(url=target, status_code=307)


for _client_path in ("/logs", "/liquidity", "/settings", "/identities", "/addresses", "/invoices", "/webhooks"):
    _register_client_redirect(_client_path)

if STATIC_DIR.exists():
    @admin_app.get("/", include_in_schema=False)
    async def _spa_root() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    for _spa_path in SPA_ROUTES:
        @admin_app.get(_spa_path, include_in_schema=False)
        async def _spa_route() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    admin_app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


class ListenerDispatchApp:
    """Dispatch requests to route-isolated ASGI apps by local listener port."""

    def __init__(self, *, admin: ASGIApp, public: ASGIApp) -> None:
        self.admin = admin
        self.public = public

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        server = scope.get("server")
        is_public_request = (
            scope["type"] in {"http", "websocket"}
            and server is not None
            and server[1] == get_settings().public_service_port
        )
        target = self.public if is_public_request else self.admin
        await target(scope, receive, send)


app = ListenerDispatchApp(
    admin=admin_app,
    public=public_app,
)
