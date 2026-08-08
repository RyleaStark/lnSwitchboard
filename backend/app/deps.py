"""FastAPI dependency wiring."""

from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, HTTPException, Request, status

from .cloudflare_client import CloudflareClient
from .cloudflare_oauth import CloudflareOAuthManager
from .cloudflare_service import CloudflareService
from .config import Settings, get_settings
from .connection_secret_store import ConnectionSecretStore
from .connection_store import ConnectionStore
from .ln_address_store import LNAddressStore
from .ln_client import LNClient
from .log_storage import LogEntry, RequestLogStorage
from .macaroon_store import MacaroonStore
from .nostr_signer_store import NostrSignerStore
from .nostr_zaps import NostrZapPublisher
from .nip05_store import NostrIdentityStore
from .rate_limiter import RateLimiter
from .request_utils import get_client_ip
from .tailscale_connector import TailscaleConnector
from .tailscale_service import TailscaleService
from .webhook_dispatcher import WebhookDispatcher


@lru_cache()
def _get_log_storage() -> RequestLogStorage:
    settings = get_settings()
    return RequestLogStorage(
        settings.data_store_path,
        max_recent=settings.recent_log_limit,
        retention_days=settings.log_retention_days,
    )


@lru_cache()
def _get_rate_limiter() -> RateLimiter:
    settings = get_settings()
    return RateLimiter(limit=settings.rate_limit_per_min)


@lru_cache()
def _get_macaroon_store() -> MacaroonStore:
    settings = get_settings()
    return MacaroonStore(settings.macaroon_store_path, settings.lnd_macaroon_path)


@lru_cache()
def _get_readonly_macaroon_store() -> MacaroonStore | None:
    settings = get_settings()
    if settings.lnd_readonly_macaroon_path is None:
        return None
    return MacaroonStore(settings.macaroon_store_path, settings.lnd_readonly_macaroon_path)


@lru_cache()
def _get_nip05_store() -> NostrIdentityStore:
    settings = get_settings()
    return NostrIdentityStore(settings.data_store_path)


@lru_cache()
def _get_ln_address_store() -> LNAddressStore:
    settings = get_settings()
    return LNAddressStore(settings.data_store_path)


@lru_cache()
def _get_connection_store() -> ConnectionStore:
    return ConnectionStore(get_settings().data_store_path)


@lru_cache()
def _get_connection_secret_store() -> ConnectionSecretStore:
    settings = get_settings()
    return ConnectionSecretStore(settings.data_store_path, settings.connection_secret_key_path)


@lru_cache()
def _get_cloudflare_oauth_manager() -> CloudflareOAuthManager:
    return CloudflareOAuthManager(
        settings=get_settings(),
        secret_store=_get_connection_secret_store(),
    )


@lru_cache()
def _get_cloudflare_service() -> CloudflareService:
    settings = get_settings()
    return CloudflareService(
        store=_get_connection_store(),
        secrets=_get_connection_secret_store(),
        client_factory=CloudflareClient,
        connector_enabled=settings.cloudflared_connector_enabled,
        token_path=settings.cloudflared_token_path,
        origin_url=settings.cloudflared_origin_url,
        token_gid=settings.cloudflared_token_gid,
        access_token_resolver=_get_cloudflare_oauth_manager().get_access_token,
    )


@lru_cache()
def _get_tailscale_service() -> TailscaleService:
    settings = get_settings()
    return TailscaleService(
        connector=TailscaleConnector(
            control_dir=settings.tailscale_control_dir,
            status_dir=settings.tailscale_status_dir,
        ),
        store=_get_connection_store(),
        connector_enabled=settings.tailscale_connector_enabled,
    )


@lru_cache()
def _get_ln_client() -> LNClient:
    settings = get_settings()
    return LNClient(
        host=settings.lnd_host,
        port=settings.lnd_grpc_port,
        macaroon_store=_get_macaroon_store(),
        readonly_macaroon_store=_get_readonly_macaroon_store(),
        tls_path=settings.lnd_tls_path,
        tls_server_name=settings.lnd_tls_server_name,
    )


@lru_cache()
def _get_webhook_dispatcher() -> WebhookDispatcher:
    settings = get_settings()
    return WebhookDispatcher(
        address_store=_get_ln_address_store(),
        delivery_storage=_get_log_storage(),
        max_retries=settings.webhook_max_retries,
        retry_window_seconds=settings.webhook_retry_window_seconds,
        zap_publisher=_get_zap_publisher(),
        allow_private_webhooks=settings.allow_private_webhooks,
    )


@lru_cache()
def _get_nostr_signer_store() -> NostrSignerStore:
    settings = get_settings()
    return NostrSignerStore(settings.nostr_zap_secret_path)


@lru_cache()
def _get_zap_publisher() -> NostrZapPublisher:
    settings = get_settings()
    return NostrZapPublisher(
        signer_store=_get_nostr_signer_store(),
        storage=_get_log_storage(),
        allow_private_relays=settings.allow_private_nostr_relays,
    )


async def get_settings_dep() -> Settings:
    return get_settings()


async def get_log_storage_dep() -> RequestLogStorage:
    return _get_log_storage()


async def get_rate_limiter_dep() -> RateLimiter:
    return _get_rate_limiter()


async def get_ln_client_dep() -> LNClient:
    return _get_ln_client()


async def get_macaroon_store_dep() -> MacaroonStore:
    return _get_macaroon_store()


async def get_nip05_store_dep() -> NostrIdentityStore:
    return _get_nip05_store()


async def get_ln_address_store_dep() -> LNAddressStore:
    return _get_ln_address_store()


async def get_connection_store_dep() -> ConnectionStore:
    return _get_connection_store()


async def get_connection_secret_store_dep() -> ConnectionSecretStore:
    return _get_connection_secret_store()


async def get_cloudflare_service_dep() -> CloudflareService:
    return _get_cloudflare_service()


async def get_cloudflare_oauth_manager_dep() -> CloudflareOAuthManager:
    return _get_cloudflare_oauth_manager()


async def get_tailscale_service_dep() -> TailscaleService:
    return _get_tailscale_service()


async def get_webhook_dispatcher_dep() -> WebhookDispatcher:
    return _get_webhook_dispatcher()


async def get_nostr_signer_store_dep() -> NostrSignerStore:
    return _get_nostr_signer_store()


async def enforce_rate_limit(
    request: Request,
    limiter: RateLimiter = Depends(get_rate_limiter_dep),
    storage: RequestLogStorage = Depends(get_log_storage_dep),
) -> None:
    ip = get_client_ip(request)
    domain = request.url.hostname or request.headers.get("host") or "unknown"
    allowed, _remaining = await limiter.check(ip)
    if not allowed:
        username = request.path_params.get("username", "unknown")
        entry = LogEntry.create(
            username=username,
            ip=ip,
            event="rate_limit",
            domain=domain,
            status="blocked",
            message="rate limit exceeded",
            # Deliberately slim: blocked floods must not let an attacker grow
            # request-log rows with per-request proxy debug payloads.
            details={},
        )
        await storage.append(entry)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
        )
