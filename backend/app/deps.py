"""FastAPI dependency wiring."""

from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, HTTPException, Request, status

from .config import Settings, get_settings
from .ln_client import LNClient
from .macaroon_store import MacaroonStore
from .log_storage import LogEntry, RequestLogStorage
from .rate_limiter import RateLimiter
from .request_utils import get_client_ip, get_proxy_debug_info


@lru_cache()
def _get_log_storage() -> RequestLogStorage:
    settings = get_settings()
    return RequestLogStorage(settings.log_path, max_recent=settings.recent_log_limit)


@lru_cache()
def _get_rate_limiter() -> RateLimiter:
    settings = get_settings()
    return RateLimiter(limit=settings.rate_limit_per_min)


@lru_cache()
def _get_macaroon_store() -> MacaroonStore:
    settings = get_settings()
    return MacaroonStore(settings.macaroon_store_path)


@lru_cache()
def _get_ln_client() -> LNClient:
    settings = get_settings()
    return LNClient(
        host=settings.lnd_host,
        port=settings.lnd_grpc_port,
        macaroon_store=_get_macaroon_store(),
        tls_path=settings.lnd_tls_path,
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
            details={"proxy": get_proxy_debug_info(request)},
        )
        await storage.append(entry)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
        )
