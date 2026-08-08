"""Administration API for provider-neutral external service connections."""

from __future__ import annotations

from dataclasses import asdict
from typing import Awaitable, Callable, TypeVar

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from ..cloudflare_client import CloudflareAPIError
from ..cloudflare_oauth import CloudflareOAuthReauthRequiredError
from ..cloudflare_service import (
    CloudflareConflictError,
    CloudflareNotFoundError,
    CloudflareService,
    CloudflareServiceError,
    CloudflareUnavailableError,
    CloudflareValidationError,
)
from ..config import Settings
from ..connection_store import ConnectionStore, ProviderConnection
from ..deps import (
    get_cloudflare_service_dep,
    get_connection_store_dep,
    get_settings_dep,
    get_tailscale_service_dep,
)
from ..tailscale_connector import TailscaleProtocolError
from ..tailscale_service import (
    TailscaleNotFoundError,
    TailscaleOperationError,
    TailscaleService,
    TailscaleUnavailableError,
    TailscaleValidationError,
)

router = APIRouter(prefix="/api/connections", tags=["connections"])
_Result = TypeVar("_Result")
CLOUDFLARE_AUTHORIZATION_COOKIE = "lnswitchboard_cloudflare_authorization"
TAILSCALE_LOGIN_COOKIE = "lnswitchboard_tailscale_login"
_REQUIRED_PERMISSIONS = [
    "Account / Account Settings / Read",
    "Account / Workers Scripts / Edit",
    "Account / Zero Trust / Edit",
    "Account / Access: Apps and Policies / Edit",
    "Zone / Workers Routes / Edit",
    "Zone / DNS / Edit",
    "Zone / Zone / Read",
]
_SENSITIVE_METADATA_KEY_PARTS = ("authorization", "credential", "secret", "token")
_PRIVATE_NO_STORE = "no-store, private"


def _set_private_no_store(response: Response) -> None:
    response.headers["Cache-Control"] = _PRIVATE_NO_STORE
    response.headers["Pragma"] = "no-cache"


def _serialize_connection(connection: ProviderConnection) -> dict[str, object]:
    payload = asdict(connection)
    metadata = payload.get("public_metadata")
    if isinstance(metadata, dict):
        payload["public_metadata"] = {
            key: value
            for key, value in metadata.items()
            if not any(part in key.casefold() for part in _SENSITIVE_METADATA_KEY_PARTS)
        }
    return payload


class CloudflareProvisionRequest(BaseModel):
    account_id: str
    zone_id: str
    hostname: str


class CloudflareAuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str = Field(min_length=1, max_length=256)
    account_id: str | None = Field(default=None, min_length=1, max_length=64)


class CloudflareDomainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    zone_id: str
    hostname: str


class TailscaleLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_name: str = Field(default="lns", min_length=1, max_length=63)


async def _tailscale_call(operation: Callable[[], Awaitable[_Result]]) -> _Result:
    try:
        return await operation()
    except TailscaleUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    except TailscaleValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except TailscaleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except (TailscaleOperationError, TailscaleProtocolError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Tailscale operation failed",
        ) from exc


async def _cloudflare_call(operation: Callable[[], Awaitable[_Result]]) -> _Result:
    try:
        return await operation()
    except CloudflareUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cloudflare connector is not installed",
        ) from exc
    except CloudflareConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    except CloudflareValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except CloudflareNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except CloudflareAPIError as exc:
        if exc.status_code == status.HTTP_409_CONFLICT:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cloudflare configuration changed; retry the operation",
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc
    except CloudflareOAuthReauthRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cloudflare authorization expired; reconnect Cloudflare",
        ) from exc
    except CloudflareServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Cloudflare operation failed",
        ) from exc


@router.get("")
async def list_connections(
    request: Request,
    store: ConnectionStore = Depends(get_connection_store_dep),
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    connector_available = settings.cloudflared_connector_enabled
    tailscale_available = settings.tailscale_connector_enabled
    tailscale_reason = (
        None if tailscale_available else "connector_not_installed"
    )
    return {
        "providers": [
            {
                "id": "cloudflare",
                "name": "Cloudflare",
                "capability": "available" if connector_available else "unavailable",
                "reason": (
                    None if connector_available else "connector_not_installed"
                ),
            },
            {
                "id": "tailscale",
                "name": "Tailscale Funnel",
                "capability": "available" if tailscale_available else "unavailable",
                "reason": tailscale_reason,
            },
        ],
        "connections": [
            _serialize_connection(connection) for connection in store.list_connections()
        ],
    }


@router.get(
    "/tailscale/setup",
)
async def tailscale_setup(
    service: TailscaleService = Depends(get_tailscale_service_dep),
) -> dict[str, object]:
    return service.setup()


@router.post(
    "/tailscale/login",
)
async def begin_tailscale_login(
    payload: TailscaleLoginRequest,
    response: Response,
    service: TailscaleService = Depends(get_tailscale_service_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    flow_id, result = await _tailscale_call(
        lambda: service.begin_login(payload.device_name)
    )
    response.set_cookie(
        TAILSCALE_LOGIN_COOKIE,
        flow_id,
        max_age=service.login_ttl_seconds,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/api/connections/tailscale",
    )
    return result


@router.get(
    "/tailscale/login",
)
async def tailscale_login_status(
    response: Response,
    flow_id: str | None = Cookie(default=None, alias=TAILSCALE_LOGIN_COOKIE),
    service: TailscaleService = Depends(get_tailscale_service_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    if not flow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tailscale login flow was not found",
        )
    result = await _tailscale_call(lambda: service.poll_login(flow_id))
    if result.get("state") in {"connected", "expired"}:
        response.delete_cookie(
            TAILSCALE_LOGIN_COOKIE,
            path="/api/connections/tailscale",
            secure=False,
            httponly=True,
            samesite="lax",
        )
    return result


@router.delete(
    "/tailscale/login",
)
async def cancel_tailscale_login(
    response: Response,
    flow_id: str | None = Cookie(default=None, alias=TAILSCALE_LOGIN_COOKIE),
    service: TailscaleService = Depends(get_tailscale_service_dep),
) -> dict[str, bool]:
    _set_private_no_store(response)
    if not flow_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tailscale login flow was not found",
        )
    cancelled = await _tailscale_call(lambda: service.cancel_login(flow_id))
    response.delete_cookie(
        TAILSCALE_LOGIN_COOKIE,
        path="/api/connections/tailscale",
        secure=False,
        httponly=True,
        samesite="lax",
    )
    return {"cancelled": cancelled}


@router.post(
    "/tailscale/{connection_id}/status",
)
async def refresh_tailscale_status(
    connection_id: str,
    service: TailscaleService = Depends(get_tailscale_service_dep),
) -> dict[str, object]:
    connection = await _tailscale_call(lambda: service.refresh(connection_id))
    return _serialize_connection(connection)


@router.delete(
    "/tailscale/{connection_id}",
)
async def disconnect_tailscale(
    connection_id: str,
    service: TailscaleService = Depends(get_tailscale_service_dep),
) -> dict[str, bool]:
    disconnected = await _tailscale_call(lambda: service.disconnect(connection_id))
    return {"disconnected": disconnected}


@router.get("/cloudflare/setup")
async def cloudflare_setup(
    response: Response,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    oauth_configured = (
        settings.cloudflare_oauth_client_id != "placeholder-client-id"
        and settings.cloudflare_oauth_redirect_page
        != "https://placeholder.invalid/oauth/callback"
        and len(settings.cloudflare_oauth_scope.split()) > 1
        and "replace-with" not in settings.cloudflare_oauth_scope
    )
    return {
        "available": settings.cloudflared_connector_enabled and oauth_configured,
        "oauth_configured": oauth_configured,
        "configuration_error": (
            None
            if oauth_configured
            else (
                "Cloudflare OAuth client, callback, and approved scope IDs are not "
                "configured for this deployment."
            )
        ),
        "origin": settings.cloudflared_origin_url,
        "required_permissions": _REQUIRED_PERMISSIONS,
        "authorization_method": "oauth",
    }


@router.post(
    "/cloudflare/authorize",
)
async def authorize_cloudflare(
    request: CloudflareAuthorizeRequest,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    account_id = request.account_id
    if account_id is None:
        accounts = await _cloudflare_call(
            lambda: service.discover_grant_accounts(request.grant_id)
        )
        return {
            "accounts": [
                {"id": account["id"], "name": account["name"], "zones": []}
                for account in accounts
            ],
        }
    authorization = await _cloudflare_call(
        lambda: service.authorize_grant(request.grant_id, account_id)
    )
    response.set_cookie(
        CLOUDFLARE_AUTHORIZATION_COOKIE,
        str(authorization["authorization_id"]),
        max_age=900,
        secure=False,
        httponly=True,
        samesite="lax",
        path="/api/connections/cloudflare",
    )
    accounts = authorization.get("accounts")
    return {"accounts": accounts if isinstance(accounts, list) else []}


@router.get(
    "/cloudflare/authorization",
)
async def get_cloudflare_authorization(
    request: Request,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    authorization_id = request.cookies.get(CLOUDFLARE_AUTHORIZATION_COOKIE)
    if not authorization_id:
        raise HTTPException(
            status_code=404,
            detail="Authorization not found",
            headers={"Cache-Control": _PRIVATE_NO_STORE, "Pragma": "no-cache"},
        )

    async def operation() -> dict[str, object]:
        return service.get_authorization(authorization_id)

    return await _cloudflare_call(operation)


@router.delete(
    "/cloudflare/authorization",
)
async def cancel_cloudflare_authorization(
    request: Request,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, bool]:
    _set_private_no_store(response)
    authorization_id = request.cookies.get(CLOUDFLARE_AUTHORIZATION_COOKIE)
    cancelled = (
        service.cancel_authorization(authorization_id) if authorization_id else False
    )
    response.delete_cookie(
        CLOUDFLARE_AUTHORIZATION_COOKIE,
        path="/api/connections/cloudflare",
        secure=False,
        httponly=True,
        samesite="lax",
    )
    return {"cancelled": cancelled}


@router.post(
    "/cloudflare/provision",
    status_code=status.HTTP_201_CREATED,
)
async def provision_cloudflare(
    request: CloudflareProvisionRequest,
    raw_request: Request,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    authorization_id = raw_request.cookies.get(CLOUDFLARE_AUTHORIZATION_COOKIE)
    if not authorization_id:
        raise HTTPException(
            status_code=404,
            detail="Authorization not found",
            headers={"Cache-Control": _PRIVATE_NO_STORE, "Pragma": "no-cache"},
        )
    connection = await _cloudflare_call(
        lambda: service.provision(
            authorization_id=authorization_id,
            account_id=request.account_id,
            zone_id=request.zone_id,
            hostname=request.hostname,
        )
    )
    response.delete_cookie(
        CLOUDFLARE_AUTHORIZATION_COOKIE,
        path="/api/connections/cloudflare",
        secure=False,
        httponly=True,
        samesite="lax",
    )
    return _serialize_connection(connection)


@router.get(
    "/cloudflare/{connection_id}/domains/available",
)
async def available_cloudflare_domains(
    connection_id: str,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    zones = await _cloudflare_call(lambda: service.available_zones(connection_id))
    return {"zones": zones}


@router.post(
    "/cloudflare/{connection_id}/domains",
    status_code=status.HTTP_201_CREATED,
)
async def add_cloudflare_domain(
    connection_id: str,
    request: CloudflareDomainRequest,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    connection = await _cloudflare_call(
        lambda: service.add_domain(connection_id, request.zone_id, request.hostname)
    )
    return _serialize_connection(connection)


@router.delete(
    "/cloudflare/{connection_id}/domains/{hostname}",
)
async def remove_cloudflare_domain(
    connection_id: str,
    hostname: str,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    connection = await _cloudflare_call(
        lambda: service.remove_domain(connection_id, hostname)
    )
    return _serialize_connection(connection)


@router.post(
    "/cloudflare/{connection_id}/status",
)
async def refresh_cloudflare_status(
    connection_id: str,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    connection = await _cloudflare_call(lambda: service.refresh_status(connection_id))
    return _serialize_connection(connection)


@router.delete(
    "/cloudflare/{connection_id}",
)
async def disconnect_cloudflare(
    connection_id: str,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, bool]:
    _set_private_no_store(response)
    removed = await _cloudflare_call(lambda: service.disconnect(connection_id))
    return {"disconnected": removed}
