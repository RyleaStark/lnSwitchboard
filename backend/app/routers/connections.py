"""Administration API for provider-neutral external service connections."""

from __future__ import annotations

from dataclasses import asdict
from typing import Awaitable, Callable, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from ..cloudflare_client import CloudflareAPIError
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
)

router = APIRouter(prefix="/api/connections", tags=["connections"])
_Result = TypeVar("_Result")
CLOUDFLARE_AUTHORIZATION_COOKIE = "lnswitchboard_cloudflare_authorization"
_REQUIRED_PERMISSIONS = [
    "Account / Cloudflare Tunnel / Edit",
    "Account / Account Settings / Read",
    "Zone / DNS / Edit",
    "Zone / Zone / Read",
]
_SENSITIVE_METADATA_KEY_PARTS = ("authorization", "credential", "secret", "token")


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
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc
    except CloudflareServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Cloudflare operation failed",
        ) from exc


@router.get("")
async def list_connections(
    store: ConnectionStore = Depends(get_connection_store_dep),
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    connector_available = settings.cloudflared_connector_enabled
    return {
        "providers": [
            {
                "id": "cloudflare",
                "name": "Cloudflare",
                "capability": "available" if connector_available else "unavailable",
                "reason": None if connector_available else "connector_not_installed",
            }
        ],
        "connections": [
            _serialize_connection(connection) for connection in store.list_connections()
        ],
    }


@router.get("/cloudflare/setup")
async def cloudflare_setup(
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    return {
        "available": settings.cloudflared_connector_enabled,
        "origin": settings.cloudflared_origin_url,
        "required_permissions": _REQUIRED_PERMISSIONS,
        "authorization_method": "api_token",
    }


@router.post("/cloudflare/authorize")
async def authorize_cloudflare(
    request: Request,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    try:
        payload = await request.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid Cloudflare authorization request",
        ) from exc
    api_token = payload.get("api_token") if isinstance(payload, dict) else None
    if not isinstance(api_token, str) or not 1 <= len(api_token) <= 4096:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid Cloudflare authorization request",
        )
    authorization = await _cloudflare_call(lambda: service.authorize(api_token))
    response.set_cookie(
        CLOUDFLARE_AUTHORIZATION_COOKIE,
        str(authorization["authorization_id"]),
        max_age=900,
        secure=True,
        httponly=True,
        samesite="lax",
        path="/api/connections/cloudflare",
    )
    return {"accounts": authorization["accounts"]}


@router.get("/cloudflare/authorization")
async def get_cloudflare_authorization(
    request: Request,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    authorization_id = request.cookies.get(CLOUDFLARE_AUTHORIZATION_COOKIE)
    if not authorization_id:
        raise HTTPException(status_code=404, detail="Authorization not found")

    async def operation() -> dict[str, object]:
        return service.get_authorization(authorization_id)

    return await _cloudflare_call(operation)


@router.delete("/cloudflare/authorization")
async def cancel_cloudflare_authorization(
    request: Request,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, bool]:
    authorization_id = request.cookies.get(CLOUDFLARE_AUTHORIZATION_COOKIE)
    cancelled = (
        service.cancel_authorization(authorization_id) if authorization_id else False
    )
    response.delete_cookie(
        CLOUDFLARE_AUTHORIZATION_COOKIE,
        path="/api/connections/cloudflare",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return {"cancelled": cancelled}


@router.post("/cloudflare/provision", status_code=status.HTTP_201_CREATED)
async def provision_cloudflare(
    request: CloudflareProvisionRequest,
    raw_request: Request,
    response: Response,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    authorization_id = raw_request.cookies.get(CLOUDFLARE_AUTHORIZATION_COOKIE)
    if not authorization_id:
        raise HTTPException(status_code=404, detail="Authorization not found")
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
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return _serialize_connection(connection)


@router.post("/cloudflare/{connection_id}/status")
async def refresh_cloudflare_status(
    connection_id: str,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, object]:
    connection = await _cloudflare_call(lambda: service.refresh_status(connection_id))
    return _serialize_connection(connection)


@router.delete("/cloudflare/{connection_id}")
async def disconnect_cloudflare(
    connection_id: str,
    service: CloudflareService = Depends(get_cloudflare_service_dep),
) -> dict[str, bool]:
    removed = await _cloudflare_call(lambda: service.disconnect(connection_id))
    return {"disconnected": removed}
