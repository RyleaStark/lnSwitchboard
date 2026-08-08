"""Administration API for Cloudflare account OAuth onboarding.

OAuth-only onboarding: there is deliberately no API-token path here. All
responses are Cache-Control: no-store, private, and no endpoint ever returns
codes, verifiers, or tokens — begin returns the one-time authorize URL, and
grant endpoints return metadata only.
"""

from __future__ import annotations

from typing import Literal, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from ..cloudflare_oauth import (
    CloudflareOAuthError,
    CloudflareOAuthExchangeError,
    CloudflareOAuthGrantNotFoundError,
    CloudflareOAuthManager,
    CloudflareOAuthReauthRequiredError,
    CloudflareOAuthStateError,
)
from ..cloudflare_service import CloudflareConflictError, CloudflareService
from .. import deps as app_deps

router = APIRouter(prefix="/api/cloudflare/oauth", tags=["cloudflare-oauth"])

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, private",
    "Pragma": "no-cache",
}
_CONNECTED_TARGET = "/connections/cloudflare/?cloudflare=connected"
_ERROR_TARGET = "/connections/cloudflare/?cloudflare=error"


def _set_private_no_store(response: Response) -> None:
    for key, value in _NO_STORE_HEADERS.items():
        response.headers[key] = value


async def get_cloudflare_oauth_manager_dep(
    manager: CloudflareOAuthManager = Depends(app_deps.get_cloudflare_oauth_manager_dep),
) -> CloudflareOAuthManager:
    """Share the cached manager (and its access-token cache) with the app."""
    return manager


class BeginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redirect_mode: Literal["loopback", "page"] = "loopback"


class CompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=2048)
    state: str = Field(min_length=1, max_length=2048)


def _raise_for_oauth_error(exc: CloudflareOAuthError) -> NoReturn:
    if isinstance(exc, CloudflareOAuthStateError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
            headers=_NO_STORE_HEADERS,
        ) from exc
    if isinstance(exc, CloudflareOAuthExchangeError):
        # Provider error bodies are surfaced verbatim (already scrubbed of
        # code/verifier/token values by the manager).
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
            headers=_NO_STORE_HEADERS,
        ) from exc
    if isinstance(exc, CloudflareOAuthReauthRequiredError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
            headers=_NO_STORE_HEADERS,
        ) from exc
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=str(exc),
        headers=_NO_STORE_HEADERS,
    ) from exc


@router.post("/begin")
async def begin_oauth_flow(
    payload: BeginRequest,
    response: Response,
    manager: CloudflareOAuthManager = Depends(get_cloudflare_oauth_manager_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    flow = manager.begin_flow(payload.redirect_mode)
    return {
        "flow_id": flow.flow_id,
        "authorize_url": flow.authorize_url,
        "expires_at": flow.expires_at,
    }


@router.get("/callback")
async def oauth_loopback_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    manager: CloudflareOAuthManager = Depends(get_cloudflare_oauth_manager_dep),
) -> RedirectResponse:
    """Loopback redirect target: auto-complete, then bounce to the UI."""
    if error or not code or not state:
        return RedirectResponse(
            _ERROR_TARGET,
            status_code=status.HTTP_303_SEE_OTHER,
            headers=_NO_STORE_HEADERS,
        )
    try:
        await manager.complete_flow(state=state, code=code)
    except CloudflareOAuthError:
        return RedirectResponse(
            _ERROR_TARGET,
            status_code=status.HTTP_303_SEE_OTHER,
            headers=_NO_STORE_HEADERS,
        )
    return RedirectResponse(
        _CONNECTED_TARGET,
        status_code=status.HTTP_303_SEE_OTHER,
        headers=_NO_STORE_HEADERS,
    )


@router.post("/complete")
async def complete_oauth_flow(
    payload: CompleteRequest,
    response: Response,
    manager: CloudflareOAuthManager = Depends(get_cloudflare_oauth_manager_dep),
) -> dict[str, object]:
    """Paste-back completion for the static project-domain callback page."""
    _set_private_no_store(response)
    try:
        grant = await manager.complete_flow(state=payload.state, code=payload.code)
    except CloudflareOAuthError as exc:
        _raise_for_oauth_error(exc)
    return grant


@router.get("/grants")
async def list_oauth_grants(
    response: Response,
    manager: CloudflareOAuthManager = Depends(get_cloudflare_oauth_manager_dep),
) -> dict[str, object]:
    _set_private_no_store(response)
    return {"grants": manager.list_grants()}


@router.delete("/grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_oauth_grant(
    grant_id: str,
    response: Response,
    manager: CloudflareOAuthManager = Depends(get_cloudflare_oauth_manager_dep),
    service: CloudflareService = Depends(app_deps.get_cloudflare_service_dep),
) -> Response:
    _set_private_no_store(response)
    try:
        revoked = await service.revoke_grant_if_unused(grant_id, manager.revoke)
    except CloudflareConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
            headers=_NO_STORE_HEADERS,
        ) from exc
    except CloudflareOAuthGrantNotFoundError:
        revoked = False
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="unknown Cloudflare OAuth grant",
            headers=_NO_STORE_HEADERS,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers=_NO_STORE_HEADERS)
