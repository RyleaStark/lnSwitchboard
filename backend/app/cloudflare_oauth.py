"""Cloudflare account OAuth onboarding (authorization code + PKCE, public client).

Privacy contract (owner requirement):
- Public client with PKCE S256 and no client_secret.
- Codes, verifiers, and tokens are never logged (fixed-message logging only)
  and never returned to any caller except the one-time authorize URL.
- Token exchange happens directly between this instance and Cloudflare's
  token endpoint; no third party ever sees customer data.

Endpoints confirmed against Cloudflare's OIDC discovery document
(https://dash.cloudflare.com/.well-known/openid-configuration) and the
fundamentals OAuth docs (https://developers.cloudflare.com/fundamentals/oauth/):
- authorization: https://dash.cloudflare.com/oauth2/auth
- token:         https://dash.cloudflare.com/oauth2/token
- revocation:    https://dash.cloudflare.com/oauth2/revoke
- response_mode=fragment is supported; PKCE S256 is required for public
  clients (token_endpoint_auth_method "none").
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlencode

import httpx

from .config import Settings
from .connection_secret_store import ConnectionSecretStore

logger = logging.getLogger(__name__)

FLOW_PREFIX = "cloudflare-oauth-flow:"
GRANT_PREFIX = "cloudflare-oauth-grant:"

# Documented at https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/
CLOUDFLARE_OAUTH_REVOKE_URL = "https://dash.cloudflare.com/oauth2/revoke"

ACCESS_TOKEN_SKEW_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 15.0

RedirectMode = Literal["loopback", "page"]

# Non-token token-response fields worth keeping as grant metadata.
_ACCOUNT_METADATA_KEYS = ("account_id", "account_name", "account_label", "sub")


class CloudflareOAuthError(RuntimeError):
    """Base class for sanitized Cloudflare OAuth failures."""


class CloudflareOAuthStateError(CloudflareOAuthError):
    """The authorization state is unknown, expired, or already consumed."""

    def __init__(self) -> None:
        super().__init__("invalid or expired authorization state")


class CloudflareOAuthExchangeError(CloudflareOAuthError):
    """The provider rejected a token-endpoint request."""


class CloudflareOAuthGrantNotFoundError(CloudflareOAuthError):
    """The referenced grant does not exist."""

    def __init__(self) -> None:
        super().__init__("unknown Cloudflare OAuth grant")


class CloudflareOAuthReauthRequiredError(CloudflareOAuthError):
    """The grant was revoked or expired; the user must reconnect."""

    def __init__(self) -> None:
        super().__init__("Cloudflare authorization expired; reconnect the account")


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _scrub(text: str, sensitive: list[str | None]) -> str:
    """Return text with any known secret values removed before surfacing."""
    for value in sensitive:
        if value:
            text = text.replace(value, "[redacted]")
    return text


@dataclass(frozen=True)
class OAuthFlowBegin:
    flow_id: str
    authorize_url: str
    expires_at: float


class CloudflareOAuthManager:
    """Owns the Cloudflare OAuth flow state and the resulting grants."""

    def __init__(
        self,
        *,
        settings: Settings,
        secret_store: ConnectionSecretStore,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._secrets = secret_store
        self._transport = transport

    # ------------------------------------------------------------------
    # Flow (begin/complete) handling
    # ------------------------------------------------------------------
    def _redirect_uri(self, redirect_mode: RedirectMode) -> str:
        if redirect_mode == "loopback":
            return self._settings.cloudflare_oauth_redirect_loopback
        if redirect_mode == "page":
            return self._settings.cloudflare_oauth_redirect_page
        raise ValueError("redirect_mode must be 'loopback' or 'page'")

    def _flow_ttl(self) -> int:
        return max(0, int(self._settings.cloudflare_oauth_state_ttl_seconds))

    def _iter_flow_owners(self) -> list[str]:
        return [
            owner
            for owner in self._secrets.list_owner_ids()
            if owner.startswith(FLOW_PREFIX)
        ]

    def _is_expired(self, payload: dict[str, Any]) -> bool:
        created_at = float(payload.get("created_at", 0.0))
        return time.time() > created_at + self._flow_ttl()

    def _load_flow_by_state(self, state: str) -> tuple[str, dict[str, Any]] | None:
        """Find the flow for a state, purging expired flows encountered."""
        for owner in self._iter_flow_owners():
            try:
                payload = self._secrets.get(owner)
            except ValueError:
                logger.warning("cloudflare oauth flow record unreadable; deleting")
                self._secrets.delete(owner)
                continue
            if payload is None:
                continue
            if self._is_expired(payload):
                self._secrets.delete(owner)
                continue
            if payload.get("state") == state:
                return owner, payload
        return None

    def purge_expired_flows(self) -> int:
        """Startup sweep: delete every expired flow record. Returns count."""
        purged = 0
        for owner in self._iter_flow_owners():
            try:
                payload = self._secrets.get(owner)
            except ValueError:
                self._secrets.delete(owner)
                purged += 1
                continue
            if payload is None or self._is_expired(payload):
                if self._secrets.delete(owner):
                    purged += 1
        if purged:
            logger.info("purged %d expired cloudflare oauth flow(s)", purged)
        return purged

    def begin_flow(self, redirect_mode: RedirectMode) -> OAuthFlowBegin:
        redirect_uri = self._redirect_uri(redirect_mode)
        flow_id = secrets.token_urlsafe(16)
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        created_at = time.time()
        self._secrets.set(
            f"{FLOW_PREFIX}{flow_id}",
            {
                "state": state,
                "verifier": verifier,
                "redirect_mode": redirect_mode,
                "redirect_uri": redirect_uri,
                "created_at": created_at,
            },
        )
        # Cloudflare supports response_mode=fragment (confirmed via OIDC
        # discovery). Fragment keeps the code out of every server log when
        # using the static project-domain page; loopback uses query.
        response_mode = "fragment" if redirect_mode == "page" else "query"
        query = urlencode(
            {
                "client_id": self._settings.cloudflare_oauth_client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "response_mode": response_mode,
                "scope": self._settings.cloudflare_oauth_scope,
                "state": state,
                "code_challenge": _pkce_challenge(verifier),
                "code_challenge_method": "S256",
            }
        )
        authorize_url = f"{self._settings.cloudflare_oauth_authorize_url}?{query}"
        logger.info("cloudflare oauth flow started")
        return OAuthFlowBegin(
            flow_id=flow_id,
            authorize_url=authorize_url,
            expires_at=created_at + self._flow_ttl(),
        )

    async def _token_request(
        self,
        form: dict[str, str],
        sensitive: list[str | None],
    ) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(
                timeout=HTTP_TIMEOUT_SECONDS, transport=self._transport
            ) as client:
                response = await client.post(
                    self._settings.cloudflare_oauth_token_url,
                    data=form,
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            logger.warning("cloudflare oauth token endpoint unreachable")
            raise CloudflareOAuthExchangeError(
                "Cloudflare OAuth token endpoint is unreachable"
            ) from exc
        try:
            body = response.json()
        except ValueError:
            body = None
        if response.is_error or not isinstance(body, dict):
            if isinstance(body, (dict, list)):
                detail = json.dumps(body)
            else:
                detail = response.text[:500]
            detail = _scrub(detail, sensitive)
            logger.warning("cloudflare oauth token request rejected")
            raise CloudflareOAuthExchangeError(
                f"Cloudflare OAuth token endpoint returned HTTP "
                f"{response.status_code}: {detail[:500]}"
            )
        return body

    async def complete_flow(self, *, state: str, code: str) -> dict[str, Any]:
        """Exchange an authorization code and persist the resulting grant."""
        found = self._load_flow_by_state(state)
        if found is None:
            raise CloudflareOAuthStateError()
        owner, flow = found
        # Single-use: the flow secret is deleted before the exchange so a
        # replayed callback can never be redeemed twice.
        self._secrets.delete(owner)
        if not code:
            raise CloudflareOAuthExchangeError(
                "authorization response did not include a code"
            )
        verifier = str(flow.get("verifier") or "")
        token_payload = await self._token_request(
            {
                "grant_type": "authorization_code",
                "client_id": self._settings.cloudflare_oauth_client_id,
                "code": code,
                "redirect_uri": str(flow.get("redirect_uri") or ""),
                "code_verifier": verifier,
            },
            sensitive=[code, verifier],
        )
        grant = self._persist_grant(token_payload, previous=None)
        logger.info("cloudflare oauth grant stored")
        return self._grant_metadata(GRANT_PREFIX + grant, self._load_grant(grant))

    # ------------------------------------------------------------------
    # Grant storage and maintenance
    # ------------------------------------------------------------------
    def _grant_owner(self, grant_id: str) -> str:
        return f"{GRANT_PREFIX}{grant_id}"

    def _load_grant(self, grant_id: str) -> dict[str, Any]:
        payload = self._secrets.get(self._grant_owner(grant_id))
        if payload is None:
            raise CloudflareOAuthGrantNotFoundError()
        return payload

    def _persist_grant(
        self,
        token_payload: dict[str, Any],
        *,
        previous: dict[str, Any] | None,
        grant_id: str | None = None,
    ) -> str:
        now = time.time()
        expires_in = token_payload.get("expires_in")
        try:
            expires_at = now + float(expires_in) if expires_in is not None else None
        except (TypeError, ValueError):
            expires_at = None
        record: dict[str, Any] = {
            "refresh_token": token_payload.get("refresh_token"),
            "access_token": token_payload.get("access_token"),
            "access_token_expires_at": expires_at,
            "scopes": str(token_payload.get("scope") or ""),
            "updated_at": now,
            "created_at": previous.get("created_at", now) if previous else now,
        }
        # Preserve account metadata verbatim from the provider response.
        metadata = dict(previous.get("account_metadata", {})) if previous else {}
        for key in _ACCOUNT_METADATA_KEYS:
            if key in token_payload:
                metadata[key] = token_payload[key]
        record["account_metadata"] = metadata
        if previous is not None:
            # Providers that rotate refresh tokens send a new one; otherwise
            # keep the existing token.
            if not record["refresh_token"]:
                record["refresh_token"] = previous.get("refresh_token")
            if grant_id is None:
                raise ValueError("grant_id is required when updating a grant")
            new_grant_id = grant_id
        else:
            new_grant_id = grant_id or secrets.token_urlsafe(16)
        self._secrets.set(self._grant_owner(new_grant_id), record)
        return new_grant_id

    @staticmethod
    def _grant_metadata(owner: str, payload: dict[str, Any]) -> dict[str, Any]:
        metadata = payload.get("account_metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        label = (
            metadata.get("account_name")
            or metadata.get("account_label")
            or metadata.get("account_id")
        )
        return {
            "grant_id": owner.removeprefix(GRANT_PREFIX),
            "scopes": payload.get("scopes") or "",
            "account_label": label,
            "account_metadata": metadata,
            "access_token_expires_at": payload.get("access_token_expires_at"),
            "has_refresh_token": bool(payload.get("refresh_token")),
            "created_at": payload.get("created_at"),
            "updated_at": payload.get("updated_at"),
        }

    def list_grants(self) -> list[dict[str, Any]]:
        """Metadata-only view of stored grants; never includes tokens."""
        grants: list[dict[str, Any]] = []
        for owner in self._secrets.list_owner_ids():
            if not owner.startswith(GRANT_PREFIX):
                continue
            try:
                payload = self._secrets.get(owner)
            except ValueError:
                logger.warning("cloudflare oauth grant record unreadable; deleting")
                self._secrets.delete(owner)
                continue
            if payload is None:
                continue
            grants.append(self._grant_metadata(owner, payload))
        return grants

    async def get_access_token(self, grant_id: str) -> str:
        """Return a fresh access token, refreshing via refresh_token if needed."""
        grant = self._load_grant(grant_id)
        access_token = grant.get("access_token")
        expires_at = grant.get("access_token_expires_at")
        now = time.time()
        if access_token and (
            expires_at is None
            or float(expires_at) - ACCESS_TOKEN_SKEW_SECONDS > now
        ):
            return str(access_token)
        refresh_token = grant.get("refresh_token")
        if not refresh_token:
            self._secrets.delete(self._grant_owner(grant_id))
            raise CloudflareOAuthReauthRequiredError()
        try:
            token_payload = await self._token_request(
                {
                    "grant_type": "refresh_token",
                    "client_id": self._settings.cloudflare_oauth_client_id,
                    "refresh_token": str(refresh_token),
                },
                sensitive=[str(refresh_token), str(access_token or "")],
            )
        except CloudflareOAuthExchangeError as exc:
            if "invalid_grant" in str(exc):
                self._secrets.delete(self._grant_owner(grant_id))
                logger.info("cloudflare oauth grant removed after invalid_grant")
                raise CloudflareOAuthReauthRequiredError() from exc
            raise
        self._persist_grant(token_payload, previous=grant, grant_id=grant_id)
        logger.info("cloudflare oauth access token refreshed")
        new_token = token_payload.get("access_token")
        if not new_token:
            raise CloudflareOAuthExchangeError(
                "Cloudflare OAuth token endpoint response lacked an access token"
            )
        return str(new_token)

    async def revoke(self, grant_id: str) -> bool:
        """Best-effort provider revocation; the local grant is always deleted."""
        try:
            grant = self._load_grant(grant_id)
        except CloudflareOAuthGrantNotFoundError:
            return False
        token = grant.get("refresh_token") or grant.get("access_token")
        if token:
            try:
                async with httpx.AsyncClient(
                    timeout=HTTP_TIMEOUT_SECONDS, transport=self._transport
                ) as client:
                    await client.post(
                        CLOUDFLARE_OAUTH_REVOKE_URL,
                        data={
                            "client_id": self._settings.cloudflare_oauth_client_id,
                            "token": str(token),
                            "token_type_hint": (
                                "refresh_token"
                                if grant.get("refresh_token")
                                else "access_token"
                            ),
                        },
                    )
            except httpx.HTTPError:
                logger.warning("cloudflare oauth revocation endpoint unreachable")
        self._secrets.delete(self._grant_owner(grant_id))
        logger.info("cloudflare oauth grant revoked")
        return True
