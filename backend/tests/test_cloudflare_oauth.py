from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import sqlite3
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import FastAPI

from backend.app import config
from backend.app.cloudflare_oauth import (
    FLOW_PREFIX,
    GRANT_PREFIX,
    CloudflareOAuthManager,
    CloudflareOAuthReauthRequiredError,
    CloudflareOAuthStateError,
)
from backend.app.connection_secret_store import ConnectionSecretStore
from backend.app.routers import cloudflare_oauth as oauth_router

CODE = "test-authorization-code-abc123"
ACCESS_TOKEN = "cf-access-token-aaa111"
REFRESH_TOKEN = "cf-refresh-token-bbb222"
ROTATED_REFRESH_TOKEN = "cf-refresh-token-rotated333"
NEW_ACCESS_TOKEN = "cf-access-token-new444"

REPO_ROOT = Path(__file__).resolve().parents[2]
STATIC_PAGE = REPO_ROOT / "oauth-callback" / "index.html"

def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def oauth_settings(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_OAUTH_CLIENT_ID", "test-client-id")
    monkeypatch.setenv(
        "CLOUDFLARE_OAUTH_SCOPE", "offline_access workers-platform.read"
    )
    config.get_settings.cache_clear()
    yield config.get_settings()
    config.get_settings.cache_clear()


@pytest.fixture
def secret_store(tmp_path):
    return ConnectionSecretStore(tmp_path / "secrets.db", tmp_path / "secrets.key")


class FakeCloudflareOAuthServer:
    """MockTransport handler emulating Cloudflare's token/revoke endpoints."""

    def __init__(self, token_responses: list[httpx.Response] | None = None) -> None:
        self.token_responses = list(token_responses or [])
        self.token_requests: list[httpx.Request] = []
        self.revoke_requests: list[httpx.Request] = []

    def token_form(self, index: int) -> dict[str, str]:
        body = self.token_requests[index].content.decode("utf-8")
        return {k: v[0] for k, v in parse_qs(body).items()}

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            self.token_requests.append(request)
            if not self.token_responses:
                raise AssertionError("unexpected token endpoint call")
            return self.token_responses.pop(0)
        if request.url.path == "/oauth2/revoke":
            self.revoke_requests.append(request)
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={"error": "not_found"})


def make_manager(settings, store, server: FakeCloudflareOAuthServer | None = None):
    return CloudflareOAuthManager(
        settings=settings,
        secret_store=store,
        transport=server.transport if server else None,
    )


def token_response(**overrides) -> httpx.Response:
    payload = {
        "access_token": ACCESS_TOKEN,
        "refresh_token": REFRESH_TOKEN,
        "expires_in": 3600,
        "scope": "offline_access workers-platform.read",
        "token_type": "bearer",
        "account_id": "acct-123",
    }
    payload.update(overrides)
    return httpx.Response(200, json=payload)


def begin_and_extract(manager, store, mode="loopback"):
    flow = manager.begin_flow(mode)
    flow_payload = store.get(f"{FLOW_PREFIX}{flow.flow_id}")
    query = parse_qs(urlsplit(flow.authorize_url).query)
    return flow, flow_payload, query


def test_begin_flow_builds_valid_authorize_url(oauth_settings, secret_store):
    manager = make_manager(oauth_settings, secret_store)
    flow, flow_payload, query = begin_and_extract(manager, secret_store)

    split = urlsplit(flow.authorize_url)
    assert split.scheme == "https"
    assert split.netloc == "dash.cloudflare.com"
    assert split.path == "/oauth2/auth"
    assert query["client_id"] == ["test-client-id"]
    assert query["redirect_uri"] == [
        "http://127.0.0.1:22121/api/cloudflare/oauth/callback"
    ]
    assert query["response_type"] == ["code"]
    assert query["response_mode"] == ["query"]
    assert query["scope"] == ["offline_access workers-platform.read"]
    assert query["state"] == [flow_payload["state"]]
    assert query["code_challenge_method"] == ["S256"]
    expected_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(flow_payload["verifier"].encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert query["code_challenge"] == [expected_challenge]
    assert flow.expires_at == pytest.approx(flow_payload["created_at"] + 600, abs=2)
    # The URL must not embed the verifier itself.
    assert flow_payload["verifier"] not in flow.authorize_url


def test_begin_flow_page_mode_uses_fragment_response_mode(
    oauth_settings, secret_store
):
    manager = make_manager(oauth_settings, secret_store)
    flow, flow_payload, query = begin_and_extract(manager, secret_store, mode="page")

    assert query["response_mode"] == ["fragment"]
    assert query["redirect_uri"] == ["https://placeholder.invalid/oauth/callback"]
    assert flow_payload["redirect_mode"] == "page"


def test_complete_flow_exchanges_with_verifier_and_stores_grant_encrypted(
    oauth_settings, secret_store
):
    server = FakeCloudflareOAuthServer([token_response()])
    manager = make_manager(oauth_settings, secret_store, server)
    flow, flow_payload, _query = begin_and_extract(manager, secret_store)

    grant = run(
        manager.complete_flow(state=flow_payload["state"], code=CODE)
    )

    form = server.token_form(0)
    assert form["grant_type"] == "authorization_code"
    assert form["client_id"] == "test-client-id"
    assert form["code"] == CODE
    assert form["code_verifier"] == flow_payload["verifier"]
    assert form["redirect_uri"] == flow_payload["redirect_uri"]
    assert "client_secret" not in form

    assert grant["grant_id"]
    assert grant["scopes"] == "offline_access workers-platform.read"
    assert grant["account_label"] == "acct-123"
    assert grant["has_refresh_token"] is True
    assert "access_token" not in grant
    assert "refresh_token" not in grant

    owner = f"{GRANT_PREFIX}{grant['grant_id']}"
    stored = secret_store.get(owner)
    assert stored["access_token"] == ACCESS_TOKEN
    assert stored["refresh_token"] == REFRESH_TOKEN

    # At rest, the ciphertext must differ from the plaintext tokens.
    with sqlite3.connect(secret_store.database_path) as connection:
        row = connection.execute(
            "SELECT ciphertext FROM connection_secrets WHERE owner_id = ?",
            (owner,),
        ).fetchone()
    ciphertext = bytes(row[0])
    assert ACCESS_TOKEN.encode() not in ciphertext
    assert REFRESH_TOKEN.encode() not in ciphertext
    # The flow secret was consumed.
    assert secret_store.get(f"{FLOW_PREFIX}{flow.flow_id}") is None


def test_state_is_single_use(oauth_settings, secret_store):
    server = FakeCloudflareOAuthServer([token_response()])
    manager = make_manager(oauth_settings, secret_store, server)
    _flow, flow_payload, _query = begin_and_extract(manager, secret_store)

    run(manager.complete_flow(state=flow_payload["state"], code=CODE))
    with pytest.raises(CloudflareOAuthStateError):
        run(manager.complete_flow(state=flow_payload["state"], code=CODE))
    assert len(server.token_requests) == 1


def test_expired_state_is_rejected_and_purged(oauth_settings, secret_store):
    server = FakeCloudflareOAuthServer([token_response()])
    manager = make_manager(oauth_settings, secret_store, server)
    flow, flow_payload, _query = begin_and_extract(manager, secret_store)

    owner = f"{FLOW_PREFIX}{flow.flow_id}"
    expired = dict(flow_payload)
    expired["created_at"] = time.time() - 10_000
    secret_store.set(owner, expired)

    with pytest.raises(CloudflareOAuthStateError):
        run(manager.complete_flow(state=flow_payload["state"], code=CODE))
    assert not server.token_requests
    # Expired flows are deleted on read...
    assert secret_store.get(owner) is None

    # ...and the startup sweep removes any that remain.
    stale = manager.begin_flow("loopback")
    stale_owner = f"{FLOW_PREFIX}{stale.flow_id}"
    stale_payload = dict(secret_store.get(stale_owner))
    stale_payload["created_at"] = time.time() - 10_000
    secret_store.set(stale_owner, stale_payload)
    fresh = manager.begin_flow("loopback")
    purged = manager.purge_expired_flows()
    assert purged == 1
    assert secret_store.get(stale_owner) is None
    assert secret_store.get(f"{FLOW_PREFIX}{fresh.flow_id}") is not None


def _complete_grant(manager, secret_store, **overrides):
    flow, flow_payload, _query = begin_and_extract(manager, secret_store)
    grant = run(manager.complete_flow(state=flow_payload["state"], code=CODE))
    return grant


def test_access_token_cache_and_forced_refresh(oauth_settings, secret_store):
    server = FakeCloudflareOAuthServer(
        [
            token_response(),
            token_response(
                access_token=NEW_ACCESS_TOKEN,
                refresh_token=ROTATED_REFRESH_TOKEN,
            ),
        ]
    )
    manager = make_manager(oauth_settings, secret_store, server)
    grant = _complete_grant(manager, secret_store)

    # Fresh cached token: no new token-endpoint call.
    assert run(manager.get_access_token(grant["grant_id"])) == ACCESS_TOKEN
    assert len(server.token_requests) == 1

    # Force expiry: refresh path kicks in and rotated tokens persist verbatim.
    owner = f"{GRANT_PREFIX}{grant['grant_id']}"
    stored = dict(secret_store.get(owner))
    stored["access_token_expires_at"] = time.time() - 5
    secret_store.set(owner, stored)

    assert run(manager.get_access_token(grant["grant_id"])) == NEW_ACCESS_TOKEN
    form = server.token_form(1)
    assert form["grant_type"] == "refresh_token"
    assert form["refresh_token"] == REFRESH_TOKEN
    assert "client_secret" not in form

    updated = secret_store.get(owner)
    assert updated["access_token"] == NEW_ACCESS_TOKEN
    assert updated["refresh_token"] == ROTATED_REFRESH_TOKEN


def test_invalid_grant_deletes_grant_and_requires_reauth(
    oauth_settings, secret_store
):
    server = FakeCloudflareOAuthServer(
        [
            token_response(),
            httpx.Response(
                400,
                json={
                    "error": "invalid_grant",
                    "error_description": "The refresh token is no longer valid",
                },
            ),
        ]
    )
    manager = make_manager(oauth_settings, secret_store, server)
    grant = _complete_grant(manager, secret_store)

    owner = f"{GRANT_PREFIX}{grant['grant_id']}"
    stored = dict(secret_store.get(owner))
    stored["access_token_expires_at"] = time.time() - 5
    secret_store.set(owner, stored)

    with pytest.raises(CloudflareOAuthReauthRequiredError):
        run(manager.get_access_token(grant["grant_id"]))
    assert secret_store.get(owner) is None


def test_revoke_deletes_grant(oauth_settings, secret_store):
    server = FakeCloudflareOAuthServer([token_response()])
    manager = make_manager(oauth_settings, secret_store, server)
    grant = _complete_grant(manager, secret_store)

    assert run(manager.revoke(grant["grant_id"])) is True
    assert len(server.revoke_requests) == 1
    assert secret_store.get(f"{GRANT_PREFIX}{grant['grant_id']}") is None
    assert manager.list_grants() == []
    # Unknown grant: False, no error.
    assert run(manager.revoke("does-not-exist")) is False


# ----------------------------------------------------------------------
# Router-level tests (router is mounted by integration later; mount locally)
# ----------------------------------------------------------------------
def build_app(manager) -> FastAPI:
    app = FastAPI()
    app.include_router(oauth_router.router)
    app.dependency_overrides[oauth_router.get_cloudflare_oauth_manager_dep] = (
        lambda: manager
    )
    return app


def api_request(app, method: str, url: str, **kwargs) -> httpx.Response:
    async def _do() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            return await client.request(method, url, **kwargs)

    return run(_do())


def assert_no_store(response: httpx.Response) -> None:
    assert response.headers["Cache-Control"] == "no-store, private"
    assert response.headers["Pragma"] == "no-cache"


def test_loopback_callback_redirects_303(oauth_settings, secret_store):
    server = FakeCloudflareOAuthServer([token_response()])
    manager = make_manager(oauth_settings, secret_store, server)
    app = build_app(manager)

    begin = api_request(app, "POST", "/api/cloudflare/oauth/begin", json={})
    assert begin.status_code == 200
    state = parse_qs(urlsplit(begin.json()["authorize_url"]).query)["state"][0]

    response = api_request(
        app,
        "GET",
        f"/api/cloudflare/oauth/callback?code={CODE}&state={state}",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["Location"] == "/connections?cloudflare=connected"
    assert_no_store(response)
    assert manager.list_grants() != []

    # Replayed callback must not succeed twice.
    replay = api_request(
        app,
        "GET",
        f"/api/cloudflare/oauth/callback?code={CODE}&state={state}",
        follow_redirects=False,
    )
    assert replay.status_code == 303
    assert replay.headers["Location"] == "/connections?cloudflare=error"


def test_paste_back_complete_endpoint(oauth_settings, secret_store):
    server = FakeCloudflareOAuthServer([token_response()])
    manager = make_manager(oauth_settings, secret_store, server)
    app = build_app(manager)

    begin = api_request(
        app,
        "POST",
        "/api/cloudflare/oauth/begin",
        json={"redirect_mode": "page"},
    )
    assert begin.status_code == 200
    state = parse_qs(urlsplit(begin.json()["authorize_url"]).query)["state"][0]

    response = api_request(
        app,
        "POST",
        "/api/cloudflare/oauth/complete",
        json={"code": CODE, "state": state},
    )
    assert response.status_code == 200
    assert_no_store(response)
    payload = response.json()
    assert payload["grant_id"]
    assert payload["account_label"] == "acct-123"
    # Tokens must never appear in any API response.
    assert ACCESS_TOKEN not in response.text
    assert REFRESH_TOKEN not in response.text
    assert CODE not in response.text

    bad = api_request(
        app,
        "POST",
        "/api/cloudflare/oauth/complete",
        json={"code": CODE, "state": "never-issued"},
    )
    assert bad.status_code == 400
    assert bad.json()["detail"] == "invalid or expired authorization state"


def test_grant_listing_and_delete_endpoints(oauth_settings, secret_store):
    server = FakeCloudflareOAuthServer([token_response()])
    manager = make_manager(oauth_settings, secret_store, server)
    app = build_app(manager)
    grant = _complete_grant(manager, secret_store)

    listing = api_request(app, "GET", "/api/cloudflare/oauth/grants")
    assert listing.status_code == 200
    assert_no_store(listing)
    grants = listing.json()["grants"]
    assert len(grants) == 1
    assert grants[0]["grant_id"] == grant["grant_id"]
    assert ACCESS_TOKEN not in listing.text
    assert REFRESH_TOKEN not in listing.text

    deleted = api_request(
        app, "DELETE", f"/api/cloudflare/oauth/grants/{grant['grant_id']}"
    )
    assert deleted.status_code == 204
    assert_no_store(deleted)
    assert manager.list_grants() == []
    assert len(server.revoke_requests) == 1

    missing = api_request(
        app, "DELETE", f"/api/cloudflare/oauth/grants/{grant['grant_id']}"
    )
    assert missing.status_code == 404


def test_no_store_headers_on_every_endpoint(oauth_settings, secret_store):
    server = FakeCloudflareOAuthServer([token_response()])
    manager = make_manager(oauth_settings, secret_store, server)
    app = build_app(manager)

    begin = api_request(
        app, "POST", "/api/cloudflare/oauth/begin", json={"redirect_mode": "loopback"}
    )
    assert_no_store(begin)
    state = parse_qs(urlsplit(begin.json()["authorize_url"]).query)["state"][0]

    callback = api_request(
        app,
        "GET",
        f"/api/cloudflare/oauth/callback?code={CODE}&state={state}",
        follow_redirects=False,
    )
    assert_no_store(callback)

    grants = api_request(app, "GET", "/api/cloudflare/oauth/grants")
    assert_no_store(grants)
    grant_id = grants.json()["grants"][0]["grant_id"]
    delete = api_request(app, "DELETE", f"/api/cloudflare/oauth/grants/{grant_id}")
    assert_no_store(delete)

    # Paste-back endpoint (new flow so the state is valid again).
    server.token_responses.append(token_response())
    begin2 = api_request(app, "POST", "/api/cloudflare/oauth/begin", json={})
    state2 = parse_qs(urlsplit(begin2.json()["authorize_url"]).query)["state"][0]
    complete = api_request(
        app,
        "POST",
        "/api/cloudflare/oauth/complete",
        json={"code": CODE, "state": state2},
    )
    assert complete.status_code == 200
    assert_no_store(complete)


def test_logs_never_contain_codes_verifiers_or_tokens(
    oauth_settings, secret_store, caplog
):
    server = FakeCloudflareOAuthServer(
        [
            token_response(),
            token_response(
                access_token=NEW_ACCESS_TOKEN,
                refresh_token=ROTATED_REFRESH_TOKEN,
            ),
        ]
    )
    manager = make_manager(oauth_settings, secret_store, server)

    with caplog.at_level(logging.DEBUG):
        flow, flow_payload, _query = begin_and_extract(manager, secret_store)
        grant = run(manager.complete_flow(state=flow_payload["state"], code=CODE))
        owner = f"{GRANT_PREFIX}{grant['grant_id']}"
        stored = dict(secret_store.get(owner))
        stored["access_token_expires_at"] = time.time() - 5
        secret_store.set(owner, stored)
        run(manager.get_access_token(grant["grant_id"]))
        run(manager.revoke(grant["grant_id"]))

    secrets_to_hide = [
        CODE,
        flow_payload["verifier"],
        ACCESS_TOKEN,
        REFRESH_TOKEN,
        ROTATED_REFRESH_TOKEN,
        NEW_ACCESS_TOKEN,
    ]
    for record in caplog.records:
        message = record.getMessage()
        for value in secrets_to_hide:
            assert value not in message


def test_static_callback_page_has_no_external_resources():
    html = STATIC_PAGE.read_text(encoding="utf-8")

    # This page is a display-only fragment receiver. It must not contain any
    # absolute destination or make any network request, including loopback.
    urls = re.findall(r"https?://[^\s\"'<>\])}]+", html)
    assert urls == []
    assert "fetch(" not in html
    assert "XMLHttpRequest" not in html
    assert "sendBeacon" not in html

    # No externally-loaded resources of any kind.
    assert "<img" not in html
    assert "<link" not in html
    assert "<iframe" not in html
    assert "<form" not in html
    assert not re.search(r"\bsrc\s*=", html)
    assert "@import" not in html
    assert "url(" not in html

    # Privacy posture is explicit and enforced.
    assert "no-referrer" in html
    assert "Content-Security-Policy" in html
    assert "default-src 'none'" in html
    assert "connect-src 'none'" in html
    assert "'unsafe-inline'" not in html
    for tag in ("style", "script"):
        body = re.search(rf"<{tag}>(.*?)</{tag}>", html, re.DOTALL)
        assert body is not None
        digest = base64.b64encode(hashlib.sha256(body.group(1).encode()).digest()).decode()
        assert f"sha256-{digest}" in html
    assert "form-action 'none'" in html
    assert "base-uri 'none'" in html
    # Fragment-first reading with query fallback.
    assert "location.hash" in html
    assert "location.search" in html
