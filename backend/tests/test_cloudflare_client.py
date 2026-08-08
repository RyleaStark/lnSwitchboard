from __future__ import annotations

import json
import logging
import re
from email.parser import BytesParser
from typing import Any

import httpx
import pytest

from backend.app.cloudflare_client import (
    CloudflareAPIError,
    CloudflareClient,
    CloudflareWorkersRouteProvisionError,
)
from backend.app.cloudflare_worker_source import (
    INTERNAL_HOSTNAME,
    LNS_WORKER_VERSION,
    MANAGED_COMMENT,
    MESH_BINDING_NAME,
    MESH_NETWORK_ID,
    PUBLIC_PORT,
    WORKER_COMPATIBILITY_DATE,
    WORKER_SOURCE,
    extract_worker_version,
)
from backend.app.logging_utils import configure_logging

API_TOKEN = "do-not-leak-this-api-token"
ACCOUNT_ID = "a" * 32
ZONE_ID = "b" * 32
NODE_ID = "11111111-2222-4333-8444-555555555555"
SCRIPT = "lnswitchboard-proxy"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _envelope(result: Any) -> httpx.Response:
    return httpx.Response(
        200, json={"success": True, "errors": [], "result": result}
    )


@pytest.mark.anyio
async def test_mesh_node_lifecycle_uses_warp_connector_endpoints() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if path.endswith("/warp_connector") and request.method == "POST":
            return _envelope({"id": NODE_ID, "name": "lnswitchboard-example-com-deadbeef"})
        if path.endswith("/token"):
            return _envelope({"token": "mesh-node-token"})
        if path.endswith("/connections"):
            return _envelope([{"id": "conn-1"}])
        if request.method == "DELETE":
            return _envelope({"id": NODE_ID})
        raise AssertionError(request.url)

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    node = await client.create_mesh_node(ACCOUNT_ID, "lnswitchboard-example-com-deadbeef")
    assert node["id"] == NODE_ID
    assert await client.get_mesh_node_token(ACCOUNT_ID, NODE_ID) == "mesh-node-token"
    assert await client.list_mesh_node_connections(ACCOUNT_ID, NODE_ID) == [
        {"id": "conn-1"}
    ]
    await client.delete_mesh_node(ACCOUNT_ID, NODE_ID)

    assert all(
        request.headers["authorization"] == f"Bearer {API_TOKEN}"
        for request in requests
    )
    create_request = requests[0]
    assert json.loads(create_request.content) == {
        "name": "lnswitchboard-example-com-deadbeef"
    }
    assert requests[1].url.path.endswith(
        f"/accounts/{ACCOUNT_ID}/warp_connector/{NODE_ID}/token"
    )
    assert requests[2].url.path.endswith(
        f"/accounts/{ACCOUNT_ID}/warp_connector/{NODE_ID}/connections"
    )
    assert requests[3].method == "DELETE"
    assert requests[3].url.path.endswith(
        f"/accounts/{ACCOUNT_ID}/warp_connector/{NODE_ID}"
    )


@pytest.mark.anyio
async def test_find_mesh_node_by_name_matches_exact_name() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["name"] == "wanted"
        return _envelope([{"id": "other", "name": "wanted-2"}, {"id": "hit", "name": "wanted"}])

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    found = await client.find_mesh_node_by_name(ACCOUNT_ID, "wanted")
    assert found == {"id": "hit", "name": "wanted"}


@pytest.mark.anyio
async def test_hostname_route_lifecycle_uses_zerotrust_routes_hostname() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if path.endswith("/zerotrust/routes/hostname") and request.method == "POST":
            return _envelope({"id": "route-1"})
        if path.endswith("/zerotrust/routes/hostname"):
            return _envelope([{"id": "route-1", "hostname": INTERNAL_HOSTNAME}])
        if path.endswith("/zerotrust/routes/hostname/route-1"):
            if request.method == "DELETE":
                return _envelope({"id": "route-1"})
            return _envelope({"id": "route-1", "hostname": INTERNAL_HOSTNAME})
        raise AssertionError(request.url)

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    created = await client.create_hostname_route(ACCOUNT_ID, NODE_ID)
    assert created["id"] == "route-1"
    routes = await client.list_hostname_routes(ACCOUNT_ID, INTERNAL_HOSTNAME)
    assert routes == [{"id": "route-1", "hostname": INTERNAL_HOSTNAME}]
    assert await client.get_hostname_route(ACCOUNT_ID, "route-1") == {
        "id": "route-1",
        "hostname": INTERNAL_HOSTNAME,
    }
    await client.delete_hostname_route(ACCOUNT_ID, "route-1")

    create_body = json.loads(requests[0].content)
    assert create_body == {
        "hostname": INTERNAL_HOSTNAME,
        "tunnel_id": NODE_ID,
        "comment": MANAGED_COMMENT,
    }
    assert requests[1].url.params["hostname"] == INTERNAL_HOSTNAME


def _parse_multipart(request: httpx.Request) -> dict[str, tuple[str | None, bytes]]:
    content_type = request.headers["content-type"]
    message = BytesParser().parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + request.content
    )
    parts: dict[str, tuple[str | None, bytes]] = {}
    for part in message.get_payload():
        name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        parts[str(name)] = (filename, part.get_payload(decode=True))
    return parts


@pytest.mark.anyio
async def test_deploy_proxy_worker_uploads_module_with_vpc_binding() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _envelope({"id": SCRIPT})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.deploy_proxy_worker(ACCOUNT_ID, SCRIPT, "mesh-ingress-secret")

    [request] = requests
    assert request.method == "PUT"
    assert request.url.path.endswith(f"/accounts/{ACCOUNT_ID}/workers/scripts/{SCRIPT}")
    assert request.headers["content-type"].startswith("multipart/form-data")
    parts = _parse_multipart(request)
    metadata = json.loads(parts["metadata"][1])
    assert metadata == {
        "main_module": "worker.js",
        "bindings": [
            {
                "name": MESH_BINDING_NAME,
                "type": "vpc_network",
                "network_id": MESH_NETWORK_ID,
            },
            {
                "name": "LNS_MESH_INGRESS_KEY",
                "type": "secret_text",
                "text": "mesh-ingress-secret",
            },
        ],
        "compatibility_date": WORKER_COMPATIBILITY_DATE,
    }
    filename, source = parts["worker.js"]
    assert filename == "worker.js"
    assert source.decode() == WORKER_SOURCE
    assert metadata["bindings"][0]["network_id"] == "cf1:network"


@pytest.mark.anyio
async def test_get_worker_script_content_returns_text_and_none_when_missing() -> None:
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        if "missing" in request.url.path:
            return httpx.Response(
                404,
                json={"success": False, "errors": [{"code": 10007}], "result": None},
            )
        return httpx.Response(200, text=WORKER_SOURCE)

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    content = await client.get_worker_script_content(ACCOUNT_ID, SCRIPT)
    assert content == WORKER_SOURCE
    assert extract_worker_version(content or "") == LNS_WORKER_VERSION
    assert await client.get_worker_script_content(ACCOUNT_ID, "missing") is None
    assert seen_paths[0].endswith(f"/workers/scripts/{SCRIPT}/content/v2")


@pytest.mark.anyio
async def test_worker_subdomain_and_preview_urls_are_explicitly_disabled() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _envelope({"enabled": False, "previews_enabled": False})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    configured = await client.configure_worker_subdomain(ACCOUNT_ID, SCRIPT)
    observed = await client.get_worker_subdomain(ACCOUNT_ID, SCRIPT)

    assert configured == {"enabled": False, "previews_enabled": False}
    assert observed == configured
    post_request, get_request = requests
    assert post_request.method == "POST"
    assert get_request.method == "GET"
    assert post_request.url.path.endswith(
        f"/accounts/{ACCOUNT_ID}/workers/scripts/{SCRIPT}/subdomain"
    )
    assert json.loads(post_request.content) == {
        "enabled": False,
        "previews_enabled": False,
    }


@pytest.mark.anyio
async def test_worker_content_error_surfaces_provider_message_verbatim() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "success": False,
                "errors": [{"code": 10000, "message": "Not allowed to edit workers"}],
                "result": None,
            },
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.get_worker_script_content(ACCOUNT_ID, SCRIPT)
    assert "Not allowed to edit workers" in str(captured.value)


@pytest.mark.anyio
async def test_ensure_workers_routes_creates_exactly_the_two_managed_patterns() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return _envelope([])
        return _envelope({"id": f"route-{len(requests)}"})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.ensure_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)

    posts = [request for request in requests if request.method == "POST"]
    assert [json.loads(request.content) for request in posts] == [
        {
            "pattern": "pay.example.com/.well-known/lnurlp/*",
            "script": SCRIPT,
        },
        {
            "pattern": "pay.example.com/.well-known/nostr.json",
            "script": SCRIPT,
        },
    ]
    assert all(
        request.url.path.endswith(f"/zones/{ZONE_ID}/workers/routes")
        for request in posts
    )


@pytest.mark.anyio
async def test_ensure_workers_routes_refuses_identical_pattern_on_foreign_script() -> None:
    posts: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            posts.append(request)
        return _envelope(
            [
                {
                    "id": "foreign-1",
                    "pattern": "pay.example.com/.well-known/nostr.json",
                    "script": "operator-script",
                }
            ]
            if request.method == "GET"
            else {"id": "unused"}
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.ensure_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)

    assert captured.value.status_code == 409
    # Preflight both exact patterns before the first mutation, so an existing
    # conflict cannot leave the other route partially provisioned.
    assert posts == []


@pytest.mark.anyio
async def test_ensure_workers_routes_reports_exact_partial_ownership() -> None:
    patterns = CloudflareClient.workers_route_patterns("pay.example.com")
    routes: list[dict[str, Any]] = []
    posts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal posts
        if request.method == "POST":
            posts += 1
            payload = json.loads(request.content)
            if posts == 1:
                route = {"id": "created-first", **payload}
                routes.append(route)
                return _envelope({"id": route["id"]})
            routes.append(
                {
                    "id": "foreign-second",
                    "pattern": payload["pattern"],
                    "script": "operator-worker",
                }
            )
            return httpx.Response(
                409,
                json={"success": False, "errors": [{"code": 10020}], "result": None},
            )
        return _envelope(list(routes))

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))

    with pytest.raises(CloudflareWorkersRouteProvisionError) as captured:
        await client.ensure_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)

    assert captured.value.status_code == 409
    assert captured.value.created_routes == (("created-first", patterns[0]),)


@pytest.mark.anyio
async def test_ensure_workers_routes_ignores_foreign_wildcard_routes() -> None:
    """Most-specific-wins: our exact path patterns beat operator host/* routes."""
    posts: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            posts.append(request)
            return _envelope({"id": f"route-{len(posts)}"})
        return _envelope(
            [
                {"id": "wild", "pattern": "pay.example.com/*", "script": "operator-script"},
                {"id": "other", "pattern": "other.example.com/.well-known/nostr.json", "script": "operator-script"},
            ]
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.ensure_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)

    assert len(posts) == 2


@pytest.mark.anyio
async def test_ensure_workers_routes_adopts_patterns_already_on_our_script() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            raise AssertionError("must not recreate adopted routes")
        return _envelope(
            [
                {
                    "id": f"route-{index}",
                    "pattern": pattern,
                    "script": SCRIPT,
                }
                for index, pattern in enumerate(
                    CloudflareClient.workers_route_patterns("pay.example.com")
                )
            ]
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.ensure_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)


@pytest.mark.anyio
async def test_ensure_workers_routes_reconciles_ambiguous_create() -> None:
    routes: list[dict[str, Any]] = []
    posts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal posts
        if request.method == "POST":
            posts += 1
            body = json.loads(request.content)
            routes.append({"id": f"route-{posts}", **body})
            # The create succeeded but the response is lost.
            return httpx.Response(
                500,
                json={"success": False, "errors": [{"code": 1}], "result": None},
            )
        return _envelope(list(routes))

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.ensure_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)

    assert posts == 2
    assert {route["pattern"] for route in routes} == set(
        CloudflareClient.workers_route_patterns("pay.example.com")
    )


@pytest.mark.anyio
async def test_verify_workers_routes_requires_exact_pattern_and_script() -> None:
    patterns = CloudflareClient.workers_route_patterns("pay.example.com")
    scenarios = [
        ([{"id": "1", "pattern": patterns[0], "script": SCRIPT}, {"id": "2", "pattern": patterns[1], "script": SCRIPT}], True),
        ([{"id": "1", "pattern": patterns[0], "script": SCRIPT}], False),
        ([{"id": "1", "pattern": patterns[0], "script": SCRIPT}, {"id": "2", "pattern": patterns[1], "script": "other"}], False),
        ([{"id": "1", "pattern": patterns[0], "script": SCRIPT}, {"id": "2", "pattern": patterns[1], "script": SCRIPT}, {"id": "3", "pattern": patterns[1], "script": SCRIPT}], False),
    ]
    responses = [
        _envelope(routes) for routes, _expected in scenarios
    ]

    def handler(_request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    for _routes, expected in scenarios:
        assert (
            await client.verify_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)
        ) is expected


@pytest.mark.anyio
async def test_remove_workers_routes_deletes_only_exact_pattern_and_our_script() -> None:
    patterns = CloudflareClient.workers_route_patterns("pay.example.com")
    routes = [
        {"id": "ours-1", "pattern": patterns[0], "script": SCRIPT},
        {"id": "ours-2", "pattern": patterns[1], "script": SCRIPT},
        {"id": "wild", "pattern": "pay.example.com/*", "script": "operator-script"},
        {"id": "other-host", "pattern": "other.example.com/.well-known/nostr.json", "script": SCRIPT},
    ]
    deleted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            deleted.append(request.url.path.rsplit("/", 1)[-1])
            return _envelope({"id": "deleted"})
        route_id = request.url.path.rsplit("/", 1)[-1]
        if route_id in {"ours-1", "ours-2"}:
            return _envelope(next(route for route in routes if route["id"] == route_id))
        return _envelope(routes)

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.remove_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)

    assert sorted(deleted) == ["ours-1", "ours-2"]


@pytest.mark.anyio
async def test_remove_workers_routes_preserves_foreign_identical_pattern() -> None:
    patterns = CloudflareClient.workers_route_patterns("pay.example.com")
    routes = [{"id": "foreign", "pattern": patterns[0], "script": "operator-script"}]
    deleted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            deleted.append(request.url.path)
            return _envelope({"id": "deleted"})
        return _envelope(routes)

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.remove_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)

    assert captured.value.status_code == 409
    assert deleted == []


@pytest.mark.anyio
async def test_remove_workers_route_revalidates_exact_id_before_delete() -> None:
    pattern = CloudflareClient.workers_route_patterns("pay.example.com")[0]
    deleted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            deleted.append(request.url.path)
            return _envelope({"id": "deleted"})
        if request.url.path.endswith("/workers/routes/route-1"):
            return _envelope(
                {"id": "route-1", "pattern": pattern, "script": "foreign-script"}
            )
        return _envelope([{"id": "route-1", "pattern": pattern, "script": SCRIPT}])

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))

    with pytest.raises(CloudflareAPIError) as captured:
        await client.remove_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)

    assert captured.value.status_code == 409
    assert deleted == []


@pytest.mark.anyio
async def test_remove_workers_routes_is_noop_without_managed_patterns() -> None:
    writes = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal writes
        if request.method != "GET":
            writes += 1
            return _envelope({"id": "unused"})
        return _envelope(
            [{"id": "wild", "pattern": "pay.example.com/*", "script": "operator-script"}]
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.remove_workers_routes(ZONE_ID, "pay.example.com", SCRIPT)
    assert writes == 0


@pytest.mark.anyio
async def test_create_placeholder_dns_record_is_originless_proxied_aaaa() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _envelope({"id": "dns-1"})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    created = await client.create_placeholder_dns_record(ZONE_ID, "pay.example.com")
    assert created["id"] == "dns-1"
    [request] = requests
    assert json.loads(request.content) == {
        "type": "AAAA",
        "name": "pay.example.com",
        "content": "100::",
        "proxied": True,
        "comment": MANAGED_COMMENT,
    }


@pytest.mark.anyio
async def test_client_error_surfaces_provider_message_verbatim_without_token() -> None:
    provider_message = "Actor requires permission com.cloudflare.api.account.workers"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "success": False,
                "errors": [{"code": 10000, "message": provider_message}],
                "result": None,
            },
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.verify_token()

    rendered = str(captured.value)
    assert provider_message in rendered
    assert "10000" in rendered
    assert API_TOKEN not in rendered


@pytest.mark.anyio
async def test_httpx_request_logging_never_records_cloudflare_resource_ids(
    tmp_path, caplog
) -> None:
    account_sentinel = "account-resource-must-not-be-logged"
    node_sentinel = "node-resource-must-not-be-logged"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "success": True,
                "errors": [],
                "messages": [],
                "result": {"id": node_sentinel, "name": "managed-node"},
            },
        )

    configure_logging(tmp_path)
    caplog.set_level(logging.INFO)
    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))

    await client.get_mesh_node(account_sentinel, node_sentinel)

    assert account_sentinel not in caplog.text
    assert node_sentinel not in caplog.text


@pytest.mark.anyio
async def test_transport_failure_is_sanitized_fixed_message() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"secret connection detail {API_TOKEN}")

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.verify_token()

    rendered = str(captured.value)
    assert rendered == "Cloudflare rejected the request with HTTP 503"
    assert API_TOKEN not in rendered
    assert "secret connection detail" not in rendered


@pytest.mark.anyio
async def test_delete_operations_are_idempotent_when_resource_is_already_gone() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={"success": False, "errors": [{"code": 81044}], "result": None},
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.delete_dns_record(ZONE_ID, "record-id")
    await client.delete_mesh_node(ACCOUNT_ID, NODE_ID)
    await client.delete_hostname_route(ACCOUNT_ID, "route-id")
    await client.delete_worker_script(ACCOUNT_ID, SCRIPT)


@pytest.mark.anyio
async def test_access_apps_list_paginates_and_create_posts_warp_app() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            return _envelope({"id": "app-1"})
        return _envelope(
            [
                {
                    "id": "app-warp",
                    "type": "warp",
                    "policies": [{"decision": "allow"}],
                }
            ]
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    apps = await client.list_access_apps(ACCOUNT_ID)
    assert apps == [
        {"id": "app-warp", "type": "warp", "policies": [{"decision": "allow"}]}
    ]
    created = await client.create_access_app(
        ACCOUNT_ID,
        {
            "name": "Warp device enrollment",
            "type": "warp",
            "app_launcher_visible": False,
            "policies": [
                {
                    "name": "Allow device enrollment",
                    "decision": "allow",
                    "include": [{"everyone": {}}],
                    "precedence": 1,
                }
            ],
        },
    )
    assert created["id"] == "app-1"

    list_request, create_request = requests
    assert list_request.method == "GET"
    assert list_request.url.path.endswith(f"/accounts/{ACCOUNT_ID}/access/apps")
    assert list_request.url.params["per_page"] == "50"
    assert create_request.method == "POST"
    assert json.loads(create_request.content)["type"] == "warp"
    assert json.loads(create_request.content)["policies"][0]["decision"] == "allow"


@pytest.mark.anyio
async def test_device_policy_get_list_and_flat_patch() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/devices/policies"):
            return _envelope([{"policy_id": "p1", "default": True}])
        return _envelope({"default": True, "include": [], "exclude": []})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    policies = await client.list_device_policies(ACCOUNT_ID)
    assert policies == [{"policy_id": "p1", "default": True}]
    policy = await client.get_default_device_policy(ACCOUNT_ID)
    assert policy["default"] is True
    patched = await client.patch_default_device_policy(
        ACCOUNT_ID,
        {"include": [{"address": "100.96.0.0/12", "description": "mesh"}]},
    )
    assert isinstance(patched, dict)

    list_request, get_request, patch_request = requests
    assert list_request.url.path.endswith(f"/accounts/{ACCOUNT_ID}/devices/policies")
    assert get_request.method == "GET"
    assert get_request.url.path.endswith(f"/accounts/{ACCOUNT_ID}/devices/policy")
    assert patch_request.method == "PATCH"
    assert patch_request.url.path.endswith(f"/accounts/{ACCOUNT_ID}/devices/policy")
    # The PATCH body is flat (no "device_settings"-style wrapper).
    assert json.loads(patch_request.content) == {
        "include": [{"address": "100.96.0.0/12", "description": "mesh"}]
    }


@pytest.mark.anyio
async def test_device_settings_get_and_flat_patch() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _envelope({"gateway_proxy_enabled": True})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    settings = await client.get_device_settings(ACCOUNT_ID)
    assert settings == {"gateway_proxy_enabled": True}
    await client.patch_device_settings(
        ACCOUNT_ID, {"gateway_udp_proxy_enabled": True}
    )

    get_request, patch_request = requests
    assert get_request.url.path.endswith(f"/accounts/{ACCOUNT_ID}/devices/settings")
    assert patch_request.method == "PATCH"
    assert json.loads(patch_request.content) == {"gateway_udp_proxy_enabled": True}


@pytest.mark.anyio
async def test_connectivity_settings_get_and_flat_patch() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _envelope({"icmp_proxy_enabled": True, "offramp_warp_enabled": True})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    settings = await client.get_connectivity_settings(ACCOUNT_ID)
    assert settings["offramp_warp_enabled"] is True
    await client.patch_connectivity_settings(ACCOUNT_ID, {"offramp_warp_enabled": True})

    get_request, patch_request = requests
    assert get_request.url.path.endswith(
        f"/accounts/{ACCOUNT_ID}/zerotrust/connectivity_settings"
    )
    assert patch_request.method == "PATCH"
    assert patch_request.url.path.endswith(
        f"/accounts/{ACCOUNT_ID}/zerotrust/connectivity_settings"
    )
    assert json.loads(patch_request.content) == {"offramp_warp_enabled": True}


@pytest.mark.anyio
async def test_prereq_malformed_results_raise_sanitized_502() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return _envelope(None)

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    for operation in (
        client.get_default_device_policy(ACCOUNT_ID),
        client.get_device_settings(ACCOUNT_ID),
        client.get_connectivity_settings(ACCOUNT_ID),
        client.patch_device_settings(ACCOUNT_ID, {"gateway_proxy_enabled": True}),
        client.patch_default_device_policy(ACCOUNT_ID, {"include": []}),
        client.patch_connectivity_settings(ACCOUNT_ID, {"icmp_proxy_enabled": True}),
        client.create_access_app(ACCOUNT_ID, {"type": "warp"}),
    ):
        with pytest.raises(CloudflareAPIError) as captured:
            await operation
        assert str(captured.value) == "Cloudflare rejected the request with HTTP 502"
        assert API_TOKEN not in str(captured.value)

    def list_handler(_request: httpx.Request) -> httpx.Response:
        return _envelope({"unexpected": "object"})

    list_client = CloudflareClient(
        API_TOKEN, transport=httpx.MockTransport(list_handler)
    )
    with pytest.raises(CloudflareAPIError) as captured:
        await list_client.list_device_policies(ACCOUNT_ID)
    assert captured.value.status_code == 502


@pytest.mark.anyio
async def test_prereq_endpoints_surface_provider_errors_verbatim() -> None:
    provider_message = "Actor requires permission com.cloudflare.api.account.zero_trust"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "success": False,
                "errors": [{"code": 10000, "message": provider_message}],
                "result": None,
            },
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.get_device_settings(ACCOUNT_ID)
    assert provider_message in str(captured.value)
    assert API_TOKEN not in str(captured.value)


@pytest.mark.anyio
async def test_account_discovery_paginates_until_short_page() -> None:
    pages: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        pages.append(page)
        result = (
            [{"id": str(index)} for index in range(50)]
            if page == 1
            else [{"id": "last"}]
        )
        return _envelope(result)

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    accounts = await client.list_accounts()

    assert len(accounts) == 51
    assert pages == [1, 2]


def test_worker_source_privacy_and_version_marker() -> None:
    # Privacy (hard owner requirement): no logging, no telemetry, no external
    # requests beyond the mesh binding to the internal target.
    assert "console" not in WORKER_SOURCE
    assert "https://" not in WORKER_SOURCE
    assert f"http://{INTERNAL_HOSTNAME}:{PUBLIC_PORT}" in WORKER_SOURCE
    assert "env.MESH.fetch" in WORKER_SOURCE
    fetch_lines = [
        line.strip() for line in WORKER_SOURCE.splitlines() if ".fetch(" in line
    ]
    assert all("env.MESH.fetch" in line for line in fetch_lines)
    assert "X-LNS-Public-Host" in WORKER_SOURCE
    assert 'forwarded.headers.delete("X-LNS-Mesh-Key")' in WORKER_SOURCE
    assert (
        'forwarded.headers.set("X-LNS-Mesh-Key", env.LNS_MESH_INGRESS_KEY)'
        in WORKER_SOURCE
    )
    assert "stripHopByHop(forwarded.headers)" in WORKER_SOURCE
    assert "stripHopByHop(responseHeaders)" in WORKER_SOURCE
    assert "new Response(upstream.body" in WORKER_SOURCE
    assert 'url.pathname.startsWith("/.well-known/lnurlp/")' in WORKER_SOURCE
    assert 'url.pathname === "/.well-known/nostr.json"' in WORKER_SOURCE
    assert 'publicHostname.endsWith(".workers.dev")' in WORKER_SOURCE
    assert "if (isWorkersDev || !(" in WORKER_SOURCE
    assert 'new Response("Not found"' in WORKER_SOURCE
    assert extract_worker_version(WORKER_SOURCE) == LNS_WORKER_VERSION
    # Failure mapping is a fixed sanitized 503 with no exception interpolation.
    assert re.search(r'catch \{', WORKER_SOURCE)
    assert "lnSwitchboard origin unavailable" in WORKER_SOURCE
