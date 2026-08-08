from __future__ import annotations

import json

import httpx
import pytest
from typing import Any

from backend.app.cloudflare_client import (
    CloudflareAPIError,
    CloudflareClient,
    CloudflareRollbackError,
)

API_TOKEN = "do-not-leak-this-api-token"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_client_builds_remote_tunnel_dns_and_public_only_ingress() -> None:
    requests: list[httpx.Request] = []
    tunnel_config = {"config": {"ingress": []}}

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/cfd_tunnel"):
            result = {"id": "tunnel-id", "name": "tunnel"}
        elif request.url.path.endswith("/configurations") and request.method == "GET":
            result = tunnel_config
        elif request.url.path.endswith("/configurations") and request.method == "PUT":
            tunnel_config.update(json.loads(request.content))
            result = tunnel_config
        elif request.url.path.endswith("/dns_records"):
            result = {"id": "dns-id"}
        else:
            raise AssertionError(request.url)
        return httpx.Response(
            200, json={"success": True, "errors": [], "result": result}
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.create_tunnel("account-id", "tunnel")
    await client.configure_tunnel(
        "account-id",
        "tunnel-id",
        "pay.example.com",
        "http://app:21212",
    )
    await client.create_dns_record("zone-id", "pay.example.com", "tunnel-id")

    assert all(
        request.headers["authorization"] == f"Bearer {API_TOKEN}"
        for request in requests
    )
    tunnel_body = json.loads(requests[0].content)
    assert tunnel_body == {"name": "tunnel", "config_src": "cloudflare"}
    config_request = next(
        request
        for request in requests
        if request.method == "PUT" and request.url.path.endswith("/configurations")
    )
    config_body = json.loads(config_request.content)
    assert config_body == {
        "config": {
            "ingress": [
                {"hostname": "pay.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                {"hostname": "pay.example.com", "path": r"^/\.well-known/nostr\.json$", "service": "http://app:21212"},
                {"service": "http_status:404"},
            ]
        }
    }
    assert "22121" not in config_request.content.decode()
    dns_request = next(
        request
        for request in requests
        if request.method == "POST" and request.url.path.endswith("/dns_records")
    )
    dns_body = json.loads(dns_request.content)
    assert dns_body["content"] == "tunnel-id.cfargotunnel.com"
    assert dns_body["proxied"] is True


@pytest.mark.anyio
async def test_configure_tunnel_initializes_cloudflare_null_config() -> None:
    """A new remotely managed tunnel has result.config=null until its first PUT."""
    tunnel_config: dict[str, Any] = {"config": None}
    writes: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            body = json.loads(request.content)
            writes.append(body)
            tunnel_config.update(body)
        return httpx.Response(
            200,
            json={"success": True, "errors": [], "result": tunnel_config},
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))

    await client.configure_tunnel(
        "account-id",
        "tunnel-id",
        "example.com",
        "http://app:21212",
    )

    assert writes == [
        {
            "config": {
                "ingress": [
                    {
                        "hostname": "example.com",
                        "path": r"^/\.well-known/lnurlp/.*$",
                        "service": "http://app:21212",
                    },
                    {
                        "hostname": "example.com",
                        "path": r"^/\.well-known/nostr\.json$",
                        "service": "http://app:21212",
                    },
                    {"service": "http_status:404"},
                ]
            }
        }
    ]


@pytest.mark.anyio
async def test_configure_tunnel_rejects_duplicate_managed_routes() -> None:
    tunnel_config = {"config": {"ingress": []}}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            tunnel_config.update(json.loads(request.content))
            duplicate = dict(tunnel_config["config"]["ingress"][0])
            tunnel_config["config"]["ingress"].insert(1, duplicate)
        return httpx.Response(
            200, json={"success": True, "errors": [], "result": tunnel_config}
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))

    with pytest.raises(CloudflareRollbackError):
        await client.configure_tunnel(
            "account-id", "tunnel-id", "example.com", "http://app:21212"
        )


@pytest.mark.anyio
async def test_restore_tunnel_configuration_refuses_concurrent_operator_change() -> None:
    operator_config = {
        "ingress": [
            {"hostname": "operator.example.com", "service": "http://operator:8080"},
            {"service": "http_status:404"},
        ]
    }
    writes: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            writes.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={"success": True, "errors": [], "result": {"config": operator_config}},
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))

    with pytest.raises(CloudflareAPIError) as captured:
        await client.restore_tunnel_configuration(
            "account-id",
            "tunnel-id",
            {"ingress": [{"service": "http_status:404"}]},
            {"ingress": [{"hostname": "example.com", "service": "http://app"}]},
        )

    assert captured.value.status_code == 409
    assert writes == []


@pytest.mark.anyio
async def test_restore_tunnel_configuration_rechecks_immediately_before_put() -> None:
    written = {"ingress": [{"hostname": "example.com", "service": "http://app"}]}
    operator = {
        "ingress": [
            {"hostname": "operator.example.com", "service": "http://operator:8080"},
            {"service": "http_status:404"},
        ]
    }
    snapshots = [written, operator]
    writes: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            writes.append(json.loads(request.content))
            result = {"config": operator}
        else:
            result = {"config": snapshots.pop(0)}
        return httpx.Response(200, json={"success": True, "errors": [], "result": result})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.restore_tunnel_configuration(
            "account-id",
            "tunnel-id",
            {"ingress": [{"service": "http_status:404"}]},
            written,
        )

    assert captured.value.status_code == 409
    assert writes == []


@pytest.mark.anyio
async def test_configure_tunnel_refuses_unstable_prewrite_snapshot() -> None:
    snapshots = [
        {"config": {"ingress": [{"service": "http_status:404"}]}},
        {
            "config": {
                "ingress": [
                    {"hostname": "operator.example.com", "service": "http://operator:8080"},
                    {"service": "http_status:404"},
                ]
            }
        },
    ]
    writes: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            writes.append(json.loads(request.content))
            result = snapshots[-1]
        else:
            result = snapshots.pop(0)
        return httpx.Response(200, json={"success": True, "errors": [], "result": result})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.configure_tunnel(
            "account-id", "tunnel-id", "example.com", "http://app:21212"
        )

    assert captured.value.status_code == 409
    assert writes == []


@pytest.mark.anyio
async def test_configure_tunnel_rejects_verification_that_drops_unrelated_route() -> None:
    original = {
        "config": {
            "ingress": [
                {"hostname": "operator.example.com", "service": "http://operator:8080"},
                {"service": "http_status:404"},
            ]
        }
    }
    writes: list[dict[str, Any]] = []
    get_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal get_count
        if request.method == "PUT":
            writes.append(json.loads(request.content))
            result = writes[-1]
        else:
            get_count += 1
            if get_count <= 2:
                result = original
            else:
                result = {
                    "config": {
                        "ingress": [
                            {"hostname": "pay.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                            {"hostname": "pay.example.com", "path": r"^/\.well-known/nostr\.json$", "service": "http://app:21212"},
                            {"service": "http_status:404"},
                        ]
                    }
                }
        return httpx.Response(200, json={"success": True, "errors": [], "result": result})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareRollbackError):
        await client.configure_tunnel(
            "account-id", "tunnel-id", "pay.example.com", "http://app:21212"
        )

    assert len(writes) == 1


def test_tunnel_ingress_override_refuses_preexisting_exact_route() -> None:
    ingress = [
        {
            "hostname": "pay.example.com",
            "path": r"^/\.well-known/lnurlp/.*$",
            "service": "http://app:21212",
        },
        {"service": "http_status:404"},
    ]

    with pytest.raises(CloudflareAPIError) as captured:
        CloudflareClient._override_ingress_routes(
            ingress, "pay.example.com", "http://app:21212"
        )

    assert captured.value.status_code == 409


@pytest.mark.anyio
async def test_verify_tunnel_route_requires_exact_unshadowed_routes() -> None:
    configs = [
        {
            "ingress": [
                {"hostname": "other.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                {"hostname": "pay.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                {"hostname": "pay.example.com", "path": r"^/\.well-known/nostr\.json$", "service": "http://app:21212"},
                {"hostname": "pay.example.com", "service": "http://site:8080"},
                {"service": "http_status:404"},
            ]
        },
        {
            "ingress": [
                {"hostname": "*.example.com", "service": "http://operator:8080"},
                {"hostname": "pay.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                {"hostname": "pay.example.com", "path": r"^/\.well-known/nostr\.json$", "service": "http://app:21212"},
                {"service": "http_status:404"},
            ]
        },
    ]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"success": True, "errors": [], "result": {"config": configs.pop(0)}},
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    assert await client.verify_tunnel_route(
        "account-id", "tunnel-id", "pay.example.com", "http://app:21212"
    )
    assert not await client.verify_tunnel_route(
        "account-id", "tunnel-id", "pay.example.com", "http://app:21212"
    )


def test_tunnel_ingress_override_preserves_unrelated_public_hostnames() -> None:
    ingress = [
        {"hostname": "other.example.com", "service": "http://other:8080"},
        {"hostname": "pay.example.com", "path": "/other", "service": "http://old:21212"},
        {"service": "http_status:404"},
    ]

    assert CloudflareClient._override_ingress_routes(
        ingress, "pay.example.com", "http://app:21212"
    ) == [
        {"hostname": "pay.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
        {"hostname": "pay.example.com", "path": r"^/\.well-known/nostr\.json$", "service": "http://app:21212"},
        {"hostname": "other.example.com", "service": "http://other:8080"},
        {"hostname": "pay.example.com", "path": "/other", "service": "http://old:21212"},
        {"service": "http_status:404"},
    ]


@pytest.mark.anyio
async def test_remove_tunnel_route_preserves_operator_changed_service() -> None:
    tunnel_config = {
        "config": {
            "ingress": [
                {
                    "hostname": "pay.example.com",
                    "path": r"^/\.well-known/lnurlp/.*$",
                    "service": "http://operator:8080",
                },
                {"service": "http_status:404"},
            ]
        }
    }
    writes: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            writes.append(json.loads(request.content))
        return httpx.Response(
            200, json={"success": True, "errors": [], "result": tunnel_config}
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.remove_tunnel_route(
            "account-id", "tunnel-id", "pay.example.com", "http://app:21212"
        )

    assert captured.value.status_code == 409
    assert writes == []


@pytest.mark.anyio
async def test_remove_tunnel_route_only_strips_managed_well_known_paths() -> None:
    tunnel_config = {
        "config": {
            "ingress": [
                {"hostname": "pay.example.com", "service": "http://site:8080"},
                {"hostname": "pay.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                {"hostname": "pay.example.com", "path": r"^/\.well-known/nostr\.json$", "service": "http://app:21212"},
                {"hostname": "second.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                {"hostname": "second.example.com", "path": r"^/\.well-known/nostr\.json$", "service": "http://app:21212"},
                {"hostname": "other.example.com", "service": "http://other:8080"},
                {"service": "http_status:404"},
            ]
        }
    }
    writes: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            writes.append(json.loads(request.content))
            tunnel_config.update(writes[-1])
        return httpx.Response(
            200, json={"success": True, "errors": [], "result": tunnel_config}
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.remove_tunnel_route(
        "account-id", "tunnel-id", "pay.example.com", "http://app:21212"
    )

    assert writes == [{
        "config": {
            "ingress": [
                {"hostname": "pay.example.com", "service": "http://site:8080"},
                {"hostname": "second.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                {"hostname": "second.example.com", "path": r"^/\.well-known/nostr\.json$", "service": "http://app:21212"},
                {"hostname": "other.example.com", "service": "http://other:8080"},
                {"service": "http_status:404"},
            ]
        }
    }]


@pytest.mark.anyio
async def test_remove_tunnel_route_rejects_verification_that_drops_unrelated_route() -> None:
    original = {
        "config": {
            "ingress": [
                {"hostname": "pay.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                {"hostname": "operator.example.com", "service": "http://operator:8080"},
                {"service": "http_status:404"},
            ]
        }
    }
    get_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal get_count
        if request.method == "GET":
            get_count += 1
            result = (
                original
                if get_count <= 2
                else {"config": {"ingress": [{"service": "http_status:404"}]}}
            )
        else:
            result = json.loads(request.content)
        return httpx.Response(200, json={"success": True, "errors": [], "result": result})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.remove_tunnel_route(
            "account-id", "tunnel-id", "pay.example.com", "http://app:21212"
        )

    assert captured.value.status_code == 502


@pytest.mark.anyio
async def test_remove_tunnel_route_refuses_unstable_prewrite_snapshot() -> None:
    original = {
        "config": {
            "ingress": [
                {"hostname": "pay.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                {"service": "http_status:404"},
            ]
        }
    }
    changed = {
        "config": {
            "ingress": [
                {"hostname": "pay.example.com", "path": r"^/\.well-known/lnurlp/.*$", "service": "http://app:21212"},
                {"hostname": "operator.example.com", "service": "http://operator:8080"},
                {"service": "http_status:404"},
            ]
        }
    }
    snapshots = [original, changed]
    writes: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            writes.append(json.loads(request.content))
            result = changed
        else:
            result = snapshots.pop(0)
        return httpx.Response(200, json={"success": True, "errors": [], "result": result})

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    with pytest.raises(CloudflareAPIError) as captured:
        await client.remove_tunnel_route(
            "account-id", "tunnel-id", "pay.example.com", "http://app:21212"
        )

    assert captured.value.status_code == 409
    assert writes == []


@pytest.mark.anyio
async def test_remove_tunnel_route_rejects_residual_managed_routes() -> None:
    tunnel_config = {
        "config": {
            "ingress": [
                {
                    "hostname": "pay.example.com",
                    "path": r"^/\.well-known/lnurlp/.*$",
                    "service": "http://app:21212",
                },
                {"service": "http_status:404"},
            ]
        }
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"success": True, "errors": [], "result": tunnel_config}
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))

    with pytest.raises(CloudflareAPIError):
        await client.remove_tunnel_route(
            "account-id",
            "tunnel-id",
            "pay.example.com",
            "http://app:21212",
        )


@pytest.mark.anyio
async def test_remove_tunnel_route_is_noop_without_managed_paths() -> None:
    tunnel_config = {
        "config": {
            "ingress": [
                {"hostname": "pay.example.com", "service": "http://site:8080"},
                {"service": "http_status:404"},
            ]
        }
    }
    writes: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            writes.append(json.loads(request.content))
        return httpx.Response(
            200, json={"success": True, "errors": [], "result": tunnel_config}
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))
    await client.remove_tunnel_route(
        "account-id", "tunnel-id", "pay.example.com", "http://app:21212"
    )

    assert writes == []


@pytest.mark.anyio
async def test_client_error_is_sanitized_and_never_echoes_token_or_provider_message() -> (
    None
):
    provider_message = f"invalid token {API_TOKEN}"

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
    assert rendered == "Cloudflare rejected the request with HTTP 403 (codes: 10000)"
    assert API_TOKEN not in rendered
    assert provider_message not in rendered


@pytest.mark.anyio
async def test_delete_operations_are_idempotent_when_resource_is_already_gone() -> None:
    requests: list[httpx.Request] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        requests.append(_request)
        return httpx.Response(
            404,
            json={"success": False, "errors": [{"code": 81044}], "result": None},
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))

    await client.delete_dns_record("zone-id", "record-id")
    await client.cleanup_tunnel_connections("account-id", "tunnel-id")
    await client.delete_tunnel("account-id", "tunnel-id")

    cleanup_request = requests[1]
    assert cleanup_request.headers["content-type"] == "application/json"
    assert cleanup_request.content == b"{}"


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
        return httpx.Response(
            200, json={"success": True, "errors": [], "result": result}
        )

    client = CloudflareClient(API_TOKEN, transport=httpx.MockTransport(handler))

    accounts = await client.list_accounts()

    assert len(accounts) == 51
    assert pages == [1, 2]
