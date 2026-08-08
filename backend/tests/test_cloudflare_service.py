from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from backend.app.cloudflare_client import CloudflareAPIError
from backend.app.cloudflare_service import (
    CloudflareConflictError,
    CloudflareNotFoundError,
    CloudflareService,
    CloudflareServiceError,
    CloudflareUnavailableError,
    CloudflareValidationError,
)
from backend.app.cloudflare_worker_source import (
    INTERNAL_HOSTNAME,
    LNS_WORKER_VERSION,
    MANAGED_COMMENT,
    WORKER_SCRIPT_NAME,
    WORKER_SOURCE,
)
from backend.app.connection_secret_store import ConnectionSecretStore
from backend.app.connection_store import ConnectionStore

ACCOUNT_ID = "a" * 32
ZONE_ID = "b" * 32
SECOND_ZONE_ID = "d" * 32
NODE_ID = "11111111-2222-4333-8444-555555555555"
DNS_ID = "c" * 32
ROUTE_ID = "e" * 32
API_TOKEN = "cloudflare-api-token-secret"
NODE_TOKEN = "mesh-node-token-secret"


def placeholder_record(
    zone_id: str, hostname: str, record_id: str = DNS_ID
) -> dict[str, Any]:
    return {
        "id": record_id,
        "zone_id": zone_id,
        "type": "AAAA",
        "name": hostname,
        "content": "100::",
        "proxied": True,
        "comment": MANAGED_COMMENT,
    }


def managed_route(zone_id: str, hostname: str, suffix: str) -> list[dict[str, Any]]:
    return [
        {
            "id": f"route-{suffix}-lnurlp",
            "zone_id": zone_id,
            "pattern": f"{hostname}/.well-known/lnurlp/*",
            "script": WORKER_SCRIPT_NAME,
        },
        {
            "id": f"route-{suffix}-nostr",
            "zone_id": zone_id,
            "pattern": f"{hostname}/.well-known/nostr.json",
            "script": WORKER_SCRIPT_NAME,
        },
    ]


@dataclass
class FakeCloudflareClient:
    dns_records: list[dict[str, Any]] = field(default_factory=list)
    workers_routes: list[dict[str, Any]] = field(default_factory=list)
    worker_content: str | None = None
    mesh_nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    node_connections: list[dict[str, Any]] = field(default_factory=list)
    hostname_routes: list[dict[str, Any]] = field(default_factory=list)
    calls: list[tuple[str, Any]] = field(default_factory=list)
    create_node_error: CloudflareAPIError | None = None
    create_dns_error: CloudflareAPIError | None = None
    ensure_routes_error: CloudflareAPIError | None = None
    delete_node_error: CloudflareAPIError | None = None
    delete_worker_error: CloudflareAPIError | None = None
    zones: list[dict[str, Any]] = field(default_factory=lambda: [
        {"id": ZONE_ID, "name": "example.com", "account": {"id": ACCOUNT_ID}},
    ])

    async def _call(self, name: str, value: Any = None) -> None:
        self.calls.append((name, value))

    async def verify_token(self) -> None:
        await self._call("verify_token")

    async def list_accounts(self) -> list[dict[str, Any]]:
        await self._call("list_accounts")
        return [{"id": ACCOUNT_ID, "name": "Example account"}]

    async def list_zones(self, account_id: str) -> list[dict[str, Any]]:
        await self._call("list_zones", account_id)
        return self.zones

    async def get_zone(self, zone_id: str) -> dict[str, Any]:
        await self._call("get_zone", zone_id)
        return next(zone for zone in self.zones if zone["id"] == zone_id)

    async def create_mesh_node(self, account_id: str, name: str) -> dict[str, Any]:
        await self._call("create_mesh_node", (account_id, name))
        if self.create_node_error is not None:
            raise self.create_node_error
        node = {"id": NODE_ID, "name": name}
        self.mesh_nodes[name] = node
        return node

    async def find_mesh_node_by_name(
        self, account_id: str, name: str
    ) -> dict[str, Any] | None:
        await self._call("find_mesh_node_by_name", (account_id, name))
        return self.mesh_nodes.get(name)

    async def get_mesh_node(
        self, account_id: str, node_id: str
    ) -> dict[str, Any] | None:
        await self._call("get_mesh_node", (account_id, node_id))
        return next(
            (node for node in self.mesh_nodes.values() if node["id"] == node_id), None
        )

    async def get_mesh_node_token(self, account_id: str, node_id: str) -> str:
        await self._call("get_mesh_node_token", (account_id, node_id))
        return NODE_TOKEN

    async def list_mesh_node_connections(
        self, account_id: str, node_id: str
    ) -> list[dict[str, Any]]:
        await self._call("list_mesh_node_connections", (account_id, node_id))
        return self.node_connections

    async def delete_mesh_node(self, account_id: str, node_id: str) -> None:
        await self._call("delete_mesh_node", (account_id, node_id))
        if self.delete_node_error is not None:
            raise self.delete_node_error
        self.mesh_nodes = {
            name: node
            for name, node in self.mesh_nodes.items()
            if node["id"] != node_id
        }

    async def create_hostname_route(
        self, account_id: str, node_id: str
    ) -> dict[str, Any]:
        await self._call("create_hostname_route", (account_id, node_id))
        route = {
            "id": ROUTE_ID,
            "hostname": INTERNAL_HOSTNAME,
            "tunnel_id": node_id,
            "comment": MANAGED_COMMENT,
        }
        self.hostname_routes.append(route)
        return route

    async def list_hostname_routes(self, account_id: str) -> list[dict[str, Any]]:
        await self._call("list_hostname_routes", account_id)
        return list(self.hostname_routes)

    async def get_hostname_route(
        self, account_id: str, route_id: str
    ) -> dict[str, Any] | None:
        await self._call("get_hostname_route", (account_id, route_id))
        return next(
            (route for route in self.hostname_routes if route["id"] == route_id), None
        )

    async def delete_hostname_route(self, account_id: str, route_id: str) -> None:
        await self._call("delete_hostname_route", (account_id, route_id))
        self.hostname_routes = [
            route for route in self.hostname_routes if route["id"] != route_id
        ]

    async def deploy_proxy_worker(self, account_id: str, script_name: str) -> None:
        await self._call("deploy_proxy_worker", (account_id, script_name))
        self.worker_content = WORKER_SOURCE

    async def get_worker_script_content(
        self, account_id: str, script_name: str
    ) -> str | None:
        await self._call("get_worker_script_content", (account_id, script_name))
        return self.worker_content

    async def delete_worker_script(self, account_id: str, script_name: str) -> None:
        await self._call("delete_worker_script", (account_id, script_name))
        if self.delete_worker_error is not None:
            raise self.delete_worker_error
        self.worker_content = None

    async def ensure_workers_routes(
        self, zone_id: str, hostname: str, script_name: str
    ) -> None:
        await self._call("ensure_workers_routes", (zone_id, hostname, script_name))
        if self.ensure_routes_error is not None:
            raise self.ensure_routes_error
        patterns = (
            f"{hostname}/.well-known/lnurlp/*",
            f"{hostname}/.well-known/nostr.json",
        )
        for pattern in patterns:
            matches = [
                route
                for route in self.workers_routes
                if route["zone_id"] == zone_id and route["pattern"] == pattern
            ]
            if any(route["script"] == script_name for route in matches):
                continue
            if matches:
                raise CloudflareAPIError(
                    409, messages=[f"Workers route {pattern} has a foreign owner"]
                )
            self.workers_routes.append(
                {
                    "id": f"route-{len(self.workers_routes)}",
                    "zone_id": zone_id,
                    "pattern": pattern,
                    "script": script_name,
                }
            )

    async def verify_workers_routes(
        self, zone_id: str, hostname: str, script_name: str
    ) -> bool:
        await self._call("verify_workers_routes", (zone_id, hostname, script_name))
        patterns = (
            f"{hostname}/.well-known/lnurlp/*",
            f"{hostname}/.well-known/nostr.json",
        )
        for pattern in patterns:
            matches = [
                route
                for route in self.workers_routes
                if route["zone_id"] == zone_id and route["pattern"] == pattern
            ]
            if len(matches) != 1 or matches[0]["script"] != script_name:
                return False
        return True

    async def remove_workers_routes(
        self, zone_id: str, hostname: str, script_name: str
    ) -> None:
        await self._call("remove_workers_routes", (zone_id, hostname, script_name))
        patterns = (
            f"{hostname}/.well-known/lnurlp/*",
            f"{hostname}/.well-known/nostr.json",
        )
        for pattern in patterns:
            matches = [
                route
                for route in self.workers_routes
                if route["zone_id"] == zone_id and route["pattern"] == pattern
            ]
            if any(route["script"] != script_name for route in matches):
                raise CloudflareAPIError(
                    409, messages=[f"Workers route {pattern} has a foreign owner"]
                )
            self.workers_routes = [
                route
                for route in self.workers_routes
                if not (
                    route["zone_id"] == zone_id
                    and route["pattern"] == pattern
                    and route["script"] == script_name
                )
            ]

    async def list_dns_records(
        self, zone_id: str, hostname: str
    ) -> list[dict[str, Any]]:
        await self._call("list_dns_records", (zone_id, hostname))
        normalized = hostname.lower().rstrip(".")
        return [
            record
            for record in self.dns_records
            if record.get("zone_id") == zone_id
            and str(record.get("name", "")).lower().rstrip(".") == normalized
        ]

    async def create_placeholder_dns_record(
        self, zone_id: str, hostname: str
    ) -> dict[str, Any]:
        await self._call("create_placeholder_dns_record", (zone_id, hostname))
        if self.create_dns_error is not None:
            raise self.create_dns_error
        record = placeholder_record(zone_id, hostname)
        self.dns_records.append(record)
        return record

    async def get_dns_record(
        self, zone_id: str, record_id: str
    ) -> dict[str, Any] | None:
        await self._call("get_dns_record", (zone_id, record_id))
        return next(
            (
                record
                for record in self.dns_records
                if record.get("zone_id") == zone_id and record.get("id") == record_id
            ),
            None,
        )

    async def delete_dns_record(self, zone_id: str, record_id: str) -> None:
        await self._call("delete_dns_record", (zone_id, record_id))
        self.dns_records = [
            record
            for record in self.dns_records
            if not (record.get("zone_id") == zone_id and record.get("id") == record_id)
        ]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def service_parts(tmp_path: Path):
    store = ConnectionStore(tmp_path / "connections.db")
    secrets = ConnectionSecretStore(tmp_path / "connections.db", tmp_path / "connection.key")
    client = FakeCloudflareClient()
    token_path = tmp_path / "mesh" / "node.env"
    return (
        CloudflareService(store=store, secrets=secrets, client_factory=lambda _token: client, connector_enabled=True, token_path=token_path, origin_url="http://app:21212", token_gid=os.getgid()),
        store, secrets, client, token_path,
    )


async def authorize_and_provision(
    service: CloudflareService, hostname: str = "example.com", zone_id: str = ZONE_ID
):
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID)
    return await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        zone_id=zone_id,
        hostname=hostname,
    )


def call_names(client: FakeCloudflareClient) -> list[str]:
    return [name for name, _ in client.calls]


@pytest.mark.anyio
async def test_oauth_grant_flow_resolves_access_tokens_and_persists_grant_id(
    tmp_path: Path,
) -> None:
    store = ConnectionStore(tmp_path / "connections.db")
    secrets = ConnectionSecretStore(tmp_path / "connections.db", tmp_path / "connection.key")
    client = FakeCloudflareClient()
    resolved: list[str] = []

    async def resolver(grant_id: str) -> str:
        resolved.append(grant_id)
        return "access-token"

    service = CloudflareService(
        store=store,
        secrets=secrets,
        client_factory=lambda _token: client,
        connector_enabled=True,
        token_path=tmp_path / "mesh" / "node.env",
        origin_url="http://app:21212",
        token_gid=os.getgid(),
        access_token_resolver=resolver,
    )

    authorization = await service.authorize_grant("grant-123", ACCOUNT_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )

    assert secrets.get(connection.id) == {"grant_id": "grant-123"}
    assert resolved == ["grant-123", "grant-123"]

    await service.refresh_status(connection.id)
    assert resolved == ["grant-123", "grant-123", "grant-123"]


@pytest.mark.anyio
async def test_grant_payload_without_resolver_fails_closed(tmp_path: Path) -> None:
    store = ConnectionStore(tmp_path / "connections.db")
    secrets = ConnectionSecretStore(tmp_path / "connections.db", tmp_path / "connection.key")
    client = FakeCloudflareClient()
    service = CloudflareService(
        store=store,
        secrets=secrets,
        client_factory=lambda _token: client,
        connector_enabled=True,
        token_path=tmp_path / "mesh" / "node.env",
        origin_url="http://app:21212",
        token_gid=os.getgid(),
    )
    secrets.set("owner", {"grant_id": "grant-123"})

    with pytest.raises(CloudflareServiceError, match="OAuth access is unavailable"):
        await service._client_from_payload("owner", {"grant_id": "grant-123"})


@pytest.mark.parametrize(
    "origin_url",
    [
        "http://ln switchboard:21212",
        "http://lnswitchboard\\evil:21212",
        "http://.bad:21212",
        "http://bad..host:21212",
    ],
)
def test_cloudflare_origin_rejects_malformed_hostnames(origin_url: str) -> None:
    with pytest.raises(CloudflareValidationError):
        CloudflareService._validate_origin_url(origin_url)


@pytest.mark.anyio
async def test_legacy_recovery_quarantines_without_destructive_cleanup(service_parts) -> None:
    service, store, secrets, client, token_path = service_parts
    connection = store.upsert_connection(
        provider="cloudflare",
        external_id="lnswitchboard-legacy-0000",
        label="Legacy Cloudflare Mesh",
        status="provisioning",
        account_id=ACCOUNT_ID,
    )
    journal = store.create_provisioning_journal(
        provider="cloudflare",
        authorization_owner="legacy-authorization",
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
        resource_name="legacy-node",
    )
    store.update_provisioning_journal(
        journal.id,
        external_id="lnswitchboard-legacy-0000",
        domain_external_id=DNS_ID,
        phase="dns_created",
    )
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(f"MESH_NODE_TOKEN={NODE_TOKEN}\n")
    orphan_owner = "12345678-1234-1234-1234-123456789abc"
    secrets.set(orphan_owner, {"api_token": "orphan"})
    expired_authorization = "cloudflare-authorization:" + "a" * 32
    live_authorization = "cloudflare-authorization:" + "b" * 32
    secrets.set(
        expired_authorization,
        {"api_token": "expired", "created_at": time.time() - 901},
    )
    secrets.set(
        live_authorization,
        {"api_token": "live", "created_at": time.time()},
    )
    client.calls.clear()

    await service.recover_incomplete_provisioning()

    recovered = store.get_provisioning_journal(journal.id)
    assert recovered is not None
    assert recovered.phase == "cleanup_pending"
    assert recovered.last_error == "legacy_recovery_requires_operator_review"
    assert store.get_connection(connection.id) is not None
    assert token_path.read_text() == f"MESH_NODE_TOKEN={NODE_TOKEN}\n"
    assert secrets.get(orphan_owner) is None
    assert secrets.get(expired_authorization) is None
    assert secrets.get(live_authorization) is not None
    assert client.calls == []


@pytest.mark.anyio
async def test_mesh_provision_creates_node_worker_routes_and_dns(service_parts) -> None:
    service, store, secrets, client, token_path = service_parts
    connection = await authorize_and_provision(service)
    assert connection.external_id.startswith("lnswitchboard-example-com-")
    assert connection.public_metadata["mesh_node_id"] == NODE_ID
    assert connection.public_metadata["hostname_route_id"] == ROUTE_ID
    assert connection.public_metadata["worker_version"] == LNS_WORKER_VERSION
    assert token_path.read_text() == f"MESH_NODE_TOKEN={NODE_TOKEN}\n"
    assert secrets.get(connection.id) == {"api_token": API_TOKEN}
    assert store.list_provisioning_journals("cloudflare") == []
    assert call_names(client) == [
        "verify_token",
        "list_accounts",
        "list_zones",
        "get_zone",
        "create_mesh_node",
        "get_mesh_node_token",
        "create_hostname_route",
        "get_worker_script_content",
        "deploy_proxy_worker",
        "get_worker_script_content",
        "list_dns_records",
        "create_placeholder_dns_record",
        "ensure_workers_routes",
        "get_dns_record",
        "verify_workers_routes",
    ]
    assert client.mesh_nodes[connection.external_id]["id"] == NODE_ID
    assert client.hostname_routes[0]["tunnel_id"] == NODE_ID
    assert client.worker_content == WORKER_SOURCE
    assert len(client.workers_routes) == 2
    assert len(client.dns_records) == 1


@pytest.mark.anyio
async def test_provision_persists_intent_and_credential_before_remote_mutation(
    service_parts, monkeypatch
) -> None:
    service, store, secrets, client, _token_path = service_parts
    create_mesh_node = client.create_mesh_node

    async def inspect_intent(account_id: str, name: str):
        [pending] = store.list_connections()
        assert pending.external_id == name
        assert pending.status == "provisioning"
        assert pending.domains[0].hostname == "example.com"
        assert pending.domains[0].external_id is None
        assert secrets.get(pending.id) == {"api_token": API_TOKEN}
        return await create_mesh_node(account_id, name)

    monkeypatch.setattr(client, "create_mesh_node", inspect_intent)
    await authorize_and_provision(service)


@pytest.mark.anyio
async def test_ambiguous_mesh_node_create_reconciles_by_name(
    service_parts, monkeypatch
) -> None:
    service, store, _secrets, client, _token_path = service_parts

    async def lost_response(account_id: str, name: str) -> dict[str, Any]:
        client.mesh_nodes[name] = {"id": NODE_ID, "name": name}
        await client._call("create_mesh_node", (account_id, name))
        raise CloudflareAPIError(503)

    monkeypatch.setattr(client, "create_mesh_node", lost_response)
    connection = await authorize_and_provision(service)

    assert connection.public_metadata["mesh_node_id"] == NODE_ID
    assert len(client.mesh_nodes) == 1
    assert "find_mesh_node_by_name" in call_names(client)
    assert store.list_connections()[0].status == "provisioning"


@pytest.mark.anyio
async def test_ambiguous_dns_creation_keeps_durable_disconnect_recovery(
    service_parts,
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.create_dns_error = CloudflareAPIError(503)

    with pytest.raises(CloudflareAPIError):
        await authorize_and_provision(service)

    [connection] = store.list_connections()
    assert connection.status == "error"
    assert connection.domains[0].hostname == "example.com"
    assert connection.public_metadata["cleanup_pending"] == [
        {
            "hostname": "example.com",
            "zone_id": ZONE_ID,
            "dns_record_id": None,
            "route_cleanup_pending": False,
            "dns_cleanup_pending": True,
        }
    ]

    client.create_dns_error = None
    assert await service.disconnect(connection.id) is True
    assert store.list_connections() == []


@pytest.mark.anyio
async def test_provision_rolls_back_node_when_token_fetch_fails(
    service_parts, monkeypatch
) -> None:
    service, store, _secrets, client, token_path = service_parts

    async def fail_token(_account_id: str, _node_id: str) -> str:
        raise CloudflareAPIError(403, messages=["not allowed"])

    monkeypatch.setattr(client, "get_mesh_node_token", fail_token)
    with pytest.raises(CloudflareAPIError, match="not allowed"):
        await authorize_and_provision(service)

    assert not token_path.exists()
    assert store.list_connections() == []
    assert client.mesh_nodes == {}
    assert call_names(client)[-1] == "delete_mesh_node"
    assert "create_hostname_route" not in call_names(client)


@pytest.mark.anyio
async def test_failed_rollback_is_persisted_for_disconnect_retry(
    service_parts, monkeypatch
) -> None:
    service, store, secrets, client, _token_path = service_parts
    client.ensure_routes_error = CloudflareAPIError(500)

    async def fail_dns_delete(_zone_id: str, _record_id: str) -> None:
        raise CloudflareAPIError(500)

    monkeypatch.setattr(client, "delete_dns_record", fail_dns_delete)
    with pytest.raises(CloudflareAPIError):
        await authorize_and_provision(service)

    [retained] = store.list_connections()
    assert retained.status == "error"
    assert retained.public_metadata["cleanup_pending"] == [
        {
            "hostname": "example.com",
            "zone_id": ZONE_ID,
            "dns_record_id": DNS_ID,
            "route_cleanup_pending": True,
            "dns_cleanup_pending": True,
        }
    ]
    assert secrets.get(retained.id) == {"api_token": API_TOKEN}

    client.ensure_routes_error = None
    monkeypatch.undo()
    client.calls.clear()
    assert await service.disconnect(retained.id) is True
    names = call_names(client)
    assert "remove_workers_routes" in names
    assert "delete_dns_record" in names
    assert "delete_mesh_node" in names
    # The worker script and hostname route were already rolled back after the
    # failed provision, so disconnect only has to finish the pending residue.
    assert client.worker_content is None
    assert client.hostname_routes == []
    assert store.list_connections() == []


@pytest.mark.anyio
async def test_provision_accepts_subdomain_in_selected_zone(service_parts) -> None:
    service, store, _secrets, _client, _token_path = service_parts
    connection = await authorize_and_provision(service, hostname="ln.example.com")
    stored = store.get_connection(connection.id)
    assert stored is not None
    assert stored.domains[0].hostname == "ln.example.com"


@pytest.mark.anyio
async def test_provision_rejects_hostname_outside_selected_zone(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID)
    with pytest.raises(CloudflareValidationError, match="selected zone"):
        await service.provision(
            authorization_id=str(authorization["authorization_id"]),
            account_id=ACCOUNT_ID,
            zone_id=ZONE_ID,
            hostname="example.com.attacker.test",
        )


@pytest.mark.anyio
async def test_provision_rejects_second_cloudflare_connection(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    await authorize_and_provision(service)
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID)
    with pytest.raises(CloudflareConflictError, match="already connected"):
        await service.provision(
            authorization_id=str(authorization["authorization_id"]),
            account_id=ACCOUNT_ID,
            zone_id=ZONE_ID,
            hostname="second.example.com",
        )


@pytest.mark.anyio
async def test_authorize_succeeds_when_account_enumeration_is_forbidden(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts

    async def forbidden_accounts() -> list[dict[str, Any]]:
        raise CloudflareAPIError(403)

    monkeypatch.setattr(client, "list_accounts", forbidden_accounts)
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID)
    assert authorization["accounts"] == [
        {
            "id": ACCOUNT_ID,
            "name": "Selected Cloudflare account",
            "zones": [{"id": ZONE_ID, "name": "example.com"}],
        }
    ]


@pytest.mark.anyio
async def test_provision_preserves_existing_dns_and_only_adds_routes(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.dns_records = [
        {
            "id": "operator-a",
            "zone_id": ZONE_ID,
            "type": "A",
            "name": "example.com",
            "content": "192.0.2.10",
            "proxied": True,
        }
    ]
    connection = await authorize_and_provision(service)

    assert connection.public_metadata["dns_adopted"] is True
    assert connection.domains[0].external_id is None
    assert "create_placeholder_dns_record" not in call_names(client)
    assert len(client.dns_records) == 1

    client.calls.clear()
    assert await service.disconnect(connection.id) is True
    assert "delete_dns_record" not in call_names(client)
    assert client.dns_records[0]["id"] == "operator-a"


@pytest.mark.anyio
async def test_provision_adopts_own_routes_and_placeholder_on_retry(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.workers_routes = managed_route(ZONE_ID, "example.com", "existing")
    client.dns_records = [placeholder_record(ZONE_ID, "example.com")]

    connection = await authorize_and_provision(service)

    assert connection.domains[0].external_id == DNS_ID
    assert "create_placeholder_dns_record" not in call_names(client)
    assert len(client.workers_routes) == 2


@pytest.mark.anyio
async def test_provision_refuses_foreign_workers_route_without_overwrite(
    service_parts,
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.workers_routes = [
        {
            "id": "foreign",
            "zone_id": ZONE_ID,
            "pattern": "example.com/.well-known/nostr.json",
            "script": "operator-script",
        }
    ]

    with pytest.raises(CloudflareAPIError) as captured:
        await authorize_and_provision(service)

    assert captured.value.status_code == 409
    assert store.list_connections() == []
    # The foreign route and every rolled-back resource are handled correctly.
    assert client.workers_routes[0]["script"] == "operator-script"
    assert client.mesh_nodes == {}
    assert client.worker_content is None
    assert client.hostname_routes == []
    assert client.dns_records == []


@pytest.mark.anyio
async def test_provision_refuses_foreign_worker_script(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.worker_content = "// operator-managed script without marker"

    with pytest.raises(CloudflareConflictError, match="not managed by lnSwitchboard"):
        await authorize_and_provision(service)

    assert store.list_connections() == []
    assert client.worker_content == "// operator-managed script without marker"
    assert "deploy_proxy_worker" not in call_names(client)
    assert "delete_worker_script" not in call_names(client)


@pytest.mark.anyio
async def test_provision_upgrades_outdated_managed_worker(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.worker_content = WORKER_SOURCE.replace(LNS_WORKER_VERSION, "2000.01.01.1")

    connection = await authorize_and_provision(service)

    assert connection.public_metadata["worker_version"] == LNS_WORKER_VERSION
    assert "deploy_proxy_worker" in call_names(client)
    assert client.worker_content == WORKER_SOURCE


@pytest.mark.anyio
async def test_provision_surfaces_provider_dns_rejection_verbatim(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.create_dns_error = CloudflareAPIError(
        403, [9109], messages=["Not allowed to edit DNS for this zone"]
    )
    with pytest.raises(CloudflareAPIError, match="Not allowed to edit DNS"):
        await authorize_and_provision(service)


@pytest.mark.anyio
async def test_disconnect_removes_routes_dns_route_worker_node_and_token(
    service_parts,
) -> None:
    service, store, secrets, client, token_path = service_parts
    connection = await authorize_and_provision(service)
    client.calls.clear()

    assert await service.disconnect(connection.id) is True

    assert call_names(client) == [
        "get_dns_record",
        "remove_workers_routes",
        "get_dns_record",
        "delete_dns_record",
        "get_hostname_route",
        "delete_hostname_route",
        "get_worker_script_content",
        "delete_worker_script",
        "delete_mesh_node",
    ]
    assert store.get_connection(connection.id) is None
    assert secrets.get(connection.id) is None
    assert not token_path.exists()
    assert client.mesh_nodes == {}
    assert client.workers_routes == []
    assert client.dns_records == []
    assert client.worker_content is None
    assert client.hostname_routes == []


@pytest.mark.anyio
async def test_disconnect_uses_legacy_connection_zone_for_owned_dns(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    store.replace_domains(
        connection.id,
        [
            {
                "hostname": "example.com",
                "status": "active",
                "external_id": DNS_ID,
                "zone_id": None,
            }
        ],
    )
    client.calls.clear()

    assert await service.disconnect(connection.id) is True

    assert ("get_dns_record", (ZONE_ID, DNS_ID)) in client.calls
    assert ("delete_dns_record", (ZONE_ID, DNS_ID)) in client.calls


@pytest.mark.anyio
async def test_disconnect_preserves_dns_changed_after_initial_ownership_check(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    checks = 0
    original_get = client.get_dns_record

    async def changing_record(zone_id: str, record_id: str):
        nonlocal checks
        checks += 1
        record = await original_get(zone_id, record_id)
        if checks > 1 and record is not None:
            record = dict(record)
            record["comment"] = "Operator changed"
        return record

    monkeypatch.setattr(client, "get_dns_record", changing_record)
    with pytest.raises(CloudflareConflictError, match="changed during cleanup"):
        await service.disconnect(connection.id)

    assert "delete_dns_record" not in call_names(client)
    assert client.dns_records[0]["id"] == DNS_ID


@pytest.mark.anyio
async def test_disconnect_preserves_api_secret_when_local_delete_fails(
    service_parts, monkeypatch
) -> None:
    service, store, secrets, _client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    original_delete = store.delete_connection

    def fail_delete(_connection_id: str) -> bool:
        raise OSError("injected connection deletion failure")

    monkeypatch.setattr(store, "delete_connection", fail_delete)
    with pytest.raises(CloudflareServiceError, match="retry disconnect"):
        await service.disconnect(connection.id)

    retained = store.get_connection(connection.id)
    assert retained is not None
    assert retained.status == "error"
    assert retained.last_error == "Cloudflare local cleanup failed; retry disconnect"
    assert secrets.get(connection.id) == {"api_token": API_TOKEN}

    monkeypatch.setattr(store, "delete_connection", original_delete)
    assert await service.disconnect(connection.id) is True
    assert secrets.get(connection.id) is None


@pytest.mark.anyio
async def test_refresh_is_active_only_with_live_node_matching_worker_and_sane_resources(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    client.node_connections = [{"is_pending_reconnect": False}]

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "connected"
    assert refreshed.domains[0].status == "active"
    assert refreshed.public_metadata["connector_count"] == 1


@pytest.mark.anyio
async def test_refresh_degrades_when_node_has_no_live_connections(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    client.node_connections = [{"is_pending_reconnect": False}]
    await service.refresh_status(connection.id)

    client.node_connections = [{"is_pending_reconnect": True}]
    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert refreshed.domains[0].status == "error"


@pytest.mark.anyio
async def test_refresh_degrades_when_worker_version_drift_is_foreign(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    client.node_connections = [{"is_pending_reconnect": False}]
    client.worker_content = "// replaced by an operator; no marker"
    client.calls.clear()

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert refreshed.domains[0].status == "error"
    assert "not managed by lnSwitchboard" in str(refreshed.domains[0].last_error)
    assert "delete_worker_script" not in call_names(client)
    assert "deploy_proxy_worker" not in call_names(client)


@pytest.mark.anyio
async def test_refresh_upgrades_outdated_managed_worker(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    client.node_connections = [{"is_pending_reconnect": False}]
    client.worker_content = WORKER_SOURCE.replace(LNS_WORKER_VERSION, "2000.01.01.1")
    client.calls.clear()

    refreshed = await service.refresh_status(connection.id)

    assert "deploy_proxy_worker" in call_names(client)
    assert client.worker_content == WORKER_SOURCE
    assert refreshed.status == "connected"
    assert refreshed.domains[0].status == "active"


@pytest.mark.anyio
async def test_refresh_marks_hostname_error_when_routes_are_missing(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    client.node_connections = [{"is_pending_reconnect": False}]
    client.workers_routes = []

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert refreshed.domains[0].status == "error"
    assert refreshed.domains[0].last_error == (
        "Managed Workers Routes are missing, retargeted, duplicated, or owned by another script"
    )


@pytest.mark.anyio
async def test_refresh_marks_owned_hostname_error_when_dns_is_missing(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    client.node_connections = [{"is_pending_reconnect": False}]
    client.dns_records = []

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert refreshed.domains[0].status == "error"
    assert refreshed.domains[0].last_error == "Managed DNS record is missing or no longer owned"


@pytest.mark.anyio
async def test_refresh_marks_adopted_hostname_error_when_dns_disappears(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.dns_records = [
        {
            "id": "operator-a",
            "zone_id": ZONE_ID,
            "type": "A",
            "name": "example.com",
            "content": "192.0.2.10",
            "proxied": True,
        }
    ]
    connection = await authorize_and_provision(service)
    client.node_connections = [{"is_pending_reconnect": False}]
    assert (await service.refresh_status(connection.id)).domains[0].status == "active"

    client.dns_records = []
    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert refreshed.domains[0].status == "error"
    assert refreshed.domains[0].last_error == (
        "Hostname has no DNS record; the managed Workers Routes cannot activate it"
    )


@pytest.mark.anyio
async def test_refresh_recovers_owned_dns_id_from_persisted_pending_intent(
    service_parts,
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    store.replace_domains(
        connection.id,
        [
            {
                "hostname": "example.com",
                "status": "pending",
                "external_id": None,
                "zone_id": ZONE_ID,
            }
        ],
    )
    client.node_connections = [{"is_pending_reconnect": False}]

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert refreshed.domains[0].external_id == DNS_ID
    assert refreshed.domains[0].status == "error"
    assert "provisioning was interrupted" in str(refreshed.domains[0].last_error)


@pytest.mark.anyio
async def test_refresh_recovers_missing_node_id_by_name(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    metadata = dict(connection.public_metadata)
    del metadata["mesh_node_id"]
    store.upsert_connection(
        provider="cloudflare",
        external_id=connection.external_id,
        label=connection.label,
        status="provisioning",
        account_id=connection.account_id,
        public_metadata=metadata,
    )
    client.node_connections = [{"is_pending_reconnect": False}]
    client.calls.clear()

    refreshed = await service.refresh_status(connection.id)

    assert "find_mesh_node_by_name" in call_names(client)
    assert refreshed.public_metadata["mesh_node_id"] == NODE_ID
    assert refreshed.status == "connected"


@pytest.mark.anyio
async def test_add_domain_persists_intent_before_dns_mutation(
    service_parts, monkeypatch
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    connection = await authorize_and_provision(service)
    create_record = client.create_placeholder_dns_record

    async def inspect_intent(zone_id: str, hostname: str):
        pending = store.get_connection(connection.id)
        assert pending is not None
        intended = next(domain for domain in pending.domains if domain.hostname == hostname)
        assert intended.zone_id == zone_id
        assert intended.external_id is None
        return await create_record(zone_id, hostname)

    monkeypatch.setattr(client, "create_placeholder_dns_record", inspect_intent)
    updated = await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")

    added = next(domain for domain in updated.domains if domain.hostname == "example.net")
    assert added.external_id == DNS_ID


@pytest.mark.anyio
async def test_add_domain_rolls_back_created_dns_when_routes_conflict(
    service_parts,
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    connection = await authorize_and_provision(service)
    client.workers_routes.append(
        {
            "id": "foreign",
            "zone_id": SECOND_ZONE_ID,
            "pattern": "example.net/.well-known/lnurlp/*",
            "script": "operator-script",
        }
    )
    client.calls.clear()

    with pytest.raises(CloudflareAPIError):
        await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")

    assert call_names(client) == [
        "get_zone",
        "list_dns_records",
        "create_placeholder_dns_record",
        "ensure_workers_routes",
        "remove_workers_routes",
        "get_dns_record",
        "delete_dns_record",
    ]
    stored = store.get_connection(connection.id)
    assert stored is not None
    assert [domain.hostname for domain in stored.domains] == ["example.com"]
    assert client.dns_records == [
        record for record in client.dns_records if record["zone_id"] == ZONE_ID
    ]


@pytest.mark.anyio
async def test_add_domain_does_not_touch_routes_when_dns_is_rejected(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    connection = await authorize_and_provision(service)
    client.calls.clear()
    client.create_dns_error = CloudflareAPIError(403, [9109])

    with pytest.raises(CloudflareAPIError):
        await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")

    assert call_names(client) == [
        "get_zone",
        "list_dns_records",
        "create_placeholder_dns_record",
        "list_dns_records",
    ]
    stored = store.get_connection(connection.id)
    assert stored is not None
    assert [domain.hostname for domain in stored.domains] == ["example.com"]


@pytest.mark.anyio
async def test_failed_add_domain_rollback_is_persisted_for_disconnect_retry(
    service_parts, monkeypatch
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    connection = await authorize_and_provision(service)
    client.ensure_routes_error = CloudflareAPIError(500)

    async def fail_dns_delete(_zone_id: str, _record_id: str) -> None:
        raise CloudflareAPIError(500)

    monkeypatch.setattr(client, "delete_dns_record", fail_dns_delete)
    with pytest.raises(CloudflareAPIError):
        await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")

    stored = store.get_connection(connection.id)
    assert stored is not None
    assert stored.status == "error"
    assert stored.public_metadata["cleanup_pending"] == [
        {
            "hostname": "example.net",
            "zone_id": SECOND_ZONE_ID,
            "dns_record_id": DNS_ID,
            "route_cleanup_pending": True,
            "dns_cleanup_pending": True,
        }
    ]

    client.ensure_routes_error = None
    monkeypatch.undo()
    client.calls.clear()
    assert await service.disconnect(connection.id) is True
    route_calls = [
        value for name, value in client.calls if name == "remove_workers_routes"
    ]
    assert (ZONE_ID, "example.com", WORKER_SCRIPT_NAME) in route_calls
    assert (SECOND_ZONE_ID, "example.net", WORKER_SCRIPT_NAME) in route_calls


@pytest.mark.anyio
async def test_existing_connection_lists_authorized_zones_for_more_hostnames(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    connection = await authorize_and_provision(service)

    assert await service.available_zones(connection.id) == [
        {"id": ZONE_ID, "name": "example.com"},
        {"id": SECOND_ZONE_ID, "name": "example.net"},
    ]


@pytest.mark.anyio
async def test_existing_connection_adds_subdomain_from_an_already_used_zone(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    connection = await authorize_and_provision(service)

    updated = await service.add_domain(connection.id, ZONE_ID, "ln.example.com")

    assert [domain.hostname for domain in updated.domains] == [
        "example.com",
        "ln.example.com",
    ]
    assert [domain.zone_id for domain in updated.domains] == [ZONE_ID, ZONE_ID]


@pytest.mark.anyio
async def test_existing_connection_adds_and_removes_one_domain(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    connection = await authorize_and_provision(service)
    client.calls.clear()

    updated = await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")

    assert [domain.hostname for domain in updated.domains] == ["example.com", "example.net"]
    assert call_names(client) == [
        "get_zone",
        "list_dns_records",
        "create_placeholder_dns_record",
        "ensure_workers_routes",
    ]
    client.calls.clear()

    remaining = await service.remove_domain(connection.id, "example.net")

    assert [domain.hostname for domain in remaining.domains] == ["example.com"]
    assert call_names(client) == [
        "get_dns_record",
        "remove_workers_routes",
        "get_dns_record",
        "delete_dns_record",
    ]
    stored = store.get_connection(connection.id)
    assert stored is not None
    assert [domain.hostname for domain in stored.domains] == ["example.com"]
    assert client.hostname_routes != []
    assert client.mesh_nodes != {}


@pytest.mark.anyio
async def test_remove_domain_preserves_dns_changed_after_route_cleanup(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    connection = await authorize_and_provision(service)
    await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")
    checks = 0
    original_get = client.get_dns_record

    async def changing_record(zone_id: str, record_id: str):
        nonlocal checks
        record = await original_get(zone_id, record_id)
        if zone_id == SECOND_ZONE_ID:
            checks += 1
            if checks > 1 and record is not None:
                record = dict(record)
                record["comment"] = "Operator changed"
        return record

    monkeypatch.setattr(client, "get_dns_record", changing_record)
    client.calls.clear()
    with pytest.raises(CloudflareConflictError, match="changed during cleanup"):
        await service.remove_domain(connection.id, "example.net")

    assert "delete_dns_record" not in call_names(client)
    assert any(record["zone_id"] == SECOND_ZONE_ID for record in client.dns_records)


@pytest.mark.anyio
async def test_remove_adopted_domain_preserves_dns(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    connection = await authorize_and_provision(service)
    client.dns_records.append(
        {
            "id": "operator-net",
            "zone_id": SECOND_ZONE_ID,
            "type": "A",
            "name": "example.net",
            "content": "192.0.2.20",
            "proxied": True,
        }
    )
    updated = await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")
    assert next(domain for domain in updated.domains if domain.zone_id == SECOND_ZONE_ID).external_id is None
    client.calls.clear()

    await service.remove_domain(connection.id, "example.net")

    assert call_names(client) == ["list_dns_records", "remove_workers_routes"]
    assert any(record["id"] == "operator-net" for record in client.dns_records)


@pytest.mark.anyio
async def test_disconnect_cleans_up_every_connected_domain(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    connection = await authorize_and_provision(service)
    await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")
    client.calls.clear()

    assert await service.disconnect(connection.id) is True

    removed_hostnames = [
        value[1] for name, value in client.calls if name == "remove_workers_routes"
    ]
    assert removed_hostnames == ["example.com", "example.net"]
    assert sum(name == "delete_dns_record" for name, _ in client.calls) == 2
    assert client.workers_routes == []
    assert client.dns_records == []


@pytest.mark.anyio
async def test_remove_domain_requires_disconnect_for_the_final_domain(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    client.calls.clear()

    with pytest.raises(CloudflareConflictError, match="final domain"):
        await service.remove_domain(connection.id, "example.com")

    assert client.calls == []


@pytest.mark.anyio
async def test_disconnect_waits_for_domain_lifecycle_lock(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    connection = await authorize_and_provision(service)

    await service._provision_lock.acquire()
    task = asyncio.create_task(service.disconnect(connection.id))
    await asyncio.sleep(0)
    assert not task.done()
    service._provision_lock.release()
    assert await task is True


@pytest.mark.anyio
async def test_refresh_waits_for_domain_lifecycle_lock(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    connection = await authorize_and_provision(service)

    await service._provision_lock.acquire()
    task = asyncio.create_task(service.refresh_status(connection.id))
    await asyncio.sleep(0)
    assert not task.done()
    service._provision_lock.release()
    assert (await task).id == connection.id


@pytest.mark.anyio
async def test_disabled_connector_rejects_authorization(tmp_path: Path) -> None:
    service = CloudflareService(store=ConnectionStore(tmp_path / "db"), secrets=ConnectionSecretStore(tmp_path / "db", tmp_path / "key"), client_factory=lambda _token: FakeCloudflareClient(), connector_enabled=False, token_path=tmp_path / "token", origin_url="http://app:21212", token_gid=os.getgid())
    with pytest.raises(CloudflareUnavailableError):
        await service.authorize(API_TOKEN, ACCOUNT_ID)


@pytest.mark.anyio
async def test_provision_rejects_mismatched_account(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID)
    with pytest.raises(CloudflareValidationError, match="validated token"):
        await service.provision(
            authorization_id=str(authorization["authorization_id"]),
            account_id="f" * 32,
            zone_id=ZONE_ID,
            hostname="example.com",
        )


@pytest.mark.anyio
async def test_missing_connection_raises_not_found(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    with pytest.raises(CloudflareNotFoundError):
        await service.refresh_status("12345678-1234-1234-1234-123456789abc")
