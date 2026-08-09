from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from backend.app.cloudflare_client import (
    CloudflareAPIError,
    CloudflareWorkersRouteProvisionError,
)
from backend.app.cloudflare_service import (
    PREREQ_METADATA_KEY,
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
    worker_subdomain: dict[str, Any] = field(
        default_factory=lambda: {"enabled": False, "previews_enabled": False}
    )
    mesh_nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    node_connections: list[dict[str, Any]] = field(default_factory=list)
    hostname_routes: list[dict[str, Any]] = field(default_factory=list)
    calls: list[tuple[str, Any]] = field(default_factory=list)
    create_node_error: CloudflareAPIError | None = None
    create_dns_error: CloudflareAPIError | None = None
    ensure_routes_error: CloudflareAPIError | None = None
    delete_node_error: CloudflareAPIError | None = None
    delete_worker_error: CloudflareAPIError | None = None
    list_access_apps_error: CloudflareAPIError | None = None
    # Cloudflare One prerequisite state; defaults are fully satisfied so
    # provisioning tests exercise the no-write path.
    access_apps: list[dict[str, Any]] = field(default_factory=lambda: [
        {
            "id": "app-warp",
            "type": "warp",
            "name": "Warp device enrollment",
            "policies": [
                {"decision": "allow", "include": [{"everyone": {}}]},
            ],
        },
    ])
    device_policy: dict[str, Any] = field(default_factory=lambda: {
        "default": True,
        "enabled": True,
        "include": [{"address": "100.96.0.0/12", "description": "mesh"}],
        "exclude": [],
        "service_mode_v2": {"mode": "warp"},
    })
    device_settings: dict[str, Any] = field(default_factory=lambda: {
        "gateway_proxy_enabled": True,
        "gateway_udp_proxy_enabled": True,
        "use_zt_virtual_ip": True,
    })
    connectivity_settings: dict[str, Any] = field(default_factory=lambda: {
        "icmp_proxy_enabled": True,
        "offramp_warp_enabled": True,
    })
    zones: list[dict[str, Any]] = field(default_factory=lambda: [
        {"id": ZONE_ID, "name": "example.com", "account": {"id": ACCOUNT_ID}},
    ])

    async def _call(self, name: str, value: Any = None) -> None:
        self.calls.append((name, value))

    async def list_access_apps(self, account_id: str) -> list[dict[str, Any]]:
        await self._call("list_access_apps", account_id)
        if self.list_access_apps_error is not None:
            raise self.list_access_apps_error
        return [dict(app) for app in self.access_apps]

    async def create_access_app(
        self, account_id: str, app: dict[str, Any]
    ) -> dict[str, Any]:
        await self._call("create_access_app", (account_id, app))
        created = {"id": "app-created", **app}
        self.access_apps.append(created)
        return created

    async def list_device_policies(self, account_id: str) -> list[dict[str, Any]]:
        await self._call("list_device_policies", account_id)
        return [dict(self.device_policy)]

    async def get_default_device_policy(self, account_id: str) -> dict[str, Any]:
        await self._call("get_default_device_policy", account_id)
        return {
            key: (list(value) if isinstance(value, list) else value)
            for key, value in self.device_policy.items()
        }

    async def patch_default_device_policy(
        self, account_id: str, fields: dict[str, Any]
    ) -> dict[str, Any]:
        await self._call("patch_default_device_policy", (account_id, fields))
        self.device_policy.update(fields)
        return dict(self.device_policy)

    async def get_device_settings(self, account_id: str) -> dict[str, Any]:
        await self._call("get_device_settings", account_id)
        return dict(self.device_settings)

    async def patch_device_settings(
        self, account_id: str, fields: dict[str, Any]
    ) -> dict[str, Any]:
        await self._call("patch_device_settings", (account_id, fields))
        self.device_settings.update(fields)
        return dict(self.device_settings)

    async def get_connectivity_settings(self, account_id: str) -> dict[str, Any]:
        await self._call("get_connectivity_settings", account_id)
        return dict(self.connectivity_settings)

    async def patch_connectivity_settings(
        self, account_id: str, fields: dict[str, Any]
    ) -> dict[str, Any]:
        await self._call("patch_connectivity_settings", (account_id, fields))
        self.connectivity_settings.update(fields)
        return dict(self.connectivity_settings)


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

    async def deploy_proxy_worker(
        self, account_id: str, script_name: str, mesh_ingress_key: str
    ) -> None:
        assert len(mesh_ingress_key) >= 32
        await self._call("deploy_proxy_worker", (account_id, script_name))
        self.worker_content = WORKER_SOURCE

    async def get_worker_script_content(
        self, account_id: str, script_name: str
    ) -> str | None:
        await self._call("get_worker_script_content", (account_id, script_name))
        return self.worker_content

    async def configure_worker_subdomain(
        self, account_id: str, script_name: str
    ) -> dict[str, Any]:
        await self._call("configure_worker_subdomain", (account_id, script_name))
        self.worker_subdomain = {"enabled": False, "previews_enabled": False}
        return dict(self.worker_subdomain)

    async def get_worker_subdomain(
        self, account_id: str, script_name: str
    ) -> dict[str, Any] | None:
        await self._call("get_worker_subdomain", (account_id, script_name))
        return dict(self.worker_subdomain)

    async def delete_worker_script(self, account_id: str, script_name: str) -> None:
        await self._call("delete_worker_script", (account_id, script_name))
        if self.delete_worker_error is not None:
            raise self.delete_worker_error
        self.worker_content = None

    async def ensure_workers_routes(
        self, zone_id: str, hostname: str, script_name: str
    ) -> list[tuple[str, str]]:
        await self._call("ensure_workers_routes", (zone_id, hostname, script_name))
        if self.ensure_routes_error is not None:
            raise self.ensure_routes_error
        created: list[tuple[str, str]] = []
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
            route_id = f"route-{len(self.workers_routes)}"
            self.workers_routes.append(
                {
                    "id": route_id,
                    "zone_id": zone_id,
                    "pattern": pattern,
                    "script": script_name,
                }
            )
            created.append((route_id, pattern))
        return created

    async def remove_worker_route(
        self,
        zone_id: str,
        route_id: str,
        pattern: str,
        script_name: str,
    ) -> None:
        await self._call("remove_workers_routes", (zone_id, pattern, script_name))
        matches = [
            route
            for route in self.workers_routes
            if route["id"] == route_id
        ]
        if not matches:
            return
        route = matches[0]
        if route["pattern"] != pattern or route["script"] != script_name:
            raise CloudflareAPIError(409)
        self.workers_routes = [
            item for item in self.workers_routes if item["id"] != route_id
        ]

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


def test_sync_public_ingress_authority_migrates_existing_connection(
    service_parts,
) -> None:
    service, store, secret_store, _client, _token_path = service_parts
    connection = store.upsert_connection(
        provider="cloudflare",
        external_id="existing-mesh",
        label="Existing Mesh",
        status="connected",
    )
    store.replace_domains(
        connection.id,
        [{"hostname": "existing.example", "status": "active"}],
    )
    secret_store.set(
        connection.id,
        {"grant_id": "existing-grant", "mesh_ingress_key": "existing-key"},
    )

    assert store.get_public_ingress_key("existing.example") is None
    service.sync_public_ingress_authorities()
    assert store.get_public_ingress_key("existing.example") == "existing-key"


@pytest.mark.anyio
async def test_oauth_grant_account_discovery_does_not_create_authorization(
    tmp_path: Path,
) -> None:
    store = ConnectionStore(tmp_path / "connections.db")
    secrets = ConnectionSecretStore(
        tmp_path / "connections.db", tmp_path / "secrets.key"
    )
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

    accounts = await service.discover_grant_accounts("grant-123")

    assert accounts == [{"id": ACCOUNT_ID, "name": "Example account"}]
    assert resolved == ["grant-123"]
    assert not any(
        owner.startswith("cloudflare-authorization:")
        for owner in secrets.list_owner_ids()
    )
    assert client.calls == [("verify_token", None), ("list_accounts", None)]


@pytest.mark.anyio
async def test_grant_revocation_serializes_reference_creation(tmp_path: Path) -> None:
    store = ConnectionStore(tmp_path / "connections.db")
    secrets = ConnectionSecretStore(
        tmp_path / "connections.db", tmp_path / "secrets.key"
    )
    client = FakeCloudflareClient()
    revoke_entered = asyncio.Event()
    allow_revoke = asyncio.Event()
    grant_active = True

    async def resolver(_grant_id: str) -> str:
        if not grant_active:
            raise CloudflareServiceError("grant unavailable")
        return "access-token"

    async def revoker(_grant_id: str) -> bool:
        nonlocal grant_active
        revoke_entered.set()
        await allow_revoke.wait()
        grant_active = False
        return True

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

    revoke_task = asyncio.create_task(
        service.revoke_grant_if_unused("race-grant", revoker)
    )
    await revoke_entered.wait()
    authorize_task = asyncio.create_task(
        service.authorize_grant("race-grant", ACCOUNT_ID)
    )
    await asyncio.sleep(0)
    assert not authorize_task.done()

    allow_revoke.set()
    assert await revoke_task is True
    with pytest.raises(CloudflareServiceError, match="grant unavailable"):
        await authorize_task
    assert not any(
        owner.startswith("cloudflare-authorization:")
        for owner in secrets.list_owner_ids()
    )


@pytest.mark.anyio
async def test_oauth_reauthorization_replaces_grant_without_remote_mutation(
    tmp_path: Path,
) -> None:
    store = ConnectionStore(tmp_path / "connections.db")
    secrets = ConnectionSecretStore(
        tmp_path / "connections.db", tmp_path / "secrets.key"
    )
    client = FakeCloudflareClient()

    async def resolver(_grant_id: str) -> str:
        return "replacement-access-token"

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
    connection = store.upsert_connection(
        provider="cloudflare",
        external_id="existing-node",
        label="Cloudflare Mesh",
        status="error",
        account_id=ACCOUNT_ID,
        public_metadata={},
    )
    secrets.set(
        connection.id,
        {"grant_id": "expired-grant", "mesh_ingress_key": "existing-ingress-key"},
    )
    authorization_id = "a" * 32
    authorization_owner = f"cloudflare-authorization:{authorization_id}"
    secrets.set(
        authorization_owner,
        {
            "grant_id": "replacement-grant",
            "account_id": ACCOUNT_ID,
            "created_at": time.time(),
        },
    )

    result = await service.reauthorize(connection.id, authorization_id)

    assert result.id == connection.id
    assert secrets.get(connection.id) == {
        "grant_id": "replacement-grant",
        "mesh_ingress_key": "existing-ingress-key",
    }
    assert secrets.get(authorization_owner) is None
    assert client.calls == [("verify_token", None)]


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

    stored_credential = secrets.get(connection.id)
    assert stored_credential is not None
    assert stored_credential["grant_id"] == "grant-123"
    assert len(stored_credential["mesh_ingress_key"]) >= 32
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
    assert not token_path.exists()
    assert secrets.get(orphan_owner) is None
    assert secrets.get(expired_authorization) is None
    assert secrets.get(live_authorization) is not None
    assert client.calls == []


@pytest.mark.anyio
async def test_recovery_revokes_mesh_token_for_incomplete_connection(
    service_parts,
) -> None:
    service, store, secrets, client, token_path = service_parts
    connection = store.upsert_connection(
        provider="cloudflare",
        external_id="lnswitchboard-interrupted-0000",
        label="Cloudflare Mesh",
        status="provisioning",
        account_id=ACCOUNT_ID,
        public_metadata={"mesh_node_id": NODE_ID},
    )
    secrets.set(
        connection.id,
        {"api_token": API_TOKEN, "mesh_ingress_key": "mesh-key"},
    )
    client.mesh_nodes[NODE_ID] = {
        "id": NODE_ID,
        "name": connection.external_id,
    }
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(f"MESH_NODE_TOKEN={NODE_TOKEN}\n")

    await service.recover_incomplete_provisioning()

    assert not token_path.exists()
    assert "delete_mesh_node" in call_names(client)
    recovered = store.get_connection(connection.id)
    assert recovered is not None
    assert recovered.status == "error"
    assert recovered.last_error == (
        "Interrupted Cloudflare provisioning was revoked; disconnect and retry"
    )


@pytest.mark.anyio
async def test_recovery_retries_failed_interrupted_node_revocation(
    service_parts,
) -> None:
    service, store, secrets, client, token_path = service_parts
    connection = store.upsert_connection(
        provider="cloudflare",
        external_id="lnswitchboard-interrupted-retry",
        label="Cloudflare Mesh",
        status="provisioning",
        account_id=ACCOUNT_ID,
        public_metadata={"mesh_node_id": NODE_ID},
    )
    secrets.set(
        connection.id,
        {"api_token": API_TOKEN, "mesh_ingress_key": "mesh-key"},
    )
    client.mesh_nodes[NODE_ID] = {
        "id": NODE_ID,
        "name": connection.external_id,
    }
    client.delete_node_error = CloudflareAPIError(503)
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(f"MESH_NODE_TOKEN={NODE_TOKEN}\n")

    with pytest.raises(
        CloudflareServiceError,
        match="Interrupted Cloudflare provisioning cleanup failed",
    ):
        await service.recover_incomplete_provisioning()

    assert not token_path.exists()
    pending = store.get_connection(connection.id)
    assert pending is not None
    assert pending.status == "error"
    assert pending.public_metadata["interrupted_cleanup_pending"] is True
    assert NODE_ID in client.mesh_nodes

    client.delete_node_error = None
    await service.recover_incomplete_provisioning()

    recovered = store.get_connection(connection.id)
    assert recovered is not None
    assert "interrupted_cleanup_pending" not in recovered.public_metadata
    assert NODE_ID not in client.mesh_nodes


@pytest.mark.anyio
async def test_recovery_preserves_committed_provisioning(service_parts) -> None:
    service, store, _secrets, client, token_path = service_parts
    connection = await authorize_and_provision(service)
    client.calls.clear()

    await service.recover_incomplete_provisioning()

    recovered = store.get_connection(connection.id)
    assert recovered is not None
    assert recovered.status == "provisioning"
    assert recovered.public_metadata["provisioning_committed"] is True
    assert token_path.exists()
    assert "delete_mesh_node" not in call_names(client)


@pytest.mark.anyio
async def test_mesh_provision_creates_node_worker_routes_and_dns(service_parts) -> None:
    service, store, secrets, client, token_path = service_parts
    connection = await authorize_and_provision(service)
    assert connection.external_id.startswith("lnswitchboard-example-com-")
    assert connection.public_metadata["mesh_node_id"] == NODE_ID
    assert connection.public_metadata["hostname_route_id"] == ROUTE_ID
    assert connection.public_metadata["worker_version"] == LNS_WORKER_VERSION
    assert token_path.read_text() == (
        f"MESH_NODE_ID={NODE_ID}\nMESH_NODE_TOKEN={NODE_TOKEN}\n"
    )
    assert token_path.stat().st_mode & 0o777 == 0o640
    assert token_path.stat().st_gid == os.getgid()
    credential = secrets.get(connection.id)
    assert credential is not None
    assert credential["api_token"] == API_TOKEN
    assert len(credential["mesh_ingress_key"]) >= 32
    assert store.list_provisioning_journals("cloudflare") == []
    assert call_names(client) == [
        "verify_token",
        "list_accounts",
        "list_zones",
        "get_zone",
        "list_access_apps",
        "get_default_device_policy",
        "get_device_settings",
        "get_connectivity_settings",
        "create_mesh_node",
        "get_mesh_node_token",
        "create_hostname_route",
        "get_worker_script_content",
        "deploy_proxy_worker",
        "get_worker_script_content",
        "configure_worker_subdomain",
        "get_worker_subdomain",
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
async def test_provision_fails_closed_if_worker_public_subdomains_remain_enabled(
    service_parts, monkeypatch
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.worker_subdomain = {"enabled": True, "previews_enabled": True}

    async def refuse_disable(
        _account_id: str, _script_name: str
    ) -> dict[str, Any]:
        await client._call("configure_worker_subdomain")
        return dict(client.worker_subdomain)

    monkeypatch.setattr(client, "configure_worker_subdomain", refuse_disable)

    with pytest.raises(CloudflareConflictError, match="subdomains"):
        await authorize_and_provision(service)

    assert store.list_connections() == []
    assert client.worker_content is None


PREREQ_WRITE_CALLS = {
    "create_access_app",
    "patch_default_device_policy",
    "patch_device_settings",
    "patch_connectivity_settings",
}


def prereq_writes(client: FakeCloudflareClient) -> list[str]:
    return [name for name in call_names(client) if name in PREREQ_WRITE_CALLS]


@pytest.mark.anyio
async def test_prerequisites_already_satisfied_issue_no_writes(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    report = await service.ensure_account_prerequisites(client, ACCOUNT_ID)

    assert report["status"] == "satisfied"
    assert set(report["checks"]) == {
        "device_enrollment",
        "device_profile",
        "gateway_proxy",
        "unique_device_ips",
        "mesh_connectivity",
    }
    assert all(
        check["status"] == "passed" for check in report["checks"].values()
    )
    assert prereq_writes(client) == []


@pytest.mark.anyio
async def test_prerequisite_device_enrollment_created_exactly_once_when_missing(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.access_apps = []
    report = await service.ensure_account_prerequisites(client, ACCOUNT_ID)

    assert report["status"] == "satisfied"
    assert report["checks"]["device_enrollment"]["status"] == "configured"
    assert prereq_writes(client) == ["create_access_app"]
    [created] = client.access_apps
    assert created["type"] == "warp"
    assert created["policies"][0]["decision"] == "allow"

    client.calls.clear()
    second = await service.ensure_account_prerequisites(client, ACCOUNT_ID)
    assert second["checks"]["device_enrollment"]["status"] == "passed"
    assert prereq_writes(client) == []


@pytest.mark.anyio
async def test_prerequisite_enrollment_app_without_allow_policy_needs_manual_action(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.access_apps = [
        {"id": "app-warp", "type": "warp", "policies": [{"decision": "block"}]}
    ]
    report = await service.ensure_account_prerequisites(client, ACCOUNT_ID)

    assert report["status"] == "needs-manual-action"
    assert report["checks"]["device_enrollment"]["status"] == "needs-manual-action"
    assert prereq_writes(client) == []


@pytest.mark.anyio
async def test_prerequisite_include_mode_profile_appends_mesh_range_preserving_entries(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.device_policy = {
        "default": True,
        "include": [{"address": "10.0.0.0/8", "description": "operator LAN"}],
        "exclude": [],
        "service_mode_v2": {"mode": "warp"},
    }
    report = await service.ensure_account_prerequisites(client, ACCOUNT_ID)

    assert report["checks"]["device_profile"]["status"] == "configured"
    assert prereq_writes(client) == ["patch_default_device_policy"]
    addresses = [entry["address"] for entry in client.device_policy["include"]]
    assert addresses == ["10.0.0.0/8", "100.96.0.0/12"]

    client.calls.clear()
    second = await service.ensure_account_prerequisites(client, ACCOUNT_ID)
    assert second["checks"]["device_profile"]["status"] == "passed"
    assert prereq_writes(client) == []


@pytest.mark.anyio
async def test_prerequisite_exclude_mode_removes_only_the_default_cgnat_exclusion(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.device_policy = {
        "default": True,
        "include": [],
        "exclude": [
            {"address": "100.64.0.0/10", "description": "Default CGNAT"},
            {"address": "10.0.0.0/8", "description": "operator LAN"},
        ],
        "service_mode_v2": {"mode": "warp"},
    }
    report = await service.ensure_account_prerequisites(client, ACCOUNT_ID)

    assert report["checks"]["device_profile"]["status"] == "configured"
    assert prereq_writes(client) == ["patch_default_device_policy"]
    # Only the exact default 100.64.0.0/10 entry is removed; every other
    # exclusion is preserved untouched.
    assert client.device_policy["exclude"] == [
        {"address": "10.0.0.0/8", "description": "operator LAN"}
    ]


@pytest.mark.anyio
async def test_prerequisite_exclude_mode_without_mesh_blockers_passes(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.device_policy = {
        "default": True,
        "include": [],
        "exclude": [{"address": "10.0.0.0/8", "description": "operator LAN"}],
        "service_mode_v2": {"mode": "warp"},
    }
    report = await service.ensure_account_prerequisites(client, ACCOUNT_ID)

    assert report["checks"]["device_profile"]["status"] == "passed"
    assert prereq_writes(client) == []


@pytest.mark.anyio
@pytest.mark.parametrize("blocking_address", ["100.64.0.0/9", "100.96.0.0/12", "100.0.0.0/8"])
async def test_prerequisite_exclude_mode_custom_blocking_entry_needs_manual_action(
    service_parts, blocking_address: str
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.device_policy = {
        "default": True,
        "include": [],
        "exclude": [
            {"address": blocking_address, "description": "operator custom"}
        ],
        "service_mode_v2": {"mode": "warp"},
    }
    report = await service.ensure_account_prerequisites(client, ACCOUNT_ID)

    check = report["checks"]["device_profile"]
    assert report["status"] == "needs-manual-action"
    assert check["status"] == "needs-manual-action"
    assert blocking_address in check["detail"]
    # A customized profile is never mutated.
    assert prereq_writes(client) == []
    assert client.device_policy["exclude"] == [
        {"address": blocking_address, "description": "operator custom"}
    ]


@pytest.mark.anyio
async def test_prerequisite_non_warp_client_mode_needs_manual_action(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.device_policy = {
        "default": True,
        "include": [{"address": "100.96.0.0/12"}],
        "exclude": [],
        "service_mode_v2": {"mode": "proxy"},
    }
    report = await service.ensure_account_prerequisites(client, ACCOUNT_ID)

    check = report["checks"]["device_profile"]
    assert check["status"] == "needs-manual-action"
    assert "proxy" in check["detail"]
    assert prereq_writes(client) == []


@pytest.mark.anyio
async def test_prerequisite_toggles_patch_only_missing_fields(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.device_settings["gateway_proxy_enabled"] = False
    client.connectivity_settings["offramp_warp_enabled"] = False
    report = await service.ensure_account_prerequisites(client, ACCOUNT_ID)

    assert report["status"] == "satisfied"
    assert report["checks"]["gateway_proxy"]["status"] == "configured"
    assert report["checks"]["mesh_connectivity"]["status"] == "configured"
    assert report["checks"]["unique_device_ips"]["status"] == "passed"
    assert prereq_writes(client) == [
        "patch_device_settings",
        "patch_connectivity_settings",
    ]
    patch_bodies = {
        name: value[1]
        for name, value in client.calls
        if name in {"patch_device_settings", "patch_connectivity_settings"}
    }
    assert patch_bodies["patch_device_settings"] == {"gateway_proxy_enabled": True}
    assert patch_bodies["patch_connectivity_settings"] == {
        "offramp_warp_enabled": True
    }

    client.calls.clear()
    second = await service.ensure_account_prerequisites(client, ACCOUNT_ID)
    assert all(
        check["status"] == "passed" for check in second["checks"].values()
    )
    assert prereq_writes(client) == []


@pytest.mark.anyio
async def test_prerequisites_second_run_is_fully_idempotent(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.access_apps = []
    client.device_policy = {
        "default": True,
        "include": [],
        "exclude": [{"address": "100.64.0.0/10", "description": "Default CGNAT"}],
        "service_mode_v2": {"mode": "warp"},
    }
    client.device_settings = {
        "gateway_proxy_enabled": False,
        "gateway_udp_proxy_enabled": False,
        "use_zt_virtual_ip": False,
    }
    client.connectivity_settings = {
        "icmp_proxy_enabled": False,
        "offramp_warp_enabled": False,
    }
    first = await service.ensure_account_prerequisites(client, ACCOUNT_ID)
    assert first["status"] == "satisfied"
    assert sorted(prereq_writes(client)) == [
        "create_access_app",
        "patch_connectivity_settings",
        "patch_default_device_policy",
        "patch_device_settings",
    ]

    client.calls.clear()
    second = await service.ensure_account_prerequisites(client, ACCOUNT_ID)
    assert second["status"] == "satisfied"
    assert all(
        check["status"] == "passed" for check in second["checks"].values()
    )
    assert prereq_writes(client) == []


@pytest.mark.anyio
async def test_provision_runs_prerequisites_before_node_creation(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)

    names = call_names(client)
    prereq_reads = [
        "list_access_apps",
        "get_default_device_policy",
        "get_device_settings",
        "get_connectivity_settings",
    ]
    node_index = names.index("create_mesh_node")
    assert all(names.index(name) < node_index for name in prereq_reads)
    report = connection.public_metadata[PREREQ_METADATA_KEY]
    assert report["status"] == "satisfied"
    # The persisted report carries no credentials.
    assert API_TOKEN not in str(report)
    assert NODE_TOKEN not in str(report)


@pytest.mark.anyio
async def test_provision_aborts_before_remote_mutation_when_prereq_api_fails(
    service_parts,
) -> None:
    service, store, _secrets, client, token_path = service_parts
    client.list_access_apps_error = CloudflareAPIError(
        403, messages=["Actor requires Zero Trust Edit permission"]
    )

    with pytest.raises(CloudflareAPIError, match="Zero Trust Edit permission"):
        await authorize_and_provision(service)

    assert store.list_connections() == []
    assert client.mesh_nodes == {}
    assert client.hostname_routes == []
    assert client.dns_records == []
    assert client.workers_routes == []
    assert client.worker_content is None
    assert not token_path.exists()
    assert "create_mesh_node" not in call_names(client)


@pytest.mark.anyio
async def test_provision_aborts_when_prereqs_need_manual_action(service_parts) -> None:
    service, store, _secrets, client, token_path = service_parts
    client.device_policy = {
        "default": True,
        "include": [],
        "exclude": [{"address": "100.96.0.0/12", "description": "operator"}],
        "service_mode_v2": {"mode": "warp"},
    }

    with pytest.raises(CloudflareConflictError, match="manual action"):
        await authorize_and_provision(service)

    assert store.list_connections() == []
    assert client.mesh_nodes == {}
    assert client.hostname_routes == []
    assert client.dns_records == []
    assert client.workers_routes == []
    assert not token_path.exists()
    assert "create_mesh_node" not in call_names(client)


@pytest.mark.anyio
async def test_refresh_reverifies_and_heals_prereq_drift(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    client.node_connections = [{"is_pending_reconnect": False}]
    client.device_settings["use_zt_virtual_ip"] = False
    client.calls.clear()

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "connected"
    assert prereq_writes(client) == ["patch_device_settings"]
    report = refreshed.public_metadata[PREREQ_METADATA_KEY]
    assert report["status"] == "satisfied"
    assert report["checks"]["unique_device_ips"]["status"] == "configured"
    assert client.device_settings["use_zt_virtual_ip"] is True


@pytest.mark.anyio
async def test_refresh_degrades_with_per_check_detail_when_prereq_needs_manual_action(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    client.node_connections = [{"is_pending_reconnect": False}]
    client.device_policy = {
        "default": True,
        "include": [],
        "exclude": [{"address": "100.64.0.0/9", "description": "operator"}],
        "service_mode_v2": {"mode": "warp"},
    }
    client.calls.clear()

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert prereq_writes(client) == []
    report = refreshed.public_metadata[PREREQ_METADATA_KEY]
    assert report["status"] == "needs-manual-action"
    check = report["checks"]["device_profile"]
    assert check["status"] == "needs-manual-action"
    assert "100.64.0.0/9" in check["detail"]


@pytest.mark.anyio
async def test_refresh_degrades_when_prereq_verification_fails(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    client.node_connections = [{"is_pending_reconnect": False}]
    client.list_access_apps_error = CloudflareAPIError(403, messages=["denied"])

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"


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
        credential = secrets.get(pending.id)
        assert credential is not None
        assert credential["api_token"] == API_TOKEN
        assert len(credential["mesh_ingress_key"]) >= 32
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
            "route_cleanup_pending": False,
            "dns_cleanup_pending": True,
        }
    ]
    credential = secrets.get(retained.id)
    assert credential is not None
    assert credential["api_token"] == API_TOKEN
    assert len(credential["mesh_ingress_key"]) >= 32

    client.ensure_routes_error = None
    monkeypatch.undo()
    client.calls.clear()
    assert await service.disconnect(retained.id) is True
    names = call_names(client)
    assert "remove_workers_routes" in names
    assert "delete_dns_record" in names
    assert "get_mesh_node" in names
    assert "delete_mesh_node" not in names
    # The worker script, hostname route, and Mesh node were already rolled back
    # failed provision, so disconnect only has to finish the pending residue.
    assert client.worker_content is None
    assert client.hostname_routes == []
    assert store.list_connections() == []


@pytest.mark.anyio
async def test_failed_provision_never_deletes_preexisting_managed_worker(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.worker_content = WORKER_SOURCE
    client.ensure_routes_error = CloudflareAPIError(500)

    with pytest.raises(CloudflareAPIError):
        await authorize_and_provision(service)

    assert "deploy_proxy_worker" in call_names(client)
    assert "delete_worker_script" not in call_names(client)


@pytest.mark.anyio
async def test_failed_provision_preserves_adopted_worker_route(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    adopted = managed_route(ZONE_ID, "example.com", "adopted")[0]
    client.workers_routes = [dict(adopted)]
    original_verify = client.verify_workers_routes

    async def fail_after_ensure(
        zone_id: str, hostname: str, script_name: str
    ) -> bool:
        await original_verify(zone_id, hostname, script_name)
        return False

    client.verify_workers_routes = fail_after_ensure  # type: ignore[method-assign]

    authorization_id = await service.authorize(API_TOKEN, ACCOUNT_ID)
    with pytest.raises(CloudflareAPIError):
        await service.provision(
            authorization_id=str(authorization_id["authorization_id"]),
            account_id=ACCOUNT_ID,
            zone_id=ZONE_ID,
            hostname="example.com",
        )

    assert client.workers_routes == [adopted]


@pytest.mark.anyio
async def test_failed_provision_rolls_back_exact_partially_created_worker_route(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    pattern = "example.com/.well-known/lnurlp/*"

    async def fail_after_first_route(
        zone_id: str, hostname: str, script_name: str
    ) -> list[tuple[str, str]]:
        route = {
            "id": "created-first",
            "zone_id": zone_id,
            "pattern": pattern,
            "script": script_name,
        }
        client.workers_routes.append(route)
        raise CloudflareWorkersRouteProvisionError(
            CloudflareAPIError(409), [("created-first", pattern)]
        )

    monkeypatch.setattr(client, "ensure_workers_routes", fail_after_first_route)

    with pytest.raises(CloudflareWorkersRouteProvisionError):
        await authorize_and_provision(service)

    assert client.workers_routes == []
    assert "remove_workers_routes" in call_names(client)


@pytest.mark.anyio
async def test_failed_provision_never_deletes_adopted_hostname_route(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.hostname_routes = [
        {
            "id": ROUTE_ID,
            "hostname": INTERNAL_HOSTNAME,
            "tunnel_id": NODE_ID,
            "comment": MANAGED_COMMENT,
        }
    ]
    client.ensure_routes_error = CloudflareAPIError(500)

    async def conflict(_account_id: str, _node_id: str) -> dict[str, Any]:
        raise CloudflareAPIError(409)

    monkeypatch.setattr(client, "create_hostname_route", conflict)

    with pytest.raises(CloudflareAPIError):
        await authorize_and_provision(service)

    assert client.hostname_routes[0]["id"] == ROUTE_ID
    assert "delete_hostname_route" not in call_names(client)


@pytest.mark.anyio
async def test_failed_provision_revalidates_created_hostname_route_before_delete(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.ensure_routes_error = CloudflareAPIError(500)
    original_get = client.get_hostname_route

    async def retarget_before_rollback(
        account_id: str, route_id: str
    ) -> dict[str, Any] | None:
        for route in client.hostname_routes:
            if route["id"] == route_id:
                route["tunnel_id"] = "operator-node"
        return await original_get(account_id, route_id)

    monkeypatch.setattr(client, "get_hostname_route", retarget_before_rollback)

    with pytest.raises(CloudflareAPIError):
        await authorize_and_provision(service)

    assert client.hostname_routes == [
        {
            "id": ROUTE_ID,
            "hostname": INTERNAL_HOSTNAME,
            "tunnel_id": "operator-node",
            "comment": MANAGED_COMMENT,
        }
    ]
    assert "delete_hostname_route" not in call_names(client)


@pytest.mark.anyio
async def test_failed_provision_preserves_mesh_node_renamed_before_rollback(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.ensure_routes_error = CloudflareAPIError(500)
    original_get = client.get_mesh_node

    async def rename_before_rollback(
        account_id: str, node_id: str
    ) -> dict[str, Any] | None:
        node = await original_get(account_id, node_id)
        if node is not None:
            node["name"] = "operator-renamed-node"
        return node

    monkeypatch.setattr(client, "get_mesh_node", rename_before_rollback)

    with pytest.raises(CloudflareAPIError):
        await authorize_and_provision(service)

    assert any(
        node["id"] == NODE_ID and node["name"] == "operator-renamed-node"
        for node in client.mesh_nodes.values()
    )
    assert "delete_mesh_node" not in call_names(client)


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
        "get_mesh_node",
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
async def test_disconnect_preserves_mesh_node_that_changed_ownership(
    service_parts,
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    connection = await authorize_and_provision(service)
    node = await client.get_mesh_node(ACCOUNT_ID, NODE_ID)
    assert node is not None
    node["name"] = "operator-renamed-node"
    client.calls.clear()

    with pytest.raises(CloudflareConflictError, match="changed ownership"):
        await service.disconnect(connection.id)

    assert "delete_mesh_node" not in call_names(client)
    retained = store.get_connection(connection.id)
    assert retained is not None
    assert retained.status == "error"


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
    credential = secrets.get(connection.id)
    assert credential is not None
    assert credential["api_token"] == API_TOKEN
    assert len(credential["mesh_ingress_key"]) >= 32

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
            "route_cleanup_pending": False,
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
