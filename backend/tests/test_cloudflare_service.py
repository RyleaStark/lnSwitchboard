from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from backend.app.cloudflare_service import (
    CloudflareConflictError,
    CloudflareNotFoundError,
    CloudflareService,
    CloudflareUnavailableError,
)
from backend.app.connection_secret_store import ConnectionSecretStore
from backend.app.connection_store import ConnectionStore

ACCOUNT_ID = "a" * 32
ZONE_ID = "b" * 32
TUNNEL_ID = "11111111-2222-4333-8444-555555555555"
DNS_ID = "c" * 32
API_TOKEN = "cloudflare-api-token-secret"
CONNECTOR_TOKEN = "connector-token-secret"


@dataclass
class FakeCloudflareClient:
    calls: list[tuple[str, Any]] = field(default_factory=list)
    dns_records: list[dict[str, Any]] = field(default_factory=list)

    async def _call(self, name: str, value: Any = None) -> None:
        self.calls.append((name, value))

    async def verify_token(self) -> None:
        await self._call("verify_token")

    async def list_accounts(self) -> list[dict[str, Any]]:
        await self._call("list_accounts")
        return [{"id": ACCOUNT_ID, "name": "Example account"}]

    async def list_zones(self, account_id: str) -> list[dict[str, Any]]:
        await self._call("list_zones", account_id)
        return [{"id": ZONE_ID, "name": "example.com"}]

    async def get_tunnel(self, account_id: str, tunnel_id: str) -> dict[str, Any] | None:
        await self._call("get_tunnel", (account_id, tunnel_id))
        return {"id": tunnel_id, "name": "operator-managed-tunnel"}

    async def get_zone(self, zone_id: str) -> dict[str, Any]:
        await self._call("get_zone", zone_id)
        return {"id": ZONE_ID, "name": "example.com", "account": {"id": ACCOUNT_ID}}

    async def list_dns_records(self, zone_id: str, hostname: str) -> list[dict[str, Any]]:
        await self._call("list_dns_records", (zone_id, hostname))
        return self.dns_records

    async def configure_tunnel(self, account_id: str, tunnel_id: str, hostname: str, origin_url: str) -> None:
        await self._call("configure_tunnel", (account_id, tunnel_id, hostname, origin_url))

    async def create_dns_record(self, zone_id: str, hostname: str, tunnel_id: str) -> dict[str, Any]:
        await self._call("create_dns_record", (zone_id, hostname, tunnel_id))
        return {"id": DNS_ID, "name": hostname, "type": "CNAME", "content": f"{tunnel_id}.cfargotunnel.com", "comment": "Managed by lnSwitchboard"}

    async def get_tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        await self._call("get_tunnel_token", (account_id, tunnel_id))
        return CONNECTOR_TOKEN

    async def list_tunnel_connections(self, account_id: str, tunnel_id: str) -> list[dict[str, Any]]:
        await self._call("list_tunnel_connections", (account_id, tunnel_id))
        return []

    async def get_dns_record(self, zone_id: str, record_id: str) -> dict[str, Any] | None:
        await self._call("get_dns_record", (zone_id, record_id))
        return {"id": record_id, "type": "CNAME", "name": "pay.example.com", "content": f"{TUNNEL_ID}.cfargotunnel.com", "comment": "Managed by lnSwitchboard"}

    async def remove_tunnel_route(self, account_id: str, tunnel_id: str, hostname: str) -> None:
        await self._call("remove_tunnel_route", (account_id, tunnel_id, hostname))

    async def delete_dns_record(self, zone_id: str, record_id: str) -> None:
        await self._call("delete_dns_record", (zone_id, record_id))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def service_parts(tmp_path: Path):
    store = ConnectionStore(tmp_path / "connections.db")
    secrets = ConnectionSecretStore(tmp_path / "connections.db", tmp_path / "connection.key")
    client = FakeCloudflareClient()
    token_path = tmp_path / "cloudflared" / "tunnel.token"
    return (
        CloudflareService(store=store, secrets=secrets, client_factory=lambda _token: client, connector_enabled=True, token_path=token_path, origin_url="http://app:21212", token_gid=os.getgid()),
        store, secrets, client, token_path,
    )


@pytest.mark.anyio
async def test_existing_tunnel_onboarding_validates_operator_ids_and_never_creates_a_tunnel(service_parts) -> None:
    service, store, secrets, client, token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(authorization_id=str(authorization["authorization_id"]), account_id=ACCOUNT_ID, tunnel_id=TUNNEL_ID, zone_id=ZONE_ID, hostname="pay.example.com")
    assert connection.external_id == TUNNEL_ID
    assert token_path.read_text() == CONNECTOR_TOKEN
    assert secrets.get(connection.id) == {"api_token": API_TOKEN}
    assert store.list_provisioning_journals("cloudflare") == []
    assert [name for name, _ in client.calls] == ["verify_token", "get_tunnel", "list_accounts", "list_zones", "get_zone", "list_dns_records", "configure_tunnel", "create_dns_record", "get_tunnel_token"]


@pytest.mark.anyio
async def test_existing_tunnel_onboarding_refuses_unknown_tunnel(service_parts, monkeypatch) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    async def missing(*_args: str) -> None:
        return None
    monkeypatch.setattr(client, "get_tunnel", missing)
    with pytest.raises(CloudflareNotFoundError):
        await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)


@pytest.mark.anyio
async def test_existing_tunnel_onboarding_preserves_existing_dns(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    client.dns_records = [{"id": "existing", "type": "A"}]
    with pytest.raises(CloudflareConflictError):
        await service.provision(authorization_id=str(authorization["authorization_id"]), account_id=ACCOUNT_ID, tunnel_id=TUNNEL_ID, zone_id=ZONE_ID, hostname="pay.example.com")
    assert "create_dns_record" not in [name for name, _ in client.calls]


@pytest.mark.anyio
async def test_disconnect_removes_only_owned_route_and_dns_record(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(authorization_id=str(authorization["authorization_id"]), account_id=ACCOUNT_ID, tunnel_id=TUNNEL_ID, zone_id=ZONE_ID, hostname="pay.example.com")
    client.calls.clear()
    assert await service.disconnect(connection.id) is True
    assert [name for name, _ in client.calls] == ["get_dns_record", "remove_tunnel_route", "delete_dns_record"]
    assert store.get_connection(connection.id) is None


@pytest.mark.anyio
async def test_disabled_connector_rejects_authorization(tmp_path: Path) -> None:
    service = CloudflareService(store=ConnectionStore(tmp_path / "db"), secrets=ConnectionSecretStore(tmp_path / "db", tmp_path / "key"), client_factory=lambda _token: FakeCloudflareClient(), connector_enabled=False, token_path=tmp_path / "token", origin_url="http://app:21212", token_gid=os.getgid())
    with pytest.raises(CloudflareUnavailableError):
        await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
