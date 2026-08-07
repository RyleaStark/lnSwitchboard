from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from backend.app.cloudflare_service import (
    CloudflareConflictError,
    CloudflareService,
    CloudflareServiceError,
    CloudflareUnavailableError,
    CloudflareValidationError,
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
    fail_on: str | None = None
    also_fail_on: set[str] = field(default_factory=set)
    dns_record_override: dict[str, Any] | None = None
    remote_tunnel: dict[str, Any] | None = None
    remote_dns_record: dict[str, Any] | None = None
    lose_tunnel_response: bool = False
    lose_dns_response: bool = False
    fail_tunnel_lookup: bool = False

    async def _call(self, name: str, value: Any = None) -> None:
        self.calls.append((name, value))
        if self.fail_on == name or name in self.also_fail_on:
            raise RuntimeError(f"forced {name} failure")

    async def verify_token(self) -> None:
        await self._call("verify_token")

    async def list_accounts(self) -> list[dict[str, str]]:
        await self._call("list_accounts")
        return [{"id": ACCOUNT_ID, "name": "Example Account"}]

    async def list_zones(self, account_id: str) -> list[dict[str, Any]]:
        await self._call("list_zones", account_id)
        return [{"id": ZONE_ID, "name": "example.com", "account": {"id": ACCOUNT_ID}}]

    async def get_zone(self, zone_id: str) -> dict[str, Any]:
        await self._call("get_zone", zone_id)
        return {"id": ZONE_ID, "name": "example.com", "account": {"id": ACCOUNT_ID}}

    async def list_dns_records(
        self, zone_id: str, hostname: str
    ) -> list[dict[str, Any]]:
        await self._call("list_dns_records", (zone_id, hostname))
        records = list(self.dns_records)
        if self.remote_dns_record is not None:
            records.append(self.remote_dns_record)
        return records

    async def create_tunnel(self, account_id: str, name: str) -> dict[str, Any]:
        await self._call("create_tunnel", (account_id, name))
        self.remote_tunnel = {"id": TUNNEL_ID, "name": name, "status": "inactive"}
        if self.lose_tunnel_response:
            raise RuntimeError("tunnel response lost")
        return self.remote_tunnel

    async def find_tunnel_by_name(
        self, account_id: str, name: str
    ) -> dict[str, Any] | None:
        await self._call("find_tunnel_by_name", (account_id, name))
        if self.fail_tunnel_lookup:
            raise RuntimeError("transient tunnel lookup failure")
        if self.remote_tunnel and self.remote_tunnel.get("name") == name:
            return self.remote_tunnel
        return None

    async def configure_tunnel(
        self, account_id: str, tunnel_id: str, hostname: str, origin_url: str
    ) -> None:
        await self._call(
            "configure_tunnel", (account_id, tunnel_id, hostname, origin_url)
        )

    async def create_dns_record(
        self, zone_id: str, hostname: str, tunnel_id: str
    ) -> dict[str, Any]:
        await self._call("create_dns_record", (zone_id, hostname, tunnel_id))
        self.remote_dns_record = {
            "id": DNS_ID,
            "name": hostname,
            "type": "CNAME",
            "content": f"{tunnel_id}.cfargotunnel.com",
            "comment": "Managed by lnSwitchboard",
        }
        if self.lose_dns_response:
            raise RuntimeError("DNS response lost")
        return self.remote_dns_record

    async def get_tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        await self._call("get_tunnel_token", (account_id, tunnel_id))
        return CONNECTOR_TOKEN

    async def disable_tunnel(self, account_id: str, tunnel_id: str) -> None:
        await self._call("disable_tunnel", (account_id, tunnel_id))

    async def get_dns_record(
        self, zone_id: str, record_id: str
    ) -> dict[str, Any] | None:
        await self._call("get_dns_record", (zone_id, record_id))
        if self.dns_record_override is not None:
            return self.dns_record_override
        return {
            "id": record_id,
            "type": "CNAME",
            "name": "pay.example.com",
            "content": f"{TUNNEL_ID}.cfargotunnel.com",
            "comment": "Managed by lnSwitchboard",
        }

    async def list_tunnel_connections(
        self, account_id: str, tunnel_id: str
    ) -> list[dict[str, Any]]:
        await self._call("list_tunnel_connections", (account_id, tunnel_id))
        return [{"id": "connector-1", "is_pending_reconnect": False}]

    async def delete_dns_record(self, zone_id: str, record_id: str) -> None:
        await self._call("delete_dns_record", (zone_id, record_id))
        self.remote_dns_record = None

    async def cleanup_tunnel_connections(self, account_id: str, tunnel_id: str) -> None:
        await self._call("cleanup_tunnel_connections", (account_id, tunnel_id))

    async def delete_tunnel(self, account_id: str, tunnel_id: str) -> None:
        await self._call("delete_tunnel", (account_id, tunnel_id))
        self.remote_tunnel = None


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def service_parts(tmp_path: Path):
    store = ConnectionStore(tmp_path / "connections.db")
    secrets = ConnectionSecretStore(
        tmp_path / "connections.db", tmp_path / "connection.key"
    )
    client = FakeCloudflareClient()
    token_path = tmp_path / "cloudflared" / "tunnel.token"
    service = CloudflareService(
        store=store,
        secrets=secrets,
        client_factory=lambda token: client,
        connector_enabled=True,
        token_path=token_path,
        origin_url="http://app:21212",
        token_gid=os.getgid(),
    )
    return service, store, secrets, client, token_path


async def _authorize(service: CloudflareService) -> str:
    result = await service.authorize(API_TOKEN)
    return str(result["authorization_id"])


def _stored_authorization(
    secrets: ConnectionSecretStore, authorization_id: str
) -> dict[str, Any] | None:
    return secrets.get(f"cloudflare-authorization:{authorization_id}")


@pytest.mark.anyio
async def test_authorize_validates_and_encrypts_token_without_returning_it(
    service_parts,
) -> None:
    service, _store, secrets, client, _token_path = service_parts

    result = await service.authorize(API_TOKEN)

    authorization_id = str(result.pop("authorization_id"))
    assert result == {
        "accounts": [
            {
                "id": ACCOUNT_ID,
                "name": "Example Account",
                "zones": [{"id": ZONE_ID, "name": "example.com"}],
            }
        ]
    }
    stored = secrets.get(f"cloudflare-authorization:{authorization_id}")
    assert stored is not None
    assert stored["api_token"] == API_TOKEN
    assert API_TOKEN not in repr(result)
    assert [name for name, _ in client.calls] == [
        "verify_token",
        "list_accounts",
        "list_zones",
    ]


@pytest.mark.anyio
async def test_provision_uses_only_public_listener_and_hands_off_connector_token(
    service_parts,
) -> None:
    service, store, secrets, client, token_path = service_parts
    authorization_id = await _authorize(service)

    result = await service.provision(
        authorization_id=authorization_id,
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        hostname="Pay.Example.com.",
    )

    assert result.provider == "cloudflare"
    assert result.external_id == TUNNEL_ID
    assert result.status == "provisioning"
    assert result.domains[0].hostname == "pay.example.com"
    assert result.domains[0].status == "pending"
    assert result.domains[0].external_id == DNS_ID
    assert result.public_metadata["origin"] == "http://app:21212"
    assert "22121" not in repr(result)
    assert CONNECTOR_TOKEN not in repr(result)
    assert token_path.read_text(encoding="utf-8") == CONNECTOR_TOKEN
    assert token_path.stat().st_mode & 0o777 == 0o640
    assert secrets.get(result.id) == {"api_token": API_TOKEN}
    assert _stored_authorization(secrets, authorization_id) is None
    assert store.get_connection(result.id) == result
    configure_call = next(
        value for name, value in client.calls if name == "configure_tunnel"
    )
    assert configure_call == (
        ACCOUNT_ID,
        TUNNEL_ID,
        "pay.example.com",
        "http://app:21212",
    )


@pytest.mark.anyio
@pytest.mark.parametrize("lost_response", ["tunnel", "dns"])
async def test_provision_reconciles_remote_success_when_response_is_lost(
    service_parts, lost_response: str
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    authorization_id = await _authorize(service)
    client.lose_tunnel_response = lost_response == "tunnel"
    client.lose_dns_response = lost_response == "dns"

    connection = await service.provision(
        authorization_id=authorization_id,
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        hostname="pay.example.com",
    )

    assert connection.external_id == TUNNEL_ID
    assert connection.domains[0].external_id == DNS_ID
    assert store.list_provisioning_journals("cloudflare") == []


@pytest.mark.anyio
async def test_startup_recovery_cleans_remote_resources_from_durable_journal(
    service_parts,
) -> None:
    service, store, secrets, client, token_path = service_parts
    authorization_id = await _authorize(service)
    authorization_owner = f"cloudflare-authorization:{authorization_id}"
    journal = store.create_provisioning_journal(
        provider="cloudflare",
        authorization_owner=authorization_owner,
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        hostname="pay.example.com",
        resource_name="lnswitchboard-pay-example-com-crashed",
    )
    client.remote_tunnel = {
        "id": TUNNEL_ID,
        "name": journal.resource_name,
        "status": "inactive",
    }
    client.remote_dns_record = {
        "id": DNS_ID,
        "name": "pay.example.com",
        "type": "CNAME",
        "content": f"{TUNNEL_ID}.cfargotunnel.com",
        "comment": "Managed by lnSwitchboard",
    }
    store.update_provisioning_journal(
        journal.id,
        external_id=TUNNEL_ID,
        domain_external_id=DNS_ID,
        phase="dns_created",
    )

    await service.recover_incomplete_provisioning()

    assert store.list_provisioning_journals("cloudflare") == []
    assert client.remote_tunnel is None
    assert client.remote_dns_record is None
    assert secrets.get(authorization_owner) is not None
    assert not token_path.exists()


@pytest.mark.anyio
async def test_startup_recovery_preserves_journal_on_transient_lookup_failure(
    service_parts,
) -> None:
    service, store, secrets, client, _token_path = service_parts
    authorization_id = await _authorize(service)
    authorization_owner = f"cloudflare-authorization:{authorization_id}"
    journal = store.create_provisioning_journal(
        provider="cloudflare",
        authorization_owner=authorization_owner,
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        hostname="pay.example.com",
        resource_name="lnswitchboard-pay-example-com-crashed",
    )
    client.remote_tunnel = {
        "id": TUNNEL_ID,
        "name": journal.resource_name,
        "status": "inactive",
    }
    client.fail_tunnel_lookup = True

    await service.recover_incomplete_provisioning()

    [preserved] = store.list_provisioning_journals("cloudflare")
    assert preserved.id == journal.id
    assert preserved.phase == "cleanup_pending"
    assert preserved.last_error == "recovery_failed"
    assert client.remote_tunnel is not None
    assert secrets.get(authorization_owner) is not None


@pytest.mark.anyio
async def test_provision_refuses_to_adopt_or_replace_existing_dns(
    service_parts,
) -> None:
    service, store, _secrets, client, token_path = service_parts
    authorization_id = await _authorize(service)
    client.dns_records = [{"id": "existing", "type": "A", "name": "pay.example.com"}]

    with pytest.raises(CloudflareConflictError, match="already exists"):
        await service.provision(
            authorization_id=authorization_id,
            account_id=ACCOUNT_ID,
            zone_id=ZONE_ID,
            hostname="pay.example.com",
        )

    assert not store.list_connections()
    assert not token_path.exists()
    assert "create_tunnel" not in [name for name, _ in client.calls]


@pytest.mark.anyio
async def test_provision_compensates_remote_resources_when_token_handoff_fails(
    service_parts,
) -> None:
    service, store, secrets, client, token_path = service_parts
    authorization_id = await _authorize(service)
    client.fail_on = "get_tunnel_token"

    with pytest.raises(RuntimeError, match="forced get_tunnel_token failure"):
        await service.provision(
            authorization_id=authorization_id,
            account_id=ACCOUNT_ID,
            zone_id=ZONE_ID,
            hostname="pay.example.com",
        )

    names = [name for name, _ in client.calls]
    assert names[-3:] == [
        "delete_dns_record",
        "cleanup_tunnel_connections",
        "delete_tunnel",
    ]
    assert not store.list_connections()
    stored = _stored_authorization(secrets, authorization_id)
    assert stored is not None and stored["api_token"] == API_TOKEN
    assert not token_path.exists()


@pytest.mark.anyio
async def test_failed_remote_rollback_keeps_durable_cleanup_record(
    service_parts,
) -> None:
    service, store, secrets, client, token_path = service_parts
    authorization_id = await _authorize(service)
    client.fail_on = "get_tunnel_token"
    client.also_fail_on.add("delete_dns_record")

    with pytest.raises(CloudflareServiceError, match="cleanup is incomplete"):
        await service.provision(
            authorization_id=authorization_id,
            account_id=ACCOUNT_ID,
            zone_id=ZONE_ID,
            hostname="pay.example.com",
        )

    [recovery] = store.list_connections()
    assert recovery.status == "error"
    assert recovery.external_id == TUNNEL_ID
    assert recovery.domains[0].external_id == DNS_ID
    assert recovery.public_metadata["cleanup_pending"] == ["dns_record"]
    assert "recovery_authorization_id" not in recovery.public_metadata
    assert secrets.get(recovery.id) == {"api_token": API_TOKEN}
    assert _stored_authorization(secrets, authorization_id) is None
    assert not token_path.exists()


@pytest.mark.anyio
async def test_provision_compensates_when_local_persistence_fails(
    service_parts, monkeypatch
) -> None:
    service, store, secrets, client, token_path = service_parts
    authorization_id = await _authorize(service)

    def fail_persistence(**_kwargs):
        raise OSError("database unavailable")

    monkeypatch.setattr(store, "upsert_connection", fail_persistence)

    with pytest.raises(OSError, match="database unavailable"):
        await service.provision(
            authorization_id=authorization_id,
            account_id=ACCOUNT_ID,
            zone_id=ZONE_ID,
            hostname="pay.example.com",
        )

    assert [name for name, _ in client.calls][-3:] == [
        "delete_dns_record",
        "cleanup_tunnel_connections",
        "delete_tunnel",
    ]
    stored = _stored_authorization(secrets, authorization_id)
    assert stored is not None and stored["api_token"] == API_TOKEN
    assert not token_path.exists()


@pytest.mark.anyio
async def test_disconnect_removes_local_token_before_owned_remote_resources(
    service_parts,
) -> None:
    service, store, secrets, client, token_path = service_parts
    authorization_id = await _authorize(service)
    connection = await service.provision(
        authorization_id=authorization_id,
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        hostname="pay.example.com",
    )
    client.calls.clear()

    removed = await service.disconnect(connection.id)

    assert removed is True
    assert not token_path.exists()
    assert [name for name, _ in client.calls] == [
        "get_dns_record",
        "disable_tunnel",
        "delete_dns_record",
        "cleanup_tunnel_connections",
        "delete_tunnel",
    ]
    assert store.get_connection(connection.id) is None
    assert secrets.get(connection.id) is None


@pytest.mark.anyio
async def test_disconnect_preserves_dns_record_when_ownership_marker_changed(
    service_parts,
) -> None:
    service, store, secrets, client, token_path = service_parts
    authorization_id = await _authorize(service)
    connection = await service.provision(
        authorization_id=authorization_id,
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        hostname="pay.example.com",
    )
    client.calls.clear()
    client.dns_record_override = {
        "id": DNS_ID,
        "type": "A",
        "name": "pay.example.com",
        "content": "192.0.2.10",
    }

    with pytest.raises(CloudflareConflictError, match="no longer owned"):
        await service.disconnect(connection.id)

    assert "delete_dns_record" not in [name for name, _ in client.calls]
    assert store.get_connection(connection.id) is not None
    assert secrets.get(connection.id) == {"api_token": API_TOKEN}
    assert token_path.exists()


@pytest.mark.anyio
async def test_disabled_connector_rejects_authorization(tmp_path: Path) -> None:
    store = ConnectionStore(tmp_path / "connections.db")
    secrets = ConnectionSecretStore(
        tmp_path / "connections.db", tmp_path / "connection.key"
    )
    service = CloudflareService(
        store=store,
        secrets=secrets,
        client_factory=lambda _token: FakeCloudflareClient(),
        connector_enabled=False,
        token_path=tmp_path / "token",
        origin_url="http://app:21212",
        token_gid=os.getgid(),
    )

    with pytest.raises(CloudflareUnavailableError):
        await service.authorize(API_TOKEN)


def test_service_rejects_admin_listener_as_tunnel_origin(tmp_path: Path) -> None:
    store = ConnectionStore(tmp_path / "connections.db")
    secrets = ConnectionSecretStore(
        tmp_path / "connections.db", tmp_path / "connection.key"
    )

    with pytest.raises(CloudflareValidationError, match="public port 21212"):
        CloudflareService(
            store=store,
            secrets=secrets,
            client_factory=lambda _token: FakeCloudflareClient(),
            connector_enabled=True,
            token_path=tmp_path / "token",
            origin_url="http://app:22121",
            token_gid=os.getgid(),
        )


@pytest.mark.anyio
async def test_status_promotes_only_after_cloudflare_reports_live_connector(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    authorization_id = await _authorize(service)
    connection = await service.provision(
        authorization_id=authorization_id,
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        hostname="pay.example.com",
    )

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "connected"
    assert refreshed.domains[0].status == "active"
    assert refreshed.public_metadata["connector_count"] == 1


@pytest.mark.anyio
async def test_concurrent_provisioning_creates_only_one_remote_tunnel(
    service_parts,
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    first_authorization = await _authorize(service)
    second_authorization = await _authorize(service)

    results = await asyncio.gather(
        service.provision(
            authorization_id=first_authorization,
            account_id=ACCOUNT_ID,
            zone_id=ZONE_ID,
            hostname="pay.example.com",
        ),
        service.provision(
            authorization_id=second_authorization,
            account_id=ACCOUNT_ID,
            zone_id=ZONE_ID,
            hostname="pay.example.com",
        ),
        return_exceptions=True,
    )

    assert len(store.list_connections()) == 1
    assert sum(name == "create_tunnel" for name, _ in client.calls) == 1
    assert sum(isinstance(result, CloudflareConflictError) for result in results) == 1
