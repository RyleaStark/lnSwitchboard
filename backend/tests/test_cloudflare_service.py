from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from backend.app.cloudflare_client import CloudflareAPIError, CloudflareRollbackError
from backend.app.cloudflare_service import (
    CloudflareConflictError,
    CloudflareNotFoundError,
    CloudflareService,
    CloudflareServiceError,
    CloudflareUnavailableError,
    CloudflareValidationError,
)
from backend.app.connection_secret_store import ConnectionSecretStore
from backend.app.connection_store import ConnectionStore

ACCOUNT_ID = "a" * 32
ZONE_ID = "b" * 32
SECOND_ZONE_ID = "d" * 32
TUNNEL_ID = "11111111-2222-4333-8444-555555555555"
DNS_ID = "c" * 32
API_TOKEN = "cloudflare-api-token-secret"
CONNECTOR_TOKEN = "connector-token-secret"


@dataclass
class FakeCloudflareClient:
    dns_records: list[dict[str, Any]] = field(default_factory=list)
    route_valid: bool = True
    calls: list[tuple[str, Any]] = field(default_factory=list)
    create_dns_error: CloudflareAPIError | None = None
    configure_error: CloudflareAPIError | None = None
    restore_error: CloudflareAPIError | None = None
    tunnel_connections: list[dict[str, Any]] = field(default_factory=list)
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

    async def get_tunnel(self, account_id: str, tunnel_id: str) -> dict[str, Any] | None:
        await self._call("get_tunnel", (account_id, tunnel_id))
        return {"id": tunnel_id, "name": "operator-managed-tunnel"}

    async def get_zone(self, zone_id: str) -> dict[str, Any]:
        await self._call("get_zone", zone_id)
        return next(zone for zone in self.zones if zone["id"] == zone_id)

    async def list_dns_records(self, zone_id: str, hostname: str) -> list[dict[str, Any]]:
        await self._call("list_dns_records", (zone_id, hostname))
        return self.dns_records

    async def configure_tunnel(
        self, account_id: str, tunnel_id: str, hostname: str, origin_url: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        await self._call(
            "configure_tunnel", (account_id, tunnel_id, hostname, origin_url)
        )
        if self.configure_error is not None:
            raise self.configure_error
        original = {"ingress": [{"service": "http_status:404"}]}
        written = {
            "ingress": [
                {"hostname": hostname, "service": origin_url},
                {"service": "http_status:404"},
            ]
        }
        return original, written

    async def restore_tunnel_configuration(
        self,
        account_id: str,
        tunnel_id: str,
        original_config: dict[str, Any],
        written_config: dict[str, Any],
    ) -> None:
        await self._call(
            "restore_tunnel_configuration",
            (account_id, tunnel_id, original_config, written_config),
        )
        if self.restore_error is not None:
            raise self.restore_error

    async def create_dns_record(self, zone_id: str, hostname: str, tunnel_id: str) -> dict[str, Any]:
        await self._call("create_dns_record", (zone_id, hostname, tunnel_id))
        if self.create_dns_error is not None:
            raise self.create_dns_error
        return {"id": DNS_ID, "name": hostname, "type": "CNAME", "content": f"{tunnel_id}.cfargotunnel.com", "comment": "Managed by lnSwitchboard"}

    async def get_tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        await self._call("get_tunnel_token", (account_id, tunnel_id))
        return CONNECTOR_TOKEN

    async def list_tunnel_connections(self, account_id: str, tunnel_id: str) -> list[dict[str, Any]]:
        await self._call("list_tunnel_connections", (account_id, tunnel_id))
        return self.tunnel_connections

    async def get_dns_record(self, zone_id: str, record_id: str) -> dict[str, Any] | None:
        await self._call("get_dns_record", (zone_id, record_id))
        hostname = "example.net" if zone_id == SECOND_ZONE_ID else "example.com"
        return {"id": record_id, "type": "CNAME", "name": hostname, "content": f"{TUNNEL_ID}.cfargotunnel.com", "comment": "Managed by lnSwitchboard"}

    async def verify_tunnel_route(
        self,
        account_id: str,
        tunnel_id: str,
        hostname: str,
        origin_url: str,
    ) -> bool:
        assert account_id == ACCOUNT_ID
        assert tunnel_id == TUNNEL_ID
        assert hostname
        assert origin_url == "http://app:21212"
        return self.route_valid

    async def remove_tunnel_route(
        self,
        account_id: str,
        tunnel_id: str,
        hostname: str,
        origin_url: str,
    ) -> None:
        assert origin_url == "http://app:21212"
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
        external_id=TUNNEL_ID,
        label="Legacy Cloudflare Tunnel",
        status="provisioning",
        account_id=ACCOUNT_ID,
    )
    journal = store.create_provisioning_journal(
        provider="cloudflare",
        authorization_owner="legacy-authorization",
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
        resource_name="legacy-tunnel",
    )
    store.update_provisioning_journal(
        journal.id,
        external_id=TUNNEL_ID,
        domain_external_id=DNS_ID,
        phase="dns_created",
    )
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(CONNECTOR_TOKEN)
    orphan_owner = "12345678-1234-1234-1234-123456789abc"
    secrets.set(orphan_owner, {"api_token": "orphan"})
    expired_authorization = f"cloudflare-authorization:{'a' * 32}"
    live_authorization = f"cloudflare-authorization:{'b' * 32}"
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
    assert token_path.read_text() == CONNECTOR_TOKEN
    assert secrets.get(orphan_owner) is None
    assert secrets.get(expired_authorization) is None
    assert secrets.get(live_authorization) is not None
    assert client.calls == []


@pytest.mark.anyio
async def test_existing_tunnel_onboarding_validates_operator_ids_and_never_creates_a_tunnel(service_parts) -> None:
    service, store, secrets, client, token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(authorization_id=str(authorization["authorization_id"]), account_id=ACCOUNT_ID, tunnel_id=TUNNEL_ID, zone_id=ZONE_ID, hostname="example.com")
    assert connection.external_id == TUNNEL_ID
    assert token_path.read_text() == CONNECTOR_TOKEN
    assert secrets.get(connection.id) == {"api_token": API_TOKEN}
    assert store.list_provisioning_journals("cloudflare") == []
    assert [name for name, _ in client.calls] == ["verify_token", "get_tunnel", "list_accounts", "list_zones", "get_zone", "create_dns_record", "configure_tunnel", "get_tunnel_token"]


@pytest.mark.anyio
async def test_ambiguous_dns_creation_keeps_durable_disconnect_recovery(
    service_parts,
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.create_dns_error = CloudflareAPIError(503)
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)

    with pytest.raises(CloudflareAPIError):
        await service.provision(
            authorization_id=str(authorization["authorization_id"]),
            account_id=ACCOUNT_ID,
            tunnel_id=TUNNEL_ID,
            zone_id=ZONE_ID,
            hostname="example.com",
        )

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


@pytest.mark.anyio
async def test_provision_rolls_back_dns_and_ingress_when_token_fetch_fails(
    service_parts, monkeypatch
) -> None:
    service, store, _secrets, client, token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)

    async def fail_token(_account_id: str, _tunnel_id: str) -> str:
        raise CloudflareAPIError(502)

    monkeypatch.setattr(client, "get_tunnel_token", fail_token)
    with pytest.raises(CloudflareAPIError):
        await service.provision(
            authorization_id=str(authorization["authorization_id"]),
            account_id=ACCOUNT_ID,
            tunnel_id=TUNNEL_ID,
            zone_id=ZONE_ID,
            hostname="example.com",
        )

    assert not token_path.exists()
    assert store.list_connections() == []
    assert [name for name, _ in client.calls][-4:] == [
        "configure_tunnel",
        "get_dns_record",
        "delete_dns_record",
        "restore_tunnel_configuration",
    ]


@pytest.mark.anyio
async def test_initial_configuration_rollback_failure_persists_disconnect_retry(
    service_parts,
) -> None:
    service, store, secrets, client, _token_path = service_parts
    client.configure_error = CloudflareRollbackError(502)
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)

    with pytest.raises(CloudflareServiceError, match="operator review"):
        await service.provision(
            authorization_id=str(authorization["authorization_id"]),
            account_id=ACCOUNT_ID,
            tunnel_id=TUNNEL_ID,
            zone_id=ZONE_ID,
            hostname="example.com",
        )

    connections = store.list_connections()
    assert len(connections) == 1
    retained = connections[0]
    assert retained.status == "error"
    assert retained.public_metadata["cleanup_pending"] == [
        {
            "hostname": "example.com",
            "zone_id": ZONE_ID,
            "dns_record_id": DNS_ID,
            "route_cleanup_pending": True,
            "dns_cleanup_pending": False,
        }
    ]
    assert secrets.get(retained.id) == {"api_token": API_TOKEN}

    client.configure_error = None
    client.calls.clear()
    assert await service.disconnect(retained.id) is True
    assert ("remove_tunnel_route", (ACCOUNT_ID, TUNNEL_ID, "example.com")) in client.calls


@pytest.mark.anyio
async def test_existing_tunnel_onboarding_accepts_subdomain_in_selected_zone(service_parts) -> None:
    service, store, _secrets, _client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)

    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="ln.example.com",
    )

    stored = store.get_connection(connection.id)
    assert stored is not None
    assert stored.domains[0].hostname == "ln.example.com"


@pytest.mark.anyio
async def test_existing_tunnel_onboarding_rejects_hostname_outside_selected_zone(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)

    with pytest.raises(CloudflareValidationError, match="selected zone"):
        await service.provision(
            authorization_id=str(authorization["authorization_id"]),
            account_id=ACCOUNT_ID,
            tunnel_id=TUNNEL_ID,
            zone_id=ZONE_ID,
            hostname="example.com.attacker.test",
        )


@pytest.mark.anyio
async def test_existing_tunnel_onboarding_refuses_unknown_tunnel(service_parts, monkeypatch) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    async def missing(*_args: str) -> None:
        return None
    monkeypatch.setattr(client, "get_tunnel", missing)
    with pytest.raises(CloudflareNotFoundError):
        await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)


@pytest.mark.anyio
async def test_existing_tunnel_authorizes_when_account_enumeration_is_forbidden(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts

    async def forbidden_accounts() -> list[dict[str, Any]]:
        raise CloudflareAPIError(403)

    monkeypatch.setattr(client, "list_accounts", forbidden_accounts)
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)

    assert authorization["accounts"] == [
        {
            "id": ACCOUNT_ID,
            "name": "Selected Cloudflare account",
            "zones": [{"id": ZONE_ID, "name": "example.com"}],
        }
    ]


@pytest.mark.anyio
async def test_provision_adopts_existing_apex_dns_when_cloudflare_reports_duplicate(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.create_dns_error = CloudflareAPIError(400, [81053])
    client.dns_records = [
        {
            "id": "existing",
            "type": "CNAME",
            "name": "example.com",
            "content": f"{TUNNEL_ID}.cfargotunnel.com",
        }
    ]
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(authorization_id=str(authorization["authorization_id"]), account_id=ACCOUNT_ID, tunnel_id=TUNNEL_ID, zone_id=ZONE_ID, hostname="example.com")
    call_names = [name for name, _ in client.calls]
    assert "configure_tunnel" in call_names
    assert "create_dns_record" in call_names
    assert connection.public_metadata["dns_adopted"] is True
    refreshed = store.get_connection(connection.id)
    assert refreshed is not None and refreshed.domains[0].external_id is None

    client.calls.clear()
    assert await service.disconnect(connection.id) is True
    disconnect_calls = [name for name, _ in client.calls]
    assert disconnect_calls == ["list_dns_records", "remove_tunnel_route"]
    assert "delete_dns_record" not in disconnect_calls


@pytest.mark.anyio
async def test_disconnect_uses_legacy_connection_zone_for_owned_dns(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
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
async def test_refresh_marks_adopted_hostname_error_when_dns_moves_to_another_tunnel(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.create_dns_error = CloudflareAPIError(400, [81053])
    client.dns_records = [
        {
            "id": "existing",
            "type": "CNAME",
            "name": "example.com",
            "content": f"{TUNNEL_ID}.cfargotunnel.com",
        }
    ]
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    client.tunnel_connections = [{"is_pending_reconnect": False}]
    client.dns_records = [
        {
            "id": "existing",
            "type": "CNAME",
            "name": "example.com",
            "content": "99999999-8888-4777-8666-555555555555.cfargotunnel.com",
        }
    ]

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert refreshed.domains[0].status == "error"
    assert refreshed.domains[0].last_error == "Existing DNS points to a different tunnel"


@pytest.mark.anyio
async def test_refresh_recovers_owned_dns_id_from_persisted_pending_intent(
    service_parts,
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
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
    client.dns_records = [
        {
            "id": DNS_ID,
            "type": "CNAME",
            "name": "example.com",
            "content": f"{TUNNEL_ID}.cfargotunnel.com",
            "comment": "Managed by lnSwitchboard",
        }
    ]
    client.tunnel_connections = [{"is_pending_reconnect": False}]

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert refreshed.domains[0].external_id == DNS_ID
    assert refreshed.domains[0].status == "error"
    assert "provisioning was interrupted" in str(refreshed.domains[0].last_error)


@pytest.mark.anyio
async def test_refresh_marks_hostname_error_when_ingress_is_missing_or_shadowed(
    service_parts,
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    client.route_valid = False
    client.tunnel_connections = [{"is_pending_reconnect": False}]

    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert refreshed.domains[0].status == "error"
    assert refreshed.domains[0].last_error == (
        "Managed tunnel ingress is missing, retargeted, duplicated, or shadowed"
    )


@pytest.mark.anyio
async def test_refresh_marks_owned_hostname_error_when_dns_is_missing(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    client.tunnel_connections = [{"is_pending_reconnect": False}]

    async def missing_record(_zone_id: str, _record_id: str):
        return None

    monkeypatch.setattr(client, "get_dns_record", missing_record)
    refreshed = await service.refresh_status(connection.id)

    assert refreshed.status == "degraded"
    assert refreshed.domains[0].status == "error"
    assert refreshed.domains[0].last_error == "Managed DNS record is missing or no longer owned"


@pytest.mark.anyio
async def test_provision_rejects_adopted_dns_that_targets_another_tunnel(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.create_dns_error = CloudflareAPIError(400, [81053])
    client.dns_records = [
        {
            "id": "existing",
            "type": "CNAME",
            "name": "example.com",
            "content": "99999999-8888-4777-8666-555555555555.cfargotunnel.com",
        }
    ]
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)

    with pytest.raises(CloudflareConflictError, match="different tunnel"):
        await service.provision(
            authorization_id=str(authorization["authorization_id"]),
            account_id=ACCOUNT_ID,
            tunnel_id=TUNNEL_ID,
            zone_id=ZONE_ID,
            hostname="example.com",
        )

    assert [name for name, _ in client.calls][-2:] == [
        "create_dns_record",
        "list_dns_records",
    ]


@pytest.mark.anyio
async def test_provision_surfaces_cloudflare_rejection_of_dns_creation(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.create_dns_error = CloudflareAPIError(403, [9109])
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    with pytest.raises(CloudflareAPIError, match="9109"):
        await service.provision(authorization_id=str(authorization["authorization_id"]), account_id=ACCOUNT_ID, tunnel_id=TUNNEL_ID, zone_id=ZONE_ID, hostname="example.com")


@pytest.mark.anyio
async def test_existing_tunnel_onboarding_preserves_existing_dns(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.dns_records = [{"id": "existing", "type": "A"}]
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(authorization_id=str(authorization["authorization_id"]), account_id=ACCOUNT_ID, tunnel_id=TUNNEL_ID, zone_id=ZONE_ID, hostname="example.com")
    assert await service.disconnect(connection.id) is True
    deleted = [value for name, value in client.calls if name == "delete_dns_record"]
    assert all(record_id == DNS_ID for _zone_id, record_id in deleted)


@pytest.mark.anyio
async def test_disconnect_removes_only_owned_route_and_dns_record(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(authorization_id=str(authorization["authorization_id"]), account_id=ACCOUNT_ID, tunnel_id=TUNNEL_ID, zone_id=ZONE_ID, hostname="example.com")
    client.calls.clear()
    assert await service.disconnect(connection.id) is True
    assert [name for name, _ in client.calls] == ["get_dns_record", "remove_tunnel_route", "get_dns_record", "delete_dns_record"]
    assert store.get_connection(connection.id) is None


@pytest.mark.anyio
async def test_disconnect_preserves_dns_changed_after_initial_ownership_check(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    checks = 0

    async def changing_record(zone_id: str, record_id: str) -> dict[str, Any]:
        nonlocal checks
        checks += 1
        await client._call("get_dns_record", (zone_id, record_id))
        return {
            "id": record_id,
            "type": "CNAME",
            "name": "example.com",
            "content": f"{TUNNEL_ID}.cfargotunnel.com",
            "comment": "Managed by lnSwitchboard" if checks == 1 else "Operator changed",
        }

    monkeypatch.setattr(client, "get_dns_record", changing_record)
    client.calls.clear()
    with pytest.raises(CloudflareConflictError, match="changed during cleanup"):
        await service.disconnect(connection.id)

    assert "delete_dns_record" not in [name for name, _ in client.calls]


@pytest.mark.anyio
async def test_disconnect_preserves_api_secret_when_local_delete_fails(
    service_parts, monkeypatch
) -> None:
    service, store, secrets, _client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
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
async def test_add_domain_persists_intent_before_dns_mutation(
    service_parts, monkeypatch
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    create_dns_record = client.create_dns_record

    async def inspect_intent(zone_id: str, hostname: str, tunnel_id: str):
        pending = store.get_connection(connection.id)
        assert pending is not None
        intended = next(domain for domain in pending.domains if domain.hostname == hostname)
        assert intended.zone_id == zone_id
        assert intended.external_id is None
        return await create_dns_record(zone_id, hostname, tunnel_id)

    monkeypatch.setattr(client, "create_dns_record", inspect_intent)
    updated = await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")

    added = next(domain for domain in updated.domains if domain.hostname == "example.net")
    assert added.external_id == DNS_ID


@pytest.mark.anyio
async def test_add_domain_rolls_back_created_dns_and_routes_when_persistence_fails(
    service_parts, monkeypatch
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    client.calls.clear()

    def fail_persistence(*_args, **_kwargs) -> None:
        raise OSError("injected persistence failure")

    monkeypatch.setattr(store, "replace_domains", fail_persistence)
    with pytest.raises(OSError, match="injected persistence failure"):
        await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")

    assert [name for name, _ in client.calls] == ["get_zone"]


@pytest.mark.anyio
async def test_failed_route_rollback_is_persisted_for_disconnect_retry(
    service_parts,
) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    client.configure_error = CloudflareRollbackError(502)
    with pytest.raises(CloudflareRollbackError):
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
            "dns_cleanup_pending": False,
        }
    ]

    client.configure_error = None
    client.calls.clear()
    assert await service.disconnect(connection.id) is True
    route_calls = [
        value for name, value in client.calls if name == "remove_tunnel_route"
    ]
    assert (ACCOUNT_ID, TUNNEL_ID, "example.com") in route_calls
    assert (ACCOUNT_ID, TUNNEL_ID, "example.net") in route_calls


@pytest.mark.anyio
async def test_disconnect_waits_for_domain_lifecycle_lock(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )

    await service._provision_lock.acquire()
    task = asyncio.create_task(service.disconnect(connection.id))
    await asyncio.sleep(0)
    assert not task.done()
    service._provision_lock.release()
    assert await task is True


@pytest.mark.anyio
async def test_refresh_waits_for_domain_lifecycle_lock(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )

    await service._provision_lock.acquire()
    task = asyncio.create_task(service.refresh_status(connection.id))
    await asyncio.sleep(0)
    assert not task.done()
    service._provision_lock.release()
    assert (await task).id == connection.id


@pytest.mark.anyio
async def test_existing_connection_lists_authorized_zones_for_more_hostnames(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )

    assert await service.available_zones(connection.id) == [
        {"id": ZONE_ID, "name": "example.com"},
        {"id": SECOND_ZONE_ID, "name": "example.net"},
    ]


@pytest.mark.anyio
async def test_existing_connection_adds_subdomain_from_an_already_used_zone(service_parts) -> None:
    service, _store, _secrets, _client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )

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
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    client.calls.clear()

    updated = await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")

    assert [domain.hostname for domain in updated.domains] == ["example.com", "example.net"]
    assert [name for name, _ in client.calls] == [
        "get_zone",
        "create_dns_record",
        "configure_tunnel",
    ]
    client.calls.clear()

    remaining = await service.remove_domain(connection.id, "example.net")

    assert [domain.hostname for domain in remaining.domains] == ["example.com"]
    assert [name for name, _ in client.calls] == [
        "get_dns_record",
        "remove_tunnel_route",
        "get_dns_record",
        "delete_dns_record",
    ]
    stored = store.get_connection(connection.id)
    assert stored is not None
    assert [domain.hostname for domain in stored.domains] == ["example.com"]


@pytest.mark.anyio
async def test_remove_domain_preserves_dns_changed_after_route_cleanup(
    service_parts, monkeypatch
) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")
    checks = 0

    async def changing_record(zone_id: str, record_id: str) -> dict[str, Any]:
        nonlocal checks
        checks += 1
        await client._call("get_dns_record", (zone_id, record_id))
        return {
            "id": record_id,
            "type": "CNAME",
            "name": "example.net",
            "content": f"{TUNNEL_ID}.cfargotunnel.com",
            "comment": "Managed by lnSwitchboard" if checks == 1 else "Operator changed",
        }

    monkeypatch.setattr(client, "get_dns_record", changing_record)
    client.calls.clear()
    with pytest.raises(CloudflareConflictError, match="changed during cleanup"):
        await service.remove_domain(connection.id, "example.net")

    assert "delete_dns_record" not in [name for name, _ in client.calls]


@pytest.mark.anyio
async def test_remove_adopted_domain_preserves_dns(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    client.create_dns_error = CloudflareAPIError(400, [81053])
    client.dns_records = [
        {
            "id": "existing",
            "type": "CNAME",
            "name": "example.net",
            "content": f"{TUNNEL_ID}.cfargotunnel.com",
        }
    ]
    updated = await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")
    assert next(domain for domain in updated.domains if domain.zone_id == SECOND_ZONE_ID).external_id is None
    client.calls.clear()

    await service.remove_domain(connection.id, "example.net")

    assert [name for name, _ in client.calls] == [
        "list_dns_records",
        "remove_tunnel_route",
    ]


@pytest.mark.anyio
async def test_disconnect_cleans_up_every_connected_domain(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")
    client.calls.clear()

    assert await service.disconnect(connection.id) is True

    removed_hostnames = [
        value[2] for name, value in client.calls if name == "remove_tunnel_route"
    ]
    assert removed_hostnames == ["example.com", "example.net"]
    assert sum(name == "delete_dns_record" for name, _ in client.calls) == 2


@pytest.mark.anyio
async def test_add_domain_does_not_touch_routes_when_dns_is_rejected(service_parts) -> None:
    service, store, _secrets, client, _token_path = service_parts
    client.zones.append(
        {"id": SECOND_ZONE_ID, "name": "example.net", "account": {"id": ACCOUNT_ID}}
    )
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    client.calls.clear()
    client.create_dns_error = CloudflareAPIError(403, [9109])

    with pytest.raises(CloudflareAPIError):
        await service.add_domain(connection.id, SECOND_ZONE_ID, "example.net")

    assert [name for name, _ in client.calls] == [
        "get_zone",
        "create_dns_record",
        "list_dns_records",
    ]
    stored = store.get_connection(connection.id)
    assert stored is not None
    assert [domain.hostname for domain in stored.domains] == ["example.com"]


@pytest.mark.anyio
async def test_remove_domain_requires_disconnect_for_the_final_domain(service_parts) -> None:
    service, _store, _secrets, client, _token_path = service_parts
    authorization = await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
    connection = await service.provision(
        authorization_id=str(authorization["authorization_id"]),
        account_id=ACCOUNT_ID,
        tunnel_id=TUNNEL_ID,
        zone_id=ZONE_ID,
        hostname="example.com",
    )
    client.calls.clear()

    with pytest.raises(CloudflareConflictError, match="final domain"):
        await service.remove_domain(connection.id, "example.com")

    assert client.calls == []


@pytest.mark.anyio
async def test_disabled_connector_rejects_authorization(tmp_path: Path) -> None:
    service = CloudflareService(store=ConnectionStore(tmp_path / "db"), secrets=ConnectionSecretStore(tmp_path / "db", tmp_path / "key"), client_factory=lambda _token: FakeCloudflareClient(), connector_enabled=False, token_path=tmp_path / "token", origin_url="http://app:21212", token_gid=os.getgid())
    with pytest.raises(CloudflareUnavailableError):
        await service.authorize(API_TOKEN, ACCOUNT_ID, TUNNEL_ID)
