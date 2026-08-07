"""Cloudflare Tunnel onboarding and lifecycle orchestration."""

from __future__ import annotations

import asyncio

import os
import re
import secrets as random_secrets
import time
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from .connection_secret_store import ConnectionSecretStore
from .connection_store import ConnectionStore, ProviderConnection

_AUTHORIZATION_PREFIX = "cloudflare-authorization:"
_AUTHORIZATION_ID = re.compile(r"^[A-Za-z0-9_-]{32}$")
_AUTHORIZATION_TTL_SECONDS = 15 * 60
_RESOURCE_ID = re.compile(r"^[a-fA-F0-9]{32}$")


class CloudflareServiceError(RuntimeError):
    pass


class CloudflareUnavailableError(CloudflareServiceError):
    pass


class CloudflareConflictError(CloudflareServiceError):
    pass


class CloudflareValidationError(CloudflareServiceError):
    pass


class CloudflareNotFoundError(CloudflareServiceError):
    pass


class CloudflareClientProtocol(Protocol):
    async def verify_token(self) -> None: ...
    async def list_accounts(self) -> list[dict[str, Any]]: ...
    async def list_zones(self, account_id: str) -> list[dict[str, Any]]: ...
    async def get_zone(self, zone_id: str) -> dict[str, Any]: ...
    async def list_dns_records(
        self, zone_id: str, hostname: str
    ) -> list[dict[str, Any]]: ...
    async def create_tunnel(self, account_id: str, name: str) -> dict[str, Any]: ...
    async def find_tunnel_by_name(
        self, account_id: str, name: str
    ) -> dict[str, Any] | None: ...
    async def configure_tunnel(
        self,
        account_id: str,
        tunnel_id: str,
        hostname: str,
        origin_url: str,
    ) -> None: ...
    async def create_dns_record(
        self, zone_id: str, hostname: str, tunnel_id: str
    ) -> dict[str, Any]: ...
    async def get_tunnel_token(self, account_id: str, tunnel_id: str) -> str: ...
    async def disable_tunnel(self, account_id: str, tunnel_id: str) -> None: ...
    async def get_dns_record(
        self, zone_id: str, record_id: str
    ) -> dict[str, Any] | None: ...
    async def list_tunnel_connections(
        self, account_id: str, tunnel_id: str
    ) -> list[dict[str, Any]]: ...
    async def delete_dns_record(self, zone_id: str, record_id: str) -> None: ...
    async def cleanup_tunnel_connections(
        self, account_id: str, tunnel_id: str
    ) -> None: ...
    async def delete_tunnel(self, account_id: str, tunnel_id: str) -> None: ...


class CloudflareService:
    def __init__(
        self,
        *,
        store: ConnectionStore,
        secrets: ConnectionSecretStore,
        client_factory: Callable[[str], CloudflareClientProtocol],
        connector_enabled: bool,
        token_path: Path,
        origin_url: str,
        token_gid: int,
    ) -> None:
        self.store = store
        self.secrets = secrets
        self.client_factory = client_factory
        self.connector_enabled = connector_enabled
        self.token_path = Path(token_path)
        self.origin_url = self._validate_origin_url(origin_url)
        self.token_gid = token_gid

        self._provision_lock = asyncio.Lock()

    def _require_connector(self) -> None:
        if not self.connector_enabled:
            raise CloudflareUnavailableError("Cloudflare connector is not installed")

    @staticmethod
    def _normalize_resource_id(value: str, label: str) -> str:
        normalized = value.strip()
        if not _RESOURCE_ID.fullmatch(normalized):
            raise CloudflareValidationError(f"{label} is invalid")
        return normalized

    @staticmethod
    def _normalize_hostname(value: str) -> str:
        hostname = value.strip().lower().rstrip(".")
        if not hostname or ":" in hostname or "*" in hostname or len(hostname) > 253:
            raise CloudflareValidationError("hostname is invalid")
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise CloudflareValidationError("hostname is invalid") from exc
        labels = ascii_hostname.split(".")
        if len(labels) < 2 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels
        ):
            raise CloudflareValidationError("hostname is invalid")
        return ascii_hostname

    @staticmethod
    def _validate_origin_url(value: str) -> str:
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme != "http"
            or not parsed.hostname
            or parsed.port != 21212
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise CloudflareValidationError(
                "Cloudflare origin must be an HTTP service on public port 21212"
            )
        return normalized

    async def authorize(self, api_token: str) -> dict[str, Any]:
        self._require_connector()
        token = api_token.strip()
        if not token:
            raise CloudflareValidationError("Cloudflare API token is required")
        client = self.client_factory(token)
        await client.verify_token()
        discovered = await self._discover_accounts(client)
        authorization_id = random_secrets.token_urlsafe(24)
        self.secrets.set(
            f"{_AUTHORIZATION_PREFIX}{authorization_id}",
            {
                "api_token": token,
                "created_at": time.time(),
                "accounts": discovered,
            },
        )
        return {"authorization_id": authorization_id, "accounts": discovered}

    def get_authorization(self, authorization_id: str) -> dict[str, Any]:
        owner_id, payload = self._authorization_payload(authorization_id)
        accounts = payload.get("accounts")
        if not isinstance(accounts, list):
            self.secrets.delete(owner_id)
            raise CloudflareValidationError("Cloudflare authorization is invalid")
        return {"accounts": accounts}

    def cancel_authorization(self, authorization_id: str) -> bool:
        return self.secrets.delete(f"{_AUTHORIZATION_PREFIX}{authorization_id}")

    async def _discover_accounts(
        self, client: CloudflareClientProtocol
    ) -> list[dict[str, Any]]:
        discovered: list[dict[str, Any]] = []
        for account in await client.list_accounts():
            account_id = str(account.get("id", ""))
            if not _RESOURCE_ID.fullmatch(account_id):
                continue
            zones = await client.list_zones(account_id)
            discovered.append(
                {
                    "id": account_id,
                    "name": str(account.get("name", "")),
                    "zones": [
                        {"id": str(zone["id"]), "name": str(zone["name"])}
                        for zone in zones
                        if _RESOURCE_ID.fullmatch(str(zone.get("id", "")))
                        and zone.get("name")
                    ],
                }
            )
        return discovered

    def _authorization_payload(
        self, authorization_id: str
    ) -> tuple[str, dict[str, Any]]:
        if not _AUTHORIZATION_ID.fullmatch(authorization_id):
            raise CloudflareValidationError("Cloudflare authorization is invalid")
        owner_id = f"{_AUTHORIZATION_PREFIX}{authorization_id}"
        payload = self.secrets.get(owner_id)
        created_at = payload.get("created_at") if payload else None
        if (
            payload is None
            or not isinstance(created_at, (int, float))
            or time.time() - created_at > _AUTHORIZATION_TTL_SECONDS
        ):
            self.secrets.delete(owner_id)
            raise CloudflareValidationError("Authorize Cloudflare before provisioning")
        return owner_id, payload

    async def _pending_client(
        self, authorization_id: str
    ) -> tuple[str, dict[str, Any], CloudflareClientProtocol]:
        owner_id, payload = self._authorization_payload(authorization_id)
        client = await self._client_from_payload(owner_id, payload)
        return owner_id, payload, client

    async def provision(
        self,
        *,
        authorization_id: str,
        account_id: str,
        zone_id: str,
        hostname: str,
    ) -> ProviderConnection:
        async with self._provision_lock:
            return await self._provision_locked(
                authorization_id=authorization_id,
                account_id=account_id,
                zone_id=zone_id,
                hostname=hostname,
            )

    async def _provision_locked(
        self,
        *,
        authorization_id: str,
        account_id: str,
        zone_id: str,
        hostname: str,
    ) -> ProviderConnection:
        self._require_connector()
        if any(item.provider == "cloudflare" for item in self.store.list_connections()):
            raise CloudflareConflictError("A Cloudflare tunnel is already connected")
        account_id = self._normalize_resource_id(account_id, "account ID")
        zone_id = self._normalize_resource_id(zone_id, "zone ID")
        hostname = self._normalize_hostname(hostname)
        authorization_owner, credential_payload, client = await self._pending_client(
            authorization_id
        )

        zone = await client.get_zone(zone_id)
        zone_name = self._normalize_hostname(str(zone.get("name", "")))
        zone_account = zone.get("account")
        zone_account_id = (
            str(zone_account.get("id", "")) if isinstance(zone_account, dict) else ""
        )
        if zone_account_id != account_id:
            raise CloudflareValidationError(
                "zone does not belong to the selected account"
            )
        if hostname != zone_name and not hostname.endswith(f".{zone_name}"):
            raise CloudflareValidationError("hostname is outside the selected zone")
        if await client.list_dns_records(zone_id, hostname):
            raise CloudflareConflictError(
                "A DNS record already exists for this hostname; lnSwitchboard will not replace it"
            )

        tunnel_id: str | None = None
        dns_record_id: str | None = None
        dns_attempted = False
        connection_id: str | None = None
        tunnel_name = self._tunnel_name(hostname)
        journal = self.store.create_provisioning_journal(
            provider="cloudflare",
            authorization_owner=authorization_owner,
            account_id=account_id,
            zone_id=zone_id,
            hostname=hostname,
            resource_name=tunnel_name,
        )
        try:
            tunnel_id = await self._create_or_find_tunnel(
                client, account_id, tunnel_name
            )
            self.store.update_provisioning_journal(
                journal.id, external_id=tunnel_id, phase="tunnel_created"
            )
            await client.configure_tunnel(
                account_id,
                tunnel_id,
                hostname,
                self.origin_url,
            )
            dns_attempted = True
            dns_record_id = await self._create_or_find_dns_record(
                client, zone_id, hostname, tunnel_id
            )
            self.store.update_provisioning_journal(
                journal.id,
                domain_external_id=dns_record_id,
                phase="dns_created",
            )
            connector_token = await client.get_tunnel_token(account_id, tunnel_id)
            self._write_connector_token(connector_token)
            self.store.update_provisioning_journal(journal.id, phase="token_written")

            connection = self.store.upsert_connection(
                provider="cloudflare",
                external_id=tunnel_id,
                label="Cloudflare Tunnel",
                status="provisioning",
                account_id=account_id,
                public_metadata={
                    "zone_id": zone_id,
                    "zone_name": zone_name,
                    "tunnel_name": tunnel_name,
                    "origin": self.origin_url,
                },
            )
            connection_id = connection.id
            self.store.replace_domains(
                connection.id,
                [
                    {
                        "hostname": hostname,
                        "status": "pending",
                        "external_id": dns_record_id,
                        "zone_id": zone_id,
                    }
                ],
            )
            self.secrets.set(
                connection.id, {"api_token": str(credential_payload["api_token"])}
            )
            self.secrets.delete(authorization_owner)
            self.store.update_provisioning_journal(journal.id, phase="committed")
            self.store.delete_provisioning_journal(journal.id)
            refreshed = self.store.get_connection(connection.id)
            assert refreshed is not None
            return refreshed
        except Exception:
            journal = self.store.get_provisioning_journal(journal.id) or journal
            if tunnel_id is None:
                tunnel_id = await self._find_tunnel_id(
                    client, account_id, journal.resource_name
                )
            if tunnel_id is not None and dns_record_id is None:
                dns_record_id = await self._find_owned_dns_record_id(
                    client, zone_id, hostname, tunnel_id
                )
            try:
                self._remove_connector_token()
            except OSError:
                pass
            if connection_id is not None:
                try:
                    self.secrets.delete(connection_id)
                except Exception:
                    pass
                try:
                    self.store.delete_connection(connection_id)
                except Exception:
                    pass
            cleanup_failures: list[str] = []
            if tunnel_id is not None:
                cleanup_failures = await self._best_effort_cleanup(
                    client,
                    account_id=account_id,
                    tunnel_id=tunnel_id,
                    zone_id=zone_id,
                    dns_record_id=dns_record_id,
                )
            if cleanup_failures and tunnel_id is not None:
                self.store.update_provisioning_journal(
                    journal.id,
                    external_id=tunnel_id,
                    domain_external_id=dns_record_id,
                    phase="cleanup_pending",
                    last_error=",".join(cleanup_failures),
                )
                try:
                    recovery = self.store.upsert_connection(
                        provider="cloudflare",
                        external_id=tunnel_id,
                        label="Cloudflare Tunnel",
                        status="error",
                        account_id=account_id,
                        public_metadata={
                            "zone_id": zone_id,
                            "zone_name": zone_name,
                            "tunnel_name": tunnel_name,
                            "origin": self.origin_url,
                            "cleanup_pending": cleanup_failures,
                        },
                        last_error="Provisioning failed and Cloudflare cleanup is incomplete",
                    )
                    if dns_record_id:
                        self.store.replace_domains(
                            recovery.id,
                            [
                                {
                                    "hostname": hostname,
                                    "status": "error",
                                    "external_id": dns_record_id,
                                    "zone_id": zone_id,
                                    "last_error": "Cloudflare cleanup is incomplete",
                                }
                            ],
                        )
                    self.secrets.set(
                        recovery.id,
                        {"api_token": str(credential_payload["api_token"])},
                    )
                    self.secrets.delete(authorization_owner)
                except Exception as recovery_error:
                    raise CloudflareServiceError(
                        "Provisioning failed and a durable recovery record could not be written"
                    ) from recovery_error
                raise CloudflareServiceError(
                    "Provisioning failed and Cloudflare cleanup is incomplete"
                )
            if tunnel_id is not None and not (dns_attempted and dns_record_id is None):
                self.store.delete_provisioning_journal(journal.id)
            raise

    async def refresh_status(self, connection_id: str) -> ProviderConnection:
        connection = self._require_connection(connection_id)
        if connection.public_metadata.get("cleanup_pending"):
            return connection
        client = await self._connection_client(connection_id)
        remote_connections = await client.list_tunnel_connections(
            str(connection.account_id), connection.external_id
        )
        active = any(
            not item.get("is_pending_reconnect", False) for item in remote_connections
        )
        if active:
            status = "connected"
            domain_status = "active"
        elif connection.status == "connected":
            status = "degraded"
            domain_status = "error"
        else:
            status = "provisioning"
            domain_status = "pending"
        metadata = dict(connection.public_metadata)
        metadata["connector_count"] = len(remote_connections)
        updated = self.store.upsert_connection(
            provider="cloudflare",
            external_id=connection.external_id,
            label=connection.label,
            status=status,
            account_id=connection.account_id,
            public_metadata=metadata,
        )
        self.store.replace_domains(
            updated.id,
            [
                {
                    "hostname": domain.hostname,
                    "status": domain_status,
                    "external_id": domain.external_id,
                    "zone_id": domain.zone_id,
                }
                for domain in connection.domains
            ],
        )
        result = self.store.get_connection(updated.id)
        assert result is not None
        return result

    async def disconnect(self, connection_id: str) -> bool:
        connection = self._require_connection(connection_id)
        client = await self._connection_client(connection_id)
        zone_id = str(connection.public_metadata.get("zone_id", ""))
        dns_record_id = (
            connection.domains[0].external_id if connection.domains else None
        )
        record: dict[str, Any] | None = None
        try:
            if zone_id and dns_record_id:
                record = await client.get_dns_record(zone_id, dns_record_id)
                if record is not None and not self._owns_dns_record(connection, record):
                    raise CloudflareConflictError(
                        "The DNS record is no longer owned by lnSwitchboard and was preserved"
                    )
            await client.disable_tunnel(
                str(connection.account_id), connection.external_id
            )
            self._remove_connector_token()
            if zone_id and dns_record_id:
                if record is not None:
                    await client.delete_dns_record(zone_id, dns_record_id)
            await client.cleanup_tunnel_connections(
                str(connection.account_id), connection.external_id
            )
            await client.delete_tunnel(
                str(connection.account_id), connection.external_id
            )
        except Exception:
            self.store.upsert_connection(
                provider="cloudflare",
                external_id=connection.external_id,
                label=connection.label,
                status="error",
                account_id=connection.account_id,
                public_metadata=connection.public_metadata,
                last_error="Cloudflare resource cleanup failed; retry disconnect",
            )
            raise
        self.secrets.delete(connection.id)
        return self.store.delete_connection(connection.id)

    @staticmethod
    def _owns_dns_record(
        connection: ProviderConnection, record: dict[str, Any]
    ) -> bool:
        if not connection.domains:
            return False
        domain = connection.domains[0]
        return (
            record.get("id") == domain.external_id
            and str(record.get("type", "")).upper() == "CNAME"
            and str(record.get("name", "")).lower().rstrip(".") == domain.hostname
            and str(record.get("content", "")).lower().rstrip(".")
            == f"{connection.external_id}.cfargotunnel.com"
            and record.get("comment") == "Managed by lnSwitchboard"
        )

    def _require_connection(self, connection_id: str) -> ProviderConnection:
        connection = self.store.get_connection(connection_id)
        if connection is None or connection.provider != "cloudflare":
            raise CloudflareNotFoundError("Cloudflare connection was not found")
        return connection

    async def _client_from_payload(
        self, owner_id: str, payload: dict[str, Any]
    ) -> CloudflareClientProtocol:
        del owner_id
        api_token = payload.get("api_token")
        if not isinstance(api_token, str) or not api_token:
            raise CloudflareServiceError("Cloudflare API token is unavailable")
        return self.client_factory(api_token)

    async def _connection_client(self, connection_id: str) -> CloudflareClientProtocol:
        self._require_connection(connection_id)
        payload = self.secrets.get(connection_id)
        if payload is None:
            raise CloudflareServiceError("Cloudflare authorization is unavailable")
        return await self._client_from_payload(connection_id, payload)

    async def recover_incomplete_provisioning(self) -> None:
        for journal in self.store.list_provisioning_journals("cloudflare"):
            if journal.phase == "committed":
                self.store.delete_provisioning_journal(journal.id)
                continue
            matching_connection = next(
                (
                    item
                    for item in self.store.list_connections()
                    if journal.external_id
                    and item.provider == "cloudflare"
                    and item.external_id == journal.external_id
                ),
                None,
            )
            if matching_connection is not None:
                if self.secrets.get(matching_connection.id) is not None:
                    self.store.delete_provisioning_journal(journal.id)
                    continue
                self.secrets.delete(matching_connection.id)
                self.store.delete_connection(matching_connection.id)
            try:
                self._remove_connector_token()
            except OSError:
                pass
            payload = self.secrets.get(journal.authorization_owner)
            if payload is None:
                self.store.update_provisioning_journal(
                    journal.id,
                    phase="cleanup_pending",
                    last_error="authorization_unavailable",
                )
                continue
            try:
                client = await self._client_from_payload(
                    journal.authorization_owner, payload
                )
                tunnel_id = journal.external_id or await self._find_tunnel_id(
                    client, journal.account_id, journal.resource_name
                )
                dns_record_id = journal.domain_external_id
                if tunnel_id and dns_record_id is None:
                    dns_record_id = await self._find_owned_dns_record_id(
                        client, journal.zone_id, journal.hostname, tunnel_id
                    )
                if tunnel_id is None:
                    self.store.delete_provisioning_journal(journal.id)
                    continue
                failures = await self._best_effort_cleanup(
                    client,
                    account_id=journal.account_id,
                    tunnel_id=tunnel_id,
                    zone_id=journal.zone_id,
                    dns_record_id=dns_record_id,
                )
                if failures:
                    self.store.update_provisioning_journal(
                        journal.id,
                        external_id=tunnel_id,
                        domain_external_id=dns_record_id,
                        phase="cleanup_pending",
                        last_error=",".join(failures),
                    )
                else:
                    self.store.delete_provisioning_journal(journal.id)
            except Exception:
                self.store.update_provisioning_journal(
                    journal.id,
                    phase="cleanup_pending",
                    last_error="recovery_failed",
                )

    async def _create_or_find_tunnel(
        self, client: CloudflareClientProtocol, account_id: str, name: str
    ) -> str:
        try:
            tunnel = await client.create_tunnel(account_id, name)
            tunnel_id = str(tunnel.get("id", ""))
            if tunnel_id:
                return tunnel_id
        except Exception:
            pass
        tunnel_id = await self._find_tunnel_id(client, account_id, name)
        if tunnel_id is None:
            raise CloudflareServiceError(
                "Cloudflare tunnel creation outcome could not be reconciled"
            )
        return tunnel_id

    async def _find_tunnel_id(
        self, client: CloudflareClientProtocol, account_id: str, name: str
    ) -> str | None:
        tunnel = await client.find_tunnel_by_name(account_id, name)
        if not isinstance(tunnel, dict):
            return None
        tunnel_id = str(tunnel.get("id", ""))
        return tunnel_id or None

    async def _create_or_find_dns_record(
        self,
        client: CloudflareClientProtocol,
        zone_id: str,
        hostname: str,
        tunnel_id: str,
    ) -> str:
        try:
            record = await client.create_dns_record(zone_id, hostname, tunnel_id)
            record_id = str(record.get("id", ""))
            if record_id:
                return record_id
        except Exception:
            pass
        record_id = await self._find_owned_dns_record_id(
            client, zone_id, hostname, tunnel_id
        )
        if record_id is None:
            raise CloudflareServiceError(
                "Cloudflare DNS creation outcome could not be reconciled"
            )
        return record_id

    @staticmethod
    async def _find_owned_dns_record_id(
        client: CloudflareClientProtocol,
        zone_id: str,
        hostname: str,
        tunnel_id: str,
    ) -> str | None:
        records = await client.list_dns_records(zone_id, hostname)
        target = f"{tunnel_id}.cfargotunnel.com"
        for record in records:
            if (
                str(record.get("type", "")).upper() == "CNAME"
                and str(record.get("name", "")).lower().rstrip(".") == hostname
                and str(record.get("content", "")).lower().rstrip(".") == target
                and record.get("comment") == "Managed by lnSwitchboard"
            ):
                record_id = str(record.get("id", ""))
                return record_id or None
        return None

    @staticmethod
    def _tunnel_name(hostname: str) -> str:
        base = re.sub(r"[^a-z0-9-]+", "-", hostname).strip("-")[:70]
        return f"lnswitchboard-{base}-{random_secrets.token_hex(4)}"

    def _write_connector_token(self, token: str) -> None:
        value = token.strip()
        if not value:
            raise CloudflareServiceError("Cloudflare did not return a connector token")
        parent = self.token_path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        os.chown(parent, -1, self.token_gid)
        os.chmod(parent, 0o750)
        temporary = (
            parent / f".{self.token_path.name}.{random_secrets.token_hex(8)}.tmp"
        )
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            os.fchown(descriptor, -1, self.token_gid)
            os.fchmod(descriptor, 0o640)
            os.write(descriptor, value.encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.token_path)

    def _remove_connector_token(self) -> None:
        try:
            self.token_path.unlink()
        except FileNotFoundError:
            pass

    @staticmethod
    async def _best_effort_cleanup(
        client: CloudflareClientProtocol,
        *,
        account_id: str,
        tunnel_id: str,
        zone_id: str,
        dns_record_id: str | None,
    ) -> list[str]:
        failures: list[str] = []
        if dns_record_id:
            try:
                await client.delete_dns_record(zone_id, dns_record_id)
            except Exception:
                failures.append("dns_record")
        try:
            await client.cleanup_tunnel_connections(account_id, tunnel_id)
        except Exception:
            failures.append("connector_connections")
        try:
            await client.delete_tunnel(account_id, tunnel_id)
        except Exception:
            failures.append("tunnel")
        return failures
