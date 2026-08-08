"""Cloudflare Tunnel onboarding and lifecycle orchestration."""

from __future__ import annotations

import asyncio

import os
import re
import secrets as random_secrets
import time
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from .connection_secret_store import ConnectionSecretStore
from .connection_store import ConnectedDomain, ConnectionStore, ProviderConnection
from .cloudflare_client import CloudflareAPIError, CloudflareRollbackError

_AUTHORIZATION_PREFIX = "cloudflare-authorization:"
_AUTHORIZATION_ID = re.compile(r"^[A-Za-z0-9_-]{32}$")
_AUTHORIZATION_TTL_SECONDS = 15 * 60
_RESOURCE_ID = re.compile(r"^[a-fA-F0-9]{32}$")
_TUNNEL_ID = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12})$")
_CONNECTION_OWNER_ID = re.compile(
    r"^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$", re.IGNORECASE
)


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
    async def get_tunnel(
        self, account_id: str, tunnel_id: str
    ) -> dict[str, Any] | None: ...
    async def get_zone(self, zone_id: str) -> dict[str, Any]: ...
    async def list_dns_records(
        self, zone_id: str, hostname: str
    ) -> list[dict[str, Any]]: ...

    async def configure_tunnel(
        self,
        account_id: str,
        tunnel_id: str,
        hostname: str,
        origin_url: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]: ...
    async def restore_tunnel_configuration(
        self,
        account_id: str,
        tunnel_id: str,
        original_config: dict[str, Any],
        written_config: dict[str, Any],
    ) -> None: ...
    async def create_dns_record(
        self, zone_id: str, hostname: str, tunnel_id: str
    ) -> dict[str, Any]: ...
    async def get_tunnel_token(self, account_id: str, tunnel_id: str) -> str: ...
    async def disable_tunnel(self, account_id: str, tunnel_id: str) -> None: ...
    async def verify_tunnel_route(
        self,
        account_id: str,
        tunnel_id: str,
        hostname: str,
        origin_url: str,
    ) -> bool: ...
    async def remove_tunnel_route(
        self, account_id: str, tunnel_id: str, hostname: str, origin_url: str
    ) -> None: ...
    async def get_dns_record(
        self, zone_id: str, record_id: str
    ) -> dict[str, Any] | None: ...
    async def list_tunnel_connections(
        self, account_id: str, tunnel_id: str
    ) -> list[dict[str, Any]]: ...
    async def delete_dns_record(self, zone_id: str, record_id: str) -> None: ...



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
    def _normalize_tunnel_id(value: str) -> str:
        normalized = value.strip()
        if normalized.startswith("eyJ"):
            raise CloudflareValidationError(
                "A Cloudflared connector token was provided. Use the existing tunnel UUID instead."
            )
        if not _TUNNEL_ID.fullmatch(normalized):
            raise CloudflareValidationError(
                "Tunnel ID must be the existing tunnel UUID, not a connector token."
            )
        return normalized.lower()

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
        hostname = parsed.hostname or ""
        valid_hostname = False
        if hostname and not any(
            character.isspace() or character == "\\" for character in normalized
        ):
            try:
                ip_address(hostname)
                valid_hostname = True
            except ValueError:
                try:
                    ascii_hostname = hostname.encode("idna").decode("ascii")
                except UnicodeError:
                    ascii_hostname = ""
                labels = ascii_hostname.split(".")
                valid_hostname = bool(ascii_hostname) and all(
                    label
                    and len(label) <= 63
                    and not label.startswith("-")
                    and not label.endswith("-")
                    and re.fullmatch(r"[A-Za-z0-9-]+", label)
                    for label in labels
                )
        if (
            parsed.scheme != "http"
            or not valid_hostname
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

    async def authorize(
        self, api_token: str, account_id: str, tunnel_id: str
    ) -> dict[str, Any]:
        self._require_connector()
        token = api_token.strip()
        if not token:
            raise CloudflareValidationError("Cloudflare API token is required")
        account_id = self._normalize_resource_id(account_id, "account ID")
        tunnel_id = self._normalize_tunnel_id(tunnel_id)
        client = self.client_factory(token)
        await client.verify_token()
        tunnel = await client.get_tunnel(account_id, tunnel_id)
        if not isinstance(tunnel, dict) or str(tunnel.get("id", "")) != tunnel_id:
            raise CloudflareNotFoundError("Cloudflare tunnel was not found")
        try:
            accounts = await client.list_accounts()
        except CloudflareAPIError:
            # A selected tunnel lookup has already proven access to this account.
            # Listing every account is optional discovery and can be denied to a
            # correctly scoped user token.
            accounts = []
        selected_account = next(
            (item for item in accounts if str(item.get("id", "")) == account_id),
            None,
        )
        zones = await client.list_zones(account_id)
        authorized_accounts = [
            {
                "id": account_id,
                "name": (
                    str(selected_account.get("name", "Cloudflare account"))
                    if isinstance(selected_account, dict)
                    else "Selected Cloudflare account"
                ),
                "zones": [
                    {"id": str(zone.get("id", "")), "name": str(zone.get("name", ""))}
                    for zone in zones
                    if str(zone.get("id", "")) and str(zone.get("name", ""))
                ],
            }
        ]
        authorization_id = random_secrets.token_urlsafe(24)
        self.secrets.set(
            f"{_AUTHORIZATION_PREFIX}{authorization_id}",
            {
                "api_token": token,
                "created_at": time.time(),
                "account_id": account_id,
                "tunnel_id": tunnel_id,
            },
        )
        return {"authorization_id": authorization_id, "accounts": authorized_accounts}

    def get_authorization(self, authorization_id: str) -> dict[str, Any]:
        self._authorization_payload(authorization_id)
        return {}

    def cancel_authorization(self, authorization_id: str) -> bool:
        return self.secrets.delete(f"{_AUTHORIZATION_PREFIX}{authorization_id}")


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
        tunnel_id: str,
        zone_id: str,
        hostname: str,
    ) -> ProviderConnection:
        async with self._provision_lock:
            return await self._provision_locked(
                authorization_id=authorization_id,
                account_id=account_id,
                tunnel_id=tunnel_id,
                zone_id=zone_id,
                hostname=hostname,
            )

    async def _provision_locked(
        self,
        *,
        authorization_id: str,
        account_id: str,
        tunnel_id: str,
        zone_id: str,
        hostname: str,
    ) -> ProviderConnection:
        self._require_connector()
        if any(item.provider == "cloudflare" for item in self.store.list_connections()):
            raise CloudflareConflictError("A Cloudflare tunnel is already connected")
        account_id = self._normalize_resource_id(account_id, "account ID")
        zone_id = self._normalize_resource_id(zone_id, "zone ID")
        hostname = self._normalize_hostname(hostname)
        tunnel_id = self._normalize_tunnel_id(tunnel_id)
        authorization_owner, credential_payload, client = await self._pending_client(
            authorization_id
        )
        if (
            credential_payload.get("account_id") != account_id
            or credential_payload.get("tunnel_id") != tunnel_id
        ):
            raise CloudflareValidationError(
                "account ID and tunnel ID must match the validated token"
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
        if not self._hostname_in_zone(hostname, zone_name):
            raise CloudflareValidationError(
                "Cloudflare hostname must belong to the selected zone"
            )
        # Persist the hostname intent before DNS mutation. If the process stops
        # after Cloudflare creates DNS but before the record ID is stored,
        # refresh/disconnect can reconcile the pending hostname by exact name,
        # tunnel target, and lnSwitchboard ownership comment.
        dns_adopted = False
        dns_record_id: str | None = None
        connection: ProviderConnection | None = None
        metadata = {
            "zone_id": zone_id,
            "zone_name": zone_name,
            "origin": self.origin_url,
            "dns_adopted": False,
        }
        try:
            connection = self.store.upsert_connection(
                provider="cloudflare",
                external_id=tunnel_id,
                label="Cloudflare Tunnel",
                status="provisioning",
                account_id=account_id,
                public_metadata=metadata,
            )
            self.store.replace_domains(
                connection.id,
                [
                    {
                        "hostname": hostname,
                        "status": "pending",
                        "external_id": None,
                        "zone_id": zone_id,
                    }
                ],
            )
            self.secrets.set(
                connection.id,
                {"api_token": str(credential_payload["api_token"])},
            )
        except Exception:
            if connection is not None:
                self.secrets.delete(connection.id)
                self.store.delete_connection(connection.id)
            raise

        try:
            dns_record_id, dns_adopted = await self._create_or_adopt_dns_record(
                client, zone_id, hostname, tunnel_id
            )
            metadata["dns_adopted"] = dns_adopted
            connection = self.store.upsert_connection(
                provider="cloudflare",
                external_id=tunnel_id,
                label="Cloudflare Tunnel",
                status="provisioning",
                account_id=account_id,
                public_metadata=metadata,
            )
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
        except Exception as dns_error:
            dns_cleanup_errors = await self._cleanup_created_dns_record(
                client,
                tunnel_id=tunnel_id,
                zone_id=zone_id,
                hostname=hostname,
                dns_record_id=dns_record_id,
            )
            uncertain_dns_outcome = (
                dns_record_id is None
                and isinstance(dns_error, CloudflareAPIError)
                and dns_error.status_code >= 500
            )
            if dns_cleanup_errors or uncertain_dns_outcome:
                self._mark_rollback_review(
                    connection,
                    hostname,
                    zone_id,
                    dns_record_id,
                    route_cleanup_pending=False,
                    dns_cleanup_pending=True,
                )
            else:
                self.secrets.delete(connection.id)
                self.store.delete_connection(connection.id)
            raise dns_error
        try:
            original_config, written_config = await client.configure_tunnel(
                account_id, tunnel_id, hostname, self.origin_url
            )
        except Exception as exc:
            dns_cleanup_errors = await self._cleanup_created_dns_record(
                client,
                tunnel_id=tunnel_id,
                zone_id=zone_id,
                hostname=hostname,
                dns_record_id=dns_record_id,
            )
            route_cleanup_pending = isinstance(exc, CloudflareRollbackError)
            if dns_cleanup_errors or route_cleanup_pending:
                self._mark_rollback_review(
                    connection,
                    hostname,
                    zone_id,
                    dns_record_id,
                    route_cleanup_pending=route_cleanup_pending,
                    dns_cleanup_pending=bool(dns_cleanup_errors),
                )
                raise CloudflareServiceError(
                    "Cloudflare provisioning rollback needs operator review"
                ) from exc
            self.secrets.delete(connection.id)
            self.store.delete_connection(connection.id)
            raise

        try:
            connector_token = await client.get_tunnel_token(account_id, tunnel_id)
            self._write_connector_token(connector_token)
            self.secrets.delete(authorization_owner)
        except Exception as provision_error:
            dns_cleanup_errors = await self._cleanup_created_dns_record(
                client,
                tunnel_id=tunnel_id,
                zone_id=zone_id,
                hostname=hostname,
                dns_record_id=dns_record_id,
            )
            route_cleanup_pending = False
            try:
                await client.restore_tunnel_configuration(
                    account_id,
                    tunnel_id,
                    original_config,
                    written_config,
                )
            except Exception:
                route_cleanup_pending = True
            try:
                self._remove_connector_token()
            except OSError:
                pass
            if dns_cleanup_errors or route_cleanup_pending:
                self._mark_rollback_review(
                    connection,
                    hostname,
                    zone_id,
                    dns_record_id,
                    route_cleanup_pending=route_cleanup_pending,
                    dns_cleanup_pending=bool(dns_cleanup_errors),
                )
            else:
                self.secrets.delete(connection.id)
                self.store.delete_connection(connection.id)
            raise provision_error

        refreshed = self.store.get_connection(connection.id)
        assert refreshed is not None
        return refreshed

    async def refresh_status(self, connection_id: str) -> ProviderConnection:
        async with self._provision_lock:
            return await self._refresh_status_locked(connection_id)

    async def _refresh_status_locked(self, connection_id: str) -> ProviderConnection:
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

        domain_payloads: list[dict[str, Any]] = []
        dns_mismatch = False
        for domain in connection.domains:
            current_status = domain_status
            last_error: str | None = None
            external_id = domain.external_id
            if domain.zone_id:
                if external_id is not None:
                    record = await client.get_dns_record(domain.zone_id, external_id)
                    if record is None or not self._dns_record_is_owned(
                        record,
                        record_id=external_id,
                        hostname=domain.hostname,
                        tunnel_id=connection.external_id,
                    ):
                        current_status = "error"
                        last_error = "Managed DNS record is missing or no longer owned"
                        dns_mismatch = True
                else:
                    records = await client.list_dns_records(
                        domain.zone_id, domain.hostname
                    )
                    recovered_owned_id = self._owned_dns_record_id(
                        records, domain.hostname, connection.external_id
                    )
                    if recovered_owned_id is not None:
                        external_id = recovered_owned_id
                        current_status = "error"
                        last_error = (
                            "Cloudflare provisioning was interrupted; remove the domain or disconnect and retry"
                        )
                        dns_mismatch = True
                    elif not self._dns_points_to_tunnel(
                        records, domain.hostname, connection.external_id
                    ):
                        current_status = "error"
                        last_error = "Existing DNS points to a different tunnel"
                        dns_mismatch = True
            if current_status == "active" and not await client.verify_tunnel_route(
                str(connection.account_id),
                connection.external_id,
                domain.hostname,
                self.origin_url,
            ):
                current_status = "error"
                last_error = (
                    "Managed tunnel ingress is missing, retargeted, duplicated, or shadowed"
                )
                dns_mismatch = True
            domain_payloads.append(
                {
                    "hostname": domain.hostname,
                    "status": current_status,
                    "external_id": external_id,
                    "zone_id": domain.zone_id,
                    "last_error": last_error,
                }
            )
        if dns_mismatch:
            status = "degraded"

        metadata = dict(connection.public_metadata)
        metadata["connector_count"] = len(remote_connections)
        updated = self.store.upsert_connection(
            provider="cloudflare",
            external_id=connection.external_id,
            label=connection.label,
            status=status,
            account_id=connection.account_id,
            public_metadata=metadata,
            last_error=(
                "One or more Cloudflare hostnames need attention"
                if dns_mismatch
                else None
            ),
        )
        self.store.replace_domains(updated.id, domain_payloads)
        result = self.store.get_connection(updated.id)
        assert result is not None
        return result

    async def available_zones(self, connection_id: str) -> list[dict[str, str]]:
        connection = self._require_connection(connection_id)
        client = await self._connection_client(connection_id)
        account_id = str(connection.account_id or "")
        available: list[dict[str, str]] = []
        for zone in await client.list_zones(account_id):
            zone_id = str(zone.get("id", ""))
            name = self._normalize_hostname(str(zone.get("name", "")))
            available.append({"id": zone_id, "name": name})
        return sorted(available, key=lambda item: item["name"])

    async def add_domain(
        self, connection_id: str, zone_id: str, hostname: str
    ) -> ProviderConnection:
        async with self._provision_lock:
            connection = self._require_connection(connection_id)
            if connection.public_metadata.get("cleanup_pending"):
                raise CloudflareConflictError(
                    "Cloudflare cleanup is pending; retry disconnect before adding a domain"
                )
            zone_id = self._normalize_resource_id(zone_id, "zone ID")
            hostname = self._normalize_hostname(hostname)
            client = await self._connection_client(connection_id)
            zone = await client.get_zone(zone_id)
            zone_name = self._normalize_hostname(str(zone.get("name", "")))
            zone_account = zone.get("account")
            zone_account_id = (
                str(zone_account.get("id", ""))
                if isinstance(zone_account, dict)
                else ""
            )
            if zone_account_id != connection.account_id:
                raise CloudflareValidationError(
                    "zone does not belong to the connected Cloudflare account"
                )
            if not self._hostname_in_zone(hostname, zone_name):
                raise CloudflareValidationError(
                    "Cloudflare hostname must belong to the selected zone"
                )
            if any(domain.hostname == hostname for domain in connection.domains):
                raise CloudflareConflictError("Cloudflare domain is already connected")

            original_domains = [
                self._domain_payload(domain) for domain in connection.domains
            ]
            self.store.replace_domains(
                connection.id,
                original_domains
                + [
                    {
                        "hostname": hostname,
                        "status": "pending",
                        "external_id": None,
                        "zone_id": zone_id,
                    }
                ],
            )
            connection = self._require_connection(connection.id)
            dns_record_id: str | None = None
            try:
                dns_record_id, _dns_adopted = await self._create_or_adopt_dns_record(
                    client, zone_id, hostname, connection.external_id
                )
                self.store.replace_domains(
                    connection.id,
                    original_domains
                    + [
                        {
                            "hostname": hostname,
                            "status": "pending",
                            "external_id": dns_record_id,
                            "zone_id": zone_id,
                        }
                    ],
                )
                connection = self._require_connection(connection.id)
            except Exception as dns_error:
                dns_cleanup_errors = await self._cleanup_created_dns_record(
                    client,
                    tunnel_id=connection.external_id,
                    zone_id=zone_id,
                    hostname=hostname,
                    dns_record_id=dns_record_id,
                )
                uncertain_dns_outcome = (
                    dns_record_id is None
                    and isinstance(dns_error, CloudflareAPIError)
                    and dns_error.status_code >= 500
                )
                if dns_cleanup_errors or uncertain_dns_outcome:
                    self._mark_rollback_review(
                        connection,
                        hostname,
                        zone_id,
                        dns_record_id,
                        route_cleanup_pending=False,
                        dns_cleanup_pending=True,
                    )
                else:
                    self.store.replace_domains(connection.id, original_domains)
                raise dns_error

            try:
                await client.configure_tunnel(
                    str(connection.account_id),
                    connection.external_id,
                    hostname,
                    self.origin_url,
                )
            except Exception as exc:
                dns_cleanup_errors = await self._cleanup_created_dns_record(
                    client,
                    tunnel_id=connection.external_id,
                    zone_id=zone_id,
                    hostname=hostname,
                    dns_record_id=dns_record_id,
                )
                route_cleanup_pending = isinstance(exc, CloudflareRollbackError)
                if dns_cleanup_errors or route_cleanup_pending:
                    self._mark_rollback_review(
                        connection,
                        hostname,
                        zone_id,
                        dns_record_id,
                        route_cleanup_pending=route_cleanup_pending,
                        dns_cleanup_pending=bool(dns_cleanup_errors),
                    )
                else:
                    self.store.replace_domains(connection.id, original_domains)
                raise

            updated = self.store.get_connection(connection.id)
            assert updated is not None
            return updated

    async def remove_domain(
        self, connection_id: str, hostname: str
    ) -> ProviderConnection:
        async with self._provision_lock:
            connection = self._require_connection(connection_id)
            if len(connection.domains) <= 1:
                raise CloudflareConflictError(
                    "Disconnect the Cloudflare tunnel to remove its final domain"
                )
            hostname = self._normalize_hostname(hostname)
            domain = next(
                (item for item in connection.domains if item.hostname == hostname), None
            )
            if domain is None:
                raise CloudflareNotFoundError("Cloudflare domain was not found")
            zone_id = domain.zone_id or str(
                connection.public_metadata.get("zone_id", "")
            )
            if not zone_id:
                raise CloudflareConflictError(
                    "Cloudflare domain is missing its zone identity"
                )
            client = await self._connection_client(connection_id)
            cleanup_domain = domain
            if domain.external_id is None:
                records = await client.list_dns_records(zone_id, domain.hostname)
                recovered_owned_id = self._owned_dns_record_id(
                    records, domain.hostname, connection.external_id
                )
                if recovered_owned_id is not None:
                    cleanup_domain = ConnectedDomain(
                        hostname=domain.hostname,
                        status=domain.status,
                        external_id=recovered_owned_id,
                        zone_id=zone_id,
                        last_error=domain.last_error,
                    )
            record: dict[str, Any] | None = None
            if cleanup_domain.external_id:
                record = await client.get_dns_record(
                    zone_id, cleanup_domain.external_id
                )
                if record is not None and not self._owns_dns_record(
                    connection, cleanup_domain, record
                ):
                    raise CloudflareConflictError(
                        "The DNS record is no longer owned by lnSwitchboard and was preserved"
                    )
            await client.remove_tunnel_route(
                str(connection.account_id),
                connection.external_id,
                domain.hostname,
                self.origin_url,
            )
            if cleanup_domain.external_id and record is not None:
                latest_record = await client.get_dns_record(
                    zone_id, cleanup_domain.external_id
                )
                if latest_record is not None and not self._owns_dns_record(
                    connection, cleanup_domain, latest_record
                ):
                    raise CloudflareConflictError(
                        "The DNS record changed during cleanup and was preserved"
                    )
                if latest_record is not None:
                    await client.delete_dns_record(
                        zone_id, cleanup_domain.external_id
                    )
            self.store.replace_domains(
                connection.id,
                [
                    self._domain_payload(item)
                    for item in connection.domains
                    if item.hostname != hostname
                ],
            )
            updated = self.store.get_connection(connection.id)
            assert updated is not None
            return updated

    async def disconnect(self, connection_id: str) -> bool:
        async with self._provision_lock:
            return await self._disconnect_locked(connection_id)

    async def _disconnect_locked(self, connection_id: str) -> bool:
        connection = self._require_connection(connection_id)
        client = await self._connection_client(connection_id)
        owned_records: list[tuple[ConnectedDomain, str]] = []
        route_hostnames = {domain.hostname for domain in connection.domains}
        dns_domains = list(connection.domains)
        pending = connection.public_metadata.get("cleanup_pending")
        if isinstance(pending, list):
            for item in pending:
                if not isinstance(item, dict):
                    continue
                hostname = self._normalize_hostname(str(item.get("hostname", "")))
                zone_id = self._normalize_resource_id(
                    str(item.get("zone_id", "")), "zone ID"
                )
                dns_record_id = item.get("dns_record_id")
                if item.get("route_cleanup_pending") is True:
                    route_hostnames.add(hostname)
                if item.get("dns_cleanup_pending") is True and isinstance(
                    dns_record_id, str
                ):
                    dns_domains.append(
                        ConnectedDomain(
                            hostname=hostname,
                            status="error",
                            external_id=dns_record_id,
                            zone_id=zone_id,
                        )
                    )
        try:
            for domain in dns_domains:
                zone_id = domain.zone_id or str(
                    connection.public_metadata.get("zone_id", "")
                )
                if not zone_id:
                    continue
                cleanup_domain = domain
                if domain.external_id is None:
                    records = await client.list_dns_records(zone_id, domain.hostname)
                    recovered_owned_id = self._owned_dns_record_id(
                        records, domain.hostname, connection.external_id
                    )
                    if recovered_owned_id is None:
                        continue
                    cleanup_domain = ConnectedDomain(
                        hostname=domain.hostname,
                        status=domain.status,
                        external_id=recovered_owned_id,
                        zone_id=zone_id,
                        last_error=domain.last_error,
                    )
                assert cleanup_domain.external_id is not None
                record = await client.get_dns_record(
                    zone_id, cleanup_domain.external_id
                )
                if record is not None and not self._owns_dns_record(
                    connection, cleanup_domain, record
                ):
                    raise CloudflareConflictError(
                        "The DNS record is no longer owned by lnSwitchboard and was preserved"
                    )
                if record is not None:
                    owned_records.append((cleanup_domain, zone_id))
            for hostname in sorted(route_hostnames):
                await client.remove_tunnel_route(
                    str(connection.account_id),
                    connection.external_id,
                    hostname,
                    self.origin_url,
                )
            self._remove_connector_token()
            for domain, zone_id in owned_records:
                assert domain.external_id is not None
                latest_record = await client.get_dns_record(
                    zone_id, domain.external_id
                )
                if latest_record is not None and not self._owns_dns_record(
                    connection, domain, latest_record
                ):
                    raise CloudflareConflictError(
                        "The DNS record changed during cleanup and was preserved"
                    )
                if latest_record is not None:
                    await client.delete_dns_record(zone_id, domain.external_id)
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
        try:
            removed = self.store.delete_connection(connection.id)
            if not removed:
                raise OSError("connection row was not deleted")
        except Exception as exc:
            try:
                self.store.upsert_connection(
                    provider="cloudflare",
                    external_id=connection.external_id,
                    label=connection.label,
                    status="error",
                    account_id=connection.account_id,
                    public_metadata=connection.public_metadata,
                    last_error="Cloudflare local cleanup failed; retry disconnect",
                )
            except Exception:
                pass
            raise CloudflareServiceError(
                "Cloudflare local cleanup failed; retry disconnect"
            ) from exc
        self.secrets.delete(connection.id)
        return True

    async def _cleanup_created_dns_record(
        self,
        client: CloudflareClientProtocol,
        *,
        tunnel_id: str,
        zone_id: str,
        hostname: str,
        dns_record_id: str | None,
    ) -> list[str]:
        if dns_record_id is None:
            return []
        try:
            record = await client.get_dns_record(zone_id, dns_record_id)
            if record is None:
                return []
            if not self._dns_record_is_owned(
                record,
                record_id=dns_record_id,
                hostname=hostname,
                tunnel_id=tunnel_id,
            ):
                raise CloudflareConflictError(
                    "Created DNS record changed during rollback and was preserved"
                )
            await client.delete_dns_record(zone_id, dns_record_id)
            return []
        except Exception as exc:
            return [type(exc).__name__]

    def _mark_rollback_review(
        self,
        connection: ProviderConnection,
        hostname: str,
        zone_id: str,
        dns_record_id: str | None,
        *,
        route_cleanup_pending: bool,
        dns_cleanup_pending: bool,
    ) -> None:
        try:
            metadata = dict(connection.public_metadata)
            pending = metadata.get("cleanup_pending")
            pending_items = list(pending) if isinstance(pending, list) else []
            pending_items = [
                item
                for item in pending_items
                if not isinstance(item, dict) or item.get("hostname") != hostname
            ]
            pending_items.append(
                {
                    "hostname": hostname,
                    "zone_id": zone_id,
                    "dns_record_id": dns_record_id,
                    "route_cleanup_pending": route_cleanup_pending,
                    "dns_cleanup_pending": dns_cleanup_pending,
                }
            )
            metadata["cleanup_pending"] = pending_items
            self.store.upsert_connection(
                provider="cloudflare",
                external_id=connection.external_id,
                label=connection.label,
                status="error",
                account_id=connection.account_id,
                public_metadata=metadata,
                last_error="Cloudflare domain rollback needs operator review",
            )
        except Exception:
            pass

    @staticmethod
    def _owns_dns_record(
        connection: ProviderConnection,
        domain: ConnectedDomain,
        record: dict[str, Any],
    ) -> bool:
        return CloudflareService._dns_record_is_owned(
            record,
            record_id=domain.external_id,
            hostname=domain.hostname,
            tunnel_id=connection.external_id,
        )

    @staticmethod
    def _dns_record_is_owned(
        record: dict[str, Any],
        *,
        record_id: str | None,
        hostname: str,
        tunnel_id: str,
    ) -> bool:
        return (
            record.get("id") == record_id
            and str(record.get("type", "")).upper() == "CNAME"
            and str(record.get("name", "")).lower().rstrip(".") == hostname
            and str(record.get("content", "")).lower().rstrip(".")
            == f"{tunnel_id}.cfargotunnel.com"
            and record.get("comment") == "Managed by lnSwitchboard"
        )

    @staticmethod
    def _domain_payload(domain: ConnectedDomain) -> dict[str, Any]:
        return {
            "hostname": domain.hostname,
            "status": domain.status,
            "external_id": domain.external_id,
            "zone_id": domain.zone_id,
            "last_error": domain.last_error,
        }

    @staticmethod
    def _hostname_in_zone(hostname: str, zone_name: str) -> bool:
        return hostname == zone_name or hostname.endswith(f".{zone_name}")

    @staticmethod
    def _dns_points_to_tunnel(
        records: list[dict[str, Any]], hostname: str, tunnel_id: str
    ) -> bool:
        target = f"{tunnel_id}.cfargotunnel.com"
        return any(
            str(record.get("type", "")).upper() == "CNAME"
            and str(record.get("name", "")).lower().rstrip(".") == hostname
            and str(record.get("content", "")).lower().rstrip(".") == target
            for record in records
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

    def purge_expired_authorizations(self, *, now: float | None = None) -> None:
        current_time = time.time() if now is None else now
        for owner_id in self.secrets.list_owner_ids():
            if not owner_id.startswith(_AUTHORIZATION_PREFIX):
                continue
            authorization_id = owner_id.removeprefix(_AUTHORIZATION_PREFIX)
            try:
                payload = self.secrets.get(owner_id)
            except ValueError:
                payload = None
            created_at = payload.get("created_at") if payload else None
            if (
                not _AUTHORIZATION_ID.fullmatch(authorization_id)
                or not isinstance(created_at, (int, float))
                or float(created_at) > current_time
                or current_time - float(created_at) > _AUTHORIZATION_TTL_SECONDS
            ):
                self.secrets.delete(owner_id)

    async def recover_incomplete_provisioning(self) -> None:
        """Quarantine incomplete journals from the legacy tunnel-creation flow.

        Current provisioning records a durable provider connection before remote
        ingress mutation and does not create these journals. A legacy journal is
        not sufficient proof that its DNS record or tunnel is still owned: an
        operator may have repurposed either resource after a crash. Recovery is
        therefore deliberately non-destructive and requires operator review.
        """

        self.purge_expired_authorizations()
        live_connection_ids = {item.id for item in self.store.list_connections()}
        for owner_id in self.secrets.list_owner_ids():
            if owner_id.startswith(_AUTHORIZATION_PREFIX):
                continue
            if (
                _CONNECTION_OWNER_ID.fullmatch(owner_id)
                and owner_id not in live_connection_ids
            ):
                self.secrets.delete(owner_id)

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
            if (
                matching_connection is not None
                and self.secrets.get(matching_connection.id) is not None
            ):
                self.store.delete_provisioning_journal(journal.id)
                continue
            self.store.update_provisioning_journal(
                journal.id,
                phase="cleanup_pending",
                last_error="legacy_recovery_requires_operator_review",
            )


    @classmethod
    async def _create_or_adopt_dns_record(
        cls,
        client: CloudflareClientProtocol,
        zone_id: str,
        hostname: str,
        tunnel_id: str,
    ) -> tuple[str | None, bool]:
        try:
            record = await client.create_dns_record(zone_id, hostname, tunnel_id)
            record_id = str(record.get("id", ""))
            if not record_id:
                raise CloudflareServiceError(
                    "Cloudflare DNS creation outcome could not be reconciled"
                )
            return record_id, False
        except CloudflareAPIError as exc:
            records = await client.list_dns_records(zone_id, hostname)
            owned_id = cls._owned_dns_record_id(records, hostname, tunnel_id)
            if owned_id is not None:
                # Reconcile a successful create whose response was lost, rather
                # than downgrading lnSwitchboard's record to adopted ownership.
                return owned_id, False
            if {81053, 81057, 81058} & set(exc.error_codes):
                if cls._dns_points_to_tunnel(records, hostname, tunnel_id):
                    return None, True
                raise CloudflareConflictError(
                    "Existing Cloudflare DNS points to a different tunnel; select that tunnel or use another hostname"
                ) from exc
            raise

    @classmethod
    async def _find_owned_dns_record_id(
        cls,
        client: CloudflareClientProtocol,
        zone_id: str,
        hostname: str,
        tunnel_id: str,
    ) -> str | None:
        records = await client.list_dns_records(zone_id, hostname)
        return cls._owned_dns_record_id(records, hostname, tunnel_id)

    @staticmethod
    def _owned_dns_record_id(
        records: list[dict[str, Any]], hostname: str, tunnel_id: str
    ) -> str | None:
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
