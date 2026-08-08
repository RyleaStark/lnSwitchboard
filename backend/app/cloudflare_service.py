"""Cloudflare Mesh + proxy Worker onboarding and lifecycle orchestration."""

from __future__ import annotations

import asyncio

import os
import re
import secrets as random_secrets
import time
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol
from urllib.parse import urlsplit

from .cloudflare_client import PLACEHOLDER_DNS_CONTENT, CloudflareAPIError
from .cloudflare_worker_source import (
    INTERNAL_HOSTNAME,
    LNS_WORKER_VERSION,
    MANAGED_COMMENT,
    PUBLIC_PORT,
    WORKER_SCRIPT_NAME,
    extract_worker_version,
)
from .connection_secret_store import ConnectionSecretStore
from .connection_store import ConnectedDomain, ConnectionStore, ProviderConnection

_AUTHORIZATION_PREFIX = "cloudflare-authorization:"
_AUTHORIZATION_ID = re.compile(r"^[A-Za-z0-9_-]{32}$")
_AUTHORIZATION_TTL_SECONDS = 15 * 60
_RESOURCE_ID = re.compile(r"^[a-fA-F0-9]{32}$")
_CONNECTION_OWNER_ID = re.compile(
    r"^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$", re.IGNORECASE
)

# Cloudflare One prerequisites for Mesh networking, per
# https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/get-started/
# ("What the wizard configures" / "Existing Cloudflare One accounts") and
# .../cloudflare-mesh/routes/ ("Hostname routes" prerequisites).
MESH_IP_RANGE = "100.96.0.0/12"
DEFAULT_CGNAT_EXCLUSION = "100.64.0.0/10"
MESH_INCLUDE_DESCRIPTION = "Cloudflare Mesh device IPs (managed by lnSwitchboard)"
WARP_ENROLLMENT_APP_NAME = "Warp device enrollment"
PREREQ_METADATA_KEY = "cloudflare_one_prerequisites"
_PREREQ_PASSED = "passed"
_PREREQ_CONFIGURED = "configured"
_PREREQ_MANUAL = "needs-manual-action"


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

    async def create_mesh_node(self, account_id: str, name: str) -> dict[str, Any]: ...
    async def find_mesh_node_by_name(
        self, account_id: str, name: str
    ) -> dict[str, Any] | None: ...
    async def get_mesh_node(
        self, account_id: str, node_id: str
    ) -> dict[str, Any] | None: ...
    async def get_mesh_node_token(self, account_id: str, node_id: str) -> str: ...
    async def list_mesh_node_connections(
        self, account_id: str, node_id: str
    ) -> list[dict[str, Any]]: ...
    async def delete_mesh_node(self, account_id: str, node_id: str) -> None: ...

    async def list_access_apps(self, account_id: str) -> list[dict[str, Any]]: ...
    async def create_access_app(
        self, account_id: str, app: dict[str, Any]
    ) -> dict[str, Any]: ...
    async def list_device_policies(
        self, account_id: str
    ) -> list[dict[str, Any]]: ...
    async def get_default_device_policy(
        self, account_id: str
    ) -> dict[str, Any]: ...
    async def patch_default_device_policy(
        self, account_id: str, fields: dict[str, Any]
    ) -> dict[str, Any]: ...
    async def get_device_settings(self, account_id: str) -> dict[str, Any]: ...
    async def patch_device_settings(
        self, account_id: str, fields: dict[str, Any]
    ) -> dict[str, Any]: ...
    async def get_connectivity_settings(
        self, account_id: str
    ) -> dict[str, Any]: ...
    async def patch_connectivity_settings(
        self, account_id: str, fields: dict[str, Any]
    ) -> dict[str, Any]: ...

    async def create_hostname_route(
        self, account_id: str, node_id: str
    ) -> dict[str, Any]: ...
    async def list_hostname_routes(
        self, account_id: str
    ) -> list[dict[str, Any]]: ...
    async def get_hostname_route(
        self, account_id: str, route_id: str
    ) -> dict[str, Any] | None: ...
    async def delete_hostname_route(self, account_id: str, route_id: str) -> None: ...

    async def deploy_proxy_worker(self, account_id: str, script_name: str) -> None: ...
    async def get_worker_script_content(
        self, account_id: str, script_name: str
    ) -> str | None: ...
    async def delete_worker_script(self, account_id: str, script_name: str) -> None: ...

    async def ensure_workers_routes(
        self, zone_id: str, hostname: str, script_name: str
    ) -> None: ...
    async def verify_workers_routes(
        self, zone_id: str, hostname: str, script_name: str
    ) -> bool: ...
    async def remove_workers_routes(
        self, zone_id: str, hostname: str, script_name: str
    ) -> None: ...

    async def list_dns_records(
        self, zone_id: str, hostname: str
    ) -> list[dict[str, Any]]: ...
    async def create_placeholder_dns_record(
        self, zone_id: str, hostname: str
    ) -> dict[str, Any]: ...
    async def get_dns_record(
        self, zone_id: str, record_id: str
    ) -> dict[str, Any] | None: ...
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
        access_token_resolver: Callable[[str], Awaitable[str]] | None = None,
    ) -> None:
        self.store = store
        self.secrets = secrets
        self.client_factory = client_factory
        self.connector_enabled = connector_enabled
        self.token_path = Path(token_path)
        self.origin_url = self._validate_origin_url(origin_url)
        self.token_gid = token_gid
        self.access_token_resolver = access_token_resolver

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
            or parsed.port != PUBLIC_PORT
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise CloudflareValidationError(
                f"Cloudflare origin must be an HTTP service on public port {PUBLIC_PORT}"
            )
        return normalized

    async def authorize(self, api_token: str, account_id: str) -> dict[str, Any]:
        self._require_connector()
        token = api_token.strip()
        if not token:
            raise CloudflareValidationError("Cloudflare API token is required")
        account_id = self._normalize_resource_id(account_id, "account ID")
        client = self.client_factory(token)
        authorized_accounts = await self._verify_and_list(client, account_id)
        return self._store_authorization(
            {"api_token": token, "account_id": account_id}, authorized_accounts
        )

    async def authorize_grant(self, grant_id: str, account_id: str) -> dict[str, Any]:
        """Authorize via an OAuth grant instead of a pasted API token."""
        self._require_connector()
        grant_id = grant_id.strip()
        if not grant_id:
            raise CloudflareValidationError("Cloudflare authorization grant is required")
        if self.access_token_resolver is None:
            raise CloudflareServiceError("Cloudflare OAuth access is unavailable")
        access_token = await self.access_token_resolver(grant_id)
        account_id = self._normalize_resource_id(account_id, "account ID")
        client = self.client_factory(access_token)
        authorized_accounts = await self._verify_and_list(client, account_id)
        return self._store_authorization(
            {"grant_id": grant_id, "account_id": account_id}, authorized_accounts
        )

    async def discover_grant_accounts(self, grant_id: str) -> list[dict[str, str]]:
        """List the accounts selected during OAuth consent without storing a capability."""
        self._require_connector()
        grant_id = grant_id.strip()
        if not grant_id:
            raise CloudflareValidationError("Cloudflare authorization grant is required")
        if self.access_token_resolver is None:
            raise CloudflareServiceError("Cloudflare OAuth access is unavailable")
        access_token = await self.access_token_resolver(grant_id)
        client = self.client_factory(access_token)
        await client.verify_token()
        accounts = await client.list_accounts()
        discovered = [
            {"id": str(account.get("id", "")), "name": str(account.get("name", ""))}
            for account in accounts
            if str(account.get("id", "")) and str(account.get("name", ""))
        ]
        if not discovered:
            raise CloudflareValidationError(
                "Cloudflare returned no accounts for this authorization"
            )
        return discovered

    async def _verify_and_list(
        self, client: CloudflareClientProtocol, account_id: str
    ) -> list[dict[str, Any]]:
        await client.verify_token()
        try:
            accounts = await client.list_accounts()
        except CloudflareAPIError:
            # Zone listing below has already proven access to this account.
            # Listing every account is optional discovery and can be denied to
            # a correctly scoped user token.
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
        return authorized_accounts

    def _store_authorization(
        self, credential: dict[str, str], authorized_accounts: list[dict[str, Any]]
    ) -> dict[str, Any]:
        authorization_id = random_secrets.token_urlsafe(24)
        self.secrets.set(
            f"{_AUTHORIZATION_PREFIX}{authorization_id}",
            {
                **credential,
                "created_at": time.time(),
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

    # ------------------------------------------------------------------
    # Cloudflare One account prerequisites
    #
    # Cloudflare Mesh needs account-level Cloudflare One settings that the
    # dashboard setup wizard normally applies. The owner approved full
    # auto-configuration, so this stage reconciles them over the API
    # instead. It is idempotent: current state is read first and only
    # missing pieces are created or patched. Operator-owned entries are
    # never deleted, except the documented default 100.64.0.0/10 CGNAT
    # split-tunnel exclusion when (and only when) it is the sole entry
    # blocking the Mesh range. Anything customized beyond that is reported
    # as needing manual action instead of being mutated. These settings are
    # account-level enablement and are intentionally never torn down on
    # disconnect or rollback.
    # ------------------------------------------------------------------

    async def ensure_account_prerequisites(
        self, client: CloudflareClientProtocol, account_id: str
    ) -> dict[str, Any]:
        """Reconcile Cloudflare One prerequisites and return a structured report.

        The report is secret-free and safe to persist in public_metadata:
        ``{"status": "satisfied" | "needs-manual-action", "checks": {...}}``
        where each check is ``{"status": "passed" | "configured" |
        "needs-manual-action", "detail": <fixed message>}``.
        """
        checks: dict[str, dict[str, str]] = {}
        checks["device_enrollment"] = await self._ensure_device_enrollment(
            client, account_id
        )
        checks["device_profile"] = await self._ensure_device_profile(
            client, account_id
        )
        checks.update(await self._ensure_device_toggles(client, account_id))
        overall = (
            "satisfied"
            if all(check["status"] != _PREREQ_MANUAL for check in checks.values())
            else "needs-manual-action"
        )
        return {"status": overall, "checks": checks}

    @staticmethod
    def _prereq_check(status: str, detail: str) -> dict[str, str]:
        return {"status": status, "detail": detail}

    @staticmethod
    def _split_tunnel_network(entry: dict[str, Any]) -> Any:
        try:
            return ip_network(str(entry.get("address", "")).strip(), strict=False)
        except ValueError:
            # Split Tunnel entries may also be hostnames, which can never
            # route (or block) the Mesh IP range.
            return None

    @classmethod
    def _split_tunnel_covers(cls, entry: dict[str, Any], mesh_net: Any) -> bool:
        network = cls._split_tunnel_network(entry)
        return (
            network is not None
            and network.version == mesh_net.version
            and mesh_net.subnet_of(network)
        )

    @classmethod
    def _split_tunnel_blocks(cls, entry: dict[str, Any], mesh_net: Any) -> bool:
        network = cls._split_tunnel_network(entry)
        return (
            network is not None
            and network.version == mesh_net.version
            and network.overlaps(mesh_net)
        )

    async def _ensure_device_enrollment(
        self, client: CloudflareClientProtocol, account_id: str
    ) -> dict[str, str]:
        apps = await client.list_access_apps(account_id)
        warp_apps = [app for app in apps if app.get("type") == "warp"]
        for app in warp_apps:
            policies = app.get("policies")
            if isinstance(policies, list) and any(
                isinstance(policy, dict) and policy.get("decision") == "allow"
                for policy in policies
            ):
                return self._prereq_check(
                    _PREREQ_PASSED, "A device enrollment rule already exists"
                )
        if warp_apps:
            # An operator-managed enrollment application without an allow
            # policy is never mutated.
            return self._prereq_check(
                _PREREQ_MANUAL,
                "A device enrollment application exists without an allow "
                "policy; add an enrollment rule in the Cloudflare dashboard",
            )
        await client.create_access_app(
            account_id,
            {
                "name": WARP_ENROLLMENT_APP_NAME,
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
        return self._prereq_check(
            _PREREQ_CONFIGURED,
            "Created the device enrollment application with an allow policy",
        )

    async def _ensure_device_profile(
        self, client: CloudflareClientProtocol, account_id: str
    ) -> dict[str, str]:
        policy = await client.get_default_device_policy(account_id)
        service_mode = policy.get("service_mode_v2")
        mode_name = (
            service_mode.get("mode") if isinstance(service_mode, dict) else None
        )
        if isinstance(mode_name, str) and mode_name and mode_name != "warp":
            # Client mode is never switched on a customized profile.
            return self._prereq_check(
                _PREREQ_MANUAL,
                f"The default device profile uses client mode {mode_name!r}; "
                "Cloudflare Mesh requires Traffic and DNS (warp) mode",
            )
        include = [
            entry
            for entry in (policy.get("include") or [])
            if isinstance(entry, dict)
        ]
        exclude = [
            entry
            for entry in (policy.get("exclude") or [])
            if isinstance(entry, dict)
        ]
        mesh_net = ip_network(MESH_IP_RANGE)
        if include and exclude:
            return self._prereq_check(
                _PREREQ_MANUAL,
                "The default device profile has both Split Tunnel include and "
                "exclude lists; review the profile in the Cloudflare dashboard",
            )
        if include:
            # Include mode: adding the Mesh range only widens what routes
            # through Cloudflare, which is safe on any profile.
            if any(self._split_tunnel_covers(entry, mesh_net) for entry in include):
                return self._prereq_check(
                    _PREREQ_PASSED,
                    "The default device profile includes the Mesh IP range",
                )
            updated = [dict(entry) for entry in include]
            updated.append(
                {"address": MESH_IP_RANGE, "description": MESH_INCLUDE_DESCRIPTION}
            )
            await client.patch_default_device_policy(
                account_id, {"include": updated}
            )
            return self._prereq_check(
                _PREREQ_CONFIGURED,
                f"Added {MESH_IP_RANGE} to the default device profile Split "
                "Tunnel include list",
            )
        # Exclude mode: the Mesh range must not be excluded. Only the exact
        # documented default CGNAT exclusion may be removed, and only when it
        # is the sole entry blocking the Mesh range.
        blockers = [
            entry for entry in exclude if self._split_tunnel_blocks(entry, mesh_net)
        ]
        if not blockers:
            return self._prereq_check(
                _PREREQ_PASSED,
                "The default device profile does not exclude the Mesh IP range",
            )
        default_exclusion = ip_network(DEFAULT_CGNAT_EXCLUSION)
        if (
            len(blockers) == 1
            and self._split_tunnel_network(blockers[0]) == default_exclusion
        ):
            remaining = [
                dict(entry) for entry in exclude if entry is not blockers[0]
            ]
            await client.patch_default_device_policy(
                account_id, {"exclude": remaining}
            )
            return self._prereq_check(
                _PREREQ_CONFIGURED,
                f"Removed the default CGNAT exclusion {DEFAULT_CGNAT_EXCLUSION} "
                "from the default device profile so the Mesh IP range routes "
                "through Cloudflare",
            )
        blocking = ", ".join(
            sorted(str(entry.get("address", "")) for entry in blockers)
        )
        return self._prereq_check(
            _PREREQ_MANUAL,
            f"The default device profile excludes the Mesh IP range "
            f"{MESH_IP_RANGE} via {blocking}; remove the blocking exclusion "
            "in the Cloudflare dashboard",
        )

    async def _ensure_device_toggles(
        self, client: CloudflareClientProtocol, account_id: str
    ) -> dict[str, dict[str, str]]:
        settings = await client.get_device_settings(account_id)
        connectivity = await client.get_connectivity_settings(account_id)
        device_missing = {
            field: True
            for field in (
                "gateway_proxy_enabled",
                "gateway_udp_proxy_enabled",
                "use_zt_virtual_ip",
            )
            if settings.get(field) is not True
        }
        connectivity_missing = {
            field: True
            for field in ("icmp_proxy_enabled", "offramp_warp_enabled")
            if connectivity.get(field) is not True
        }
        if device_missing:
            await client.patch_device_settings(account_id, device_missing)
        if connectivity_missing:
            await client.patch_connectivity_settings(account_id, connectivity_missing)

        def toggle_status(missing: bool, passed_detail: str, configured_detail: str):
            if missing:
                return self._prereq_check(_PREREQ_CONFIGURED, configured_detail)
            return self._prereq_check(_PREREQ_PASSED, passed_detail)

        return {
            "gateway_proxy": toggle_status(
                "gateway_proxy_enabled" in device_missing
                or "gateway_udp_proxy_enabled" in device_missing
                or "icmp_proxy_enabled" in connectivity_missing,
                "The Gateway proxy is enabled for TCP, UDP, and ICMP",
                "Enabled the Gateway proxy for TCP, UDP, and ICMP",
            ),
            "unique_device_ips": toggle_status(
                "use_zt_virtual_ip" in device_missing,
                "A unique IP address is assigned to each device",
                "Enabled assigning a unique IP address to each device",
            ),
            "mesh_connectivity": toggle_status(
                "offramp_warp_enabled" in connectivity_missing,
                "Cloudflare One traffic can reach enrolled devices",
                "Enabled Cloudflare One traffic to reach enrolled devices",
            ),
        }

    @staticmethod
    def _prerequisites_manual_action_message(report: dict[str, Any]) -> str:
        checks = report.get("checks", {})
        blocked = "; ".join(
            f"{name}: {check.get('detail', '')}"
            for name, check in checks.items()
            if isinstance(check, dict) and check.get("status") == _PREREQ_MANUAL
        )
        return f"Cloudflare One prerequisites need manual action: {blocked}"

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

    def _persist_provisioning(
        self,
        connection: ProviderConnection,
        metadata: dict[str, Any],
        hostname: str,
        zone_id: str,
        dns_record_id: str | None,
    ) -> ProviderConnection:
        updated = self.store.upsert_connection(
            provider="cloudflare",
            external_id=connection.external_id,
            label=connection.label,
            status="provisioning",
            account_id=connection.account_id,
            public_metadata=metadata,
        )
        self.store.replace_domains(
            updated.id,
            [
                {
                    "hostname": hostname,
                    "status": "pending",
                    "external_id": dns_record_id,
                    "zone_id": zone_id,
                }
            ],
        )
        return updated

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
            raise CloudflareConflictError("Cloudflare is already connected")
        account_id = self._normalize_resource_id(account_id, "account ID")
        zone_id = self._normalize_resource_id(zone_id, "zone ID")
        hostname = self._normalize_hostname(hostname)
        authorization_owner, credential_payload, client = await self._pending_client(
            authorization_id
        )
        if credential_payload.get("account_id") != account_id:
            raise CloudflareValidationError(
                "account ID must match the validated token"
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

        # The mesh node name is generated before any remote mutation and used
        # as the connection's durable external identity: unlike the node id, it
        # is known up front and recoverable by name after a crash, so the
        # intent row can always be reconciled.
        node_name = self._mesh_node_name(hostname)
        metadata: dict[str, Any] = {
            "zone_id": zone_id,
            "zone_name": zone_name,
            "origin": self.origin_url,
            "dns_adopted": False,
            "mesh_node_name": node_name,
        }
        connection: ProviderConnection | None = None
        try:
            connection = self.store.upsert_connection(
                provider="cloudflare",
                external_id=node_name,
                label="Cloudflare Mesh",
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
            credential = (
                {"api_token": str(credential_payload["api_token"])}
                if credential_payload.get("api_token")
                else {"grant_id": str(credential_payload["grant_id"])}
            )
            self.secrets.set(connection.id, credential)
        except Exception:
            if connection is not None:
                self.secrets.delete(connection.id)
                self.store.delete_connection(connection.id)
            raise

        progress: dict[str, Any] = {
            "node_attempted": False,
            "node_id": None,
            "hostname_route_id": None,
            "worker_touched": False,
            "dns_attempted": False,
            "dns_record_id": None,
            "routes_touched": False,
        }
        dns_adopted = False
        try:
            # Account-level Cloudflare One prerequisites reconcile before any
            # mesh/worker mutation; a failure here leaves no remote resources
            # and the standard compensation below simply removes the intent.
            prereq_report = await self.ensure_account_prerequisites(
                client, account_id
            )
            metadata[PREREQ_METADATA_KEY] = prereq_report
            if prereq_report["status"] != "satisfied":
                raise CloudflareConflictError(
                    self._prerequisites_manual_action_message(prereq_report)
                )

            progress["node_attempted"] = True
            node_id = await self._create_or_recover_mesh_node(
                client, account_id, node_name
            )
            progress["node_id"] = node_id
            metadata["mesh_node_id"] = node_id
            connection = self._persist_provisioning(
                connection, metadata, hostname, zone_id, None
            )

            node_token = await client.get_mesh_node_token(account_id, node_id)
            self._write_node_token(node_token)

            hostname_route_id = await self._create_or_adopt_hostname_route(
                client, account_id, node_id
            )
            progress["hostname_route_id"] = hostname_route_id
            metadata["hostname_route_id"] = hostname_route_id
            connection = self._persist_provisioning(
                connection, metadata, hostname, zone_id, None
            )

            # Drift check before any PUT: a script carrying our version marker
            # is ours to upgrade; a script without it is foreign and never
            # overwritten.
            content = await client.get_worker_script_content(
                account_id, WORKER_SCRIPT_NAME
            )
            worker_version: str | None = None
            if content is not None:
                worker_version = extract_worker_version(content)
                if worker_version is None:
                    raise CloudflareConflictError(
                        "A Worker script named lnswitchboard-proxy already exists "
                        "and is not managed by lnSwitchboard"
                    )
            progress["worker_touched"] = True
            if worker_version != LNS_WORKER_VERSION:
                await client.deploy_proxy_worker(account_id, WORKER_SCRIPT_NAME)
                deployed = await client.get_worker_script_content(
                    account_id, WORKER_SCRIPT_NAME
                )
                if (
                    deployed is None
                    or extract_worker_version(deployed) != LNS_WORKER_VERSION
                ):
                    raise CloudflareAPIError(502)
                worker_version = LNS_WORKER_VERSION
            metadata["worker_version"] = worker_version
            connection = self._persist_provisioning(
                connection, metadata, hostname, zone_id, None
            )

            progress["dns_attempted"] = True
            dns_record_id, dns_adopted = await self._create_or_adopt_placeholder_dns(
                client, zone_id, hostname
            )
            progress["dns_record_id"] = dns_record_id
            metadata["dns_adopted"] = dns_adopted
            connection = self._persist_provisioning(
                connection, metadata, hostname, zone_id, dns_record_id
            )

            progress["routes_touched"] = True
            await client.ensure_workers_routes(zone_id, hostname, WORKER_SCRIPT_NAME)

            if not dns_adopted and dns_record_id is not None:
                record = await client.get_dns_record(zone_id, dns_record_id)
                if record is None or not self._dns_record_is_owned(
                    record, record_id=dns_record_id, hostname=hostname
                ):
                    raise CloudflareAPIError(502)
            if not await client.verify_workers_routes(
                zone_id, hostname, WORKER_SCRIPT_NAME
            ):
                raise CloudflareAPIError(502)
            self.secrets.delete(authorization_owner)
        except Exception as exc:
            cleanup_errors = await self._rollback_failed_provision(
                client,
                account_id=account_id,
                node_name=node_name,
                zone_id=zone_id,
                hostname=hostname,
                dns_adopted=dns_adopted,
                progress=progress,
            )
            ambiguous_outcome = (
                isinstance(exc, CloudflareAPIError) and exc.status_code >= 500
            )
            if cleanup_errors or ambiguous_outcome:
                self._mark_rollback_review(
                    connection,
                    hostname,
                    zone_id,
                    progress["dns_record_id"],
                    route_cleanup_pending=bool(progress["routes_touched"]),
                    dns_cleanup_pending=(
                        not dns_adopted
                        and (
                            progress["dns_record_id"] is not None
                            or (ambiguous_outcome and progress["dns_attempted"])
                        )
                    ),
                )
            else:
                self.secrets.delete(connection.id)
                self.store.delete_connection(connection.id)
            raise

        refreshed = self.store.get_connection(connection.id)
        assert refreshed is not None
        return refreshed

    async def _rollback_failed_provision(
        self,
        client: CloudflareClientProtocol,
        *,
        account_id: str,
        node_name: str,
        zone_id: str,
        hostname: str,
        dns_adopted: bool,
        progress: dict[str, Any],
    ) -> list[str]:
        """Best-effort reverse-order compensation for a failed provision.

        Every step is ownership-checked and idempotent; a stage is only
        touched when this run reached it, so foreign resources (for example a
        Worker script that failed the drift check) are never deleted.
        """
        errors: list[str] = []
        if progress["routes_touched"]:
            try:
                await client.remove_workers_routes(
                    zone_id, hostname, WORKER_SCRIPT_NAME
                )
            except CloudflareAPIError as exc:
                # A 409 here means a foreign-owned route was preserved, which
                # is the expected conflict path rather than a cleanup failure.
                if exc.status_code != 409:
                    errors.append(type(exc).__name__)
            except Exception as exc:
                errors.append(type(exc).__name__)
        if not dns_adopted and progress["dns_record_id"] is not None:
            errors.extend(
                await self._cleanup_created_dns_record(
                    client,
                    zone_id=zone_id,
                    hostname=hostname,
                    dns_record_id=progress["dns_record_id"],
                )
            )
        if progress["worker_touched"]:
            try:
                await client.delete_worker_script(account_id, WORKER_SCRIPT_NAME)
            except Exception as exc:
                errors.append(type(exc).__name__)
        if progress["hostname_route_id"] is not None:
            try:
                await client.delete_hostname_route(
                    account_id, progress["hostname_route_id"]
                )
            except Exception as exc:
                errors.append(type(exc).__name__)
        if progress["node_attempted"]:
            node_id = progress["node_id"]
            try:
                if node_id is None:
                    found = await client.find_mesh_node_by_name(account_id, node_name)
                    if isinstance(found, dict) and found.get("id"):
                        node_id = str(found["id"])
                if node_id is not None:
                    await client.delete_mesh_node(account_id, node_id)
            except Exception as exc:
                errors.append(type(exc).__name__)
        try:
            self._remove_node_token()
        except OSError:
            errors.append("OSError")
        return errors

    async def refresh_status(self, connection_id: str) -> ProviderConnection:
        async with self._provision_lock:
            return await self._refresh_status_locked(connection_id)

    async def _refresh_status_locked(self, connection_id: str) -> ProviderConnection:
        connection = self._require_connection(connection_id)
        if connection.public_metadata.get("cleanup_pending"):
            return connection
        client = await self._connection_client(connection_id)
        account_id = str(connection.account_id)
        prereq_report: dict[str, Any] | None = None
        prereq_error: str | None = None
        try:
            prereq_report = await self.ensure_account_prerequisites(
                client, account_id
            )
        except CloudflareAPIError:
            prereq_error = "Cloudflare One prerequisites could not be verified"
        else:
            if prereq_report["status"] != "satisfied":
                prereq_error = "Cloudflare One prerequisites need manual action"
        node_id = await self._resolve_node_id(client, account_id, connection)
        if (
            node_id is not None
            and connection.public_metadata.get("mesh_node_id") != node_id
        ):
            # The recovery above persisted the id; re-read so the final upsert
            # does not overwrite it with stale metadata.
            connection = self._require_connection(connection_id)
        remote_connections: list[dict[str, Any]] = []
        if node_id is not None:
            node = await client.get_mesh_node(account_id, node_id)
            if node is not None:
                remote_connections = await client.list_mesh_node_connections(
                    account_id, node_id
                )
        node_live = any(
            not item.get("is_pending_reconnect", False) for item in remote_connections
        )

        transport_error: str | None = prereq_error
        if node_id is None:
            transport_error = transport_error or "Managed mesh node is missing"
        content = await client.get_worker_script_content(
            account_id, WORKER_SCRIPT_NAME
        )
        if content is None:
            transport_error = transport_error or "Managed proxy Worker is missing"
        else:
            observed_version = extract_worker_version(content)
            if observed_version is None:
                transport_error = transport_error or (
                    "The lnswitchboard-proxy Worker is not managed by lnSwitchboard"
                )
            elif observed_version != LNS_WORKER_VERSION:
                # Our own outdated script: upgrade the drift and re-verify.
                try:
                    await client.deploy_proxy_worker(account_id, WORKER_SCRIPT_NAME)
                    deployed = await client.get_worker_script_content(
                        account_id, WORKER_SCRIPT_NAME
                    )
                    if (
                        deployed is None
                        or extract_worker_version(deployed) != LNS_WORKER_VERSION
                    ):
                        transport_error = transport_error or (
                            "Managed proxy Worker upgrade could not be verified"
                        )
                except CloudflareAPIError:
                    transport_error = transport_error or (
                        "Managed proxy Worker is outdated and could not be upgraded"
                    )

        hostname_route_ok = await self._verify_hostname_route(
            client, account_id, node_id, connection
        )
        if not hostname_route_ok:
            transport_error = transport_error or (
                "Managed hostname route is missing or retargeted"
            )

        if node_live and transport_error is None:
            status = "connected"
            domain_status = "active"
        elif transport_error is not None or connection.status == "connected":
            # A missing/replaced/outdated managed resource is always an error
            # state, even before the sidecar has ever connected.
            status = "degraded"
            domain_status = "error"
        else:
            status = "provisioning"
            domain_status = "pending"

        domain_payloads: list[dict[str, Any]] = []
        resource_mismatch = False
        for domain in connection.domains:
            current_status = domain_status
            last_error: str | None = (
                transport_error if domain_status == "error" else None
            )
            external_id = domain.external_id
            if domain.zone_id:
                if external_id is not None:
                    record = await client.get_dns_record(domain.zone_id, external_id)
                    if record is None or not self._dns_record_is_owned(
                        record,
                        record_id=external_id,
                        hostname=domain.hostname,
                    ):
                        current_status = "error"
                        last_error = "Managed DNS record is missing or no longer owned"
                        resource_mismatch = True
                else:
                    records = await client.list_dns_records(
                        domain.zone_id, domain.hostname
                    )
                    recovered_owned_id = self._owned_placeholder_id(
                        records, domain.hostname
                    )
                    if recovered_owned_id is not None:
                        external_id = recovered_owned_id
                        current_status = "error"
                        last_error = (
                            "Cloudflare provisioning was interrupted; remove the domain or disconnect and retry"
                        )
                        resource_mismatch = True
                    elif not records:
                        current_status = "error"
                        last_error = (
                            "Hostname has no DNS record; the managed Workers Routes cannot activate it"
                        )
                        resource_mismatch = True
            if current_status == "active" and not await client.verify_workers_routes(
                domain.zone_id or str(connection.public_metadata.get("zone_id", "")),
                domain.hostname,
                WORKER_SCRIPT_NAME,
            ):
                current_status = "error"
                last_error = (
                    "Managed Workers Routes are missing, retargeted, duplicated, or owned by another script"
                )
                resource_mismatch = True
            domain_payloads.append(
                {
                    "hostname": domain.hostname,
                    "status": current_status,
                    "external_id": external_id,
                    "zone_id": domain.zone_id,
                    "last_error": last_error,
                }
            )
        if resource_mismatch:
            status = "degraded"

        metadata = dict(connection.public_metadata)
        if prereq_report is not None:
            metadata[PREREQ_METADATA_KEY] = prereq_report
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
                if resource_mismatch
                else None
            ),
        )
        self.store.replace_domains(updated.id, domain_payloads)
        result = self.store.get_connection(updated.id)
        assert result is not None
        return result

    async def _resolve_node_id(
        self,
        client: CloudflareClientProtocol,
        account_id: str,
        connection: ProviderConnection,
    ) -> str | None:
        node_id = connection.public_metadata.get("mesh_node_id")
        if isinstance(node_id, str) and node_id:
            return node_id
        found = await client.find_mesh_node_by_name(
            account_id, connection.external_id
        )
        if not isinstance(found, dict) or not found.get("id"):
            return None
        recovered = str(found["id"])
        metadata = dict(connection.public_metadata)
        metadata["mesh_node_id"] = recovered
        self.store.upsert_connection(
            provider="cloudflare",
            external_id=connection.external_id,
            label=connection.label,
            status=connection.status,
            account_id=connection.account_id,
            public_metadata=metadata,
            last_error=connection.last_error,
        )
        return recovered

    async def _verify_hostname_route(
        self,
        client: CloudflareClientProtocol,
        account_id: str,
        node_id: str | None,
        connection: ProviderConnection,
    ) -> bool:
        route_id = connection.public_metadata.get("hostname_route_id")
        route: dict[str, Any] | None = None
        if isinstance(route_id, str) and route_id:
            route = await client.get_hostname_route(account_id, route_id)
        else:
            routes = await client.list_hostname_routes(account_id)
            recovered = self._owned_hostname_route_id(routes, node_id)
            if recovered is not None:
                route = await client.get_hostname_route(account_id, recovered)
        if route is None:
            return False
        return self._hostname_route_matches(route, node_id)

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
            dns_adopted = False
            routes_touched = False
            try:
                (
                    dns_record_id,
                    dns_adopted,
                ) = await self._create_or_adopt_placeholder_dns(
                    client, zone_id, hostname
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
                routes_touched = True
                await client.ensure_workers_routes(zone_id, hostname, WORKER_SCRIPT_NAME)
            except Exception as exc:
                cleanup_errors: list[str] = []
                if routes_touched:
                    try:
                        await client.remove_workers_routes(
                            zone_id, hostname, WORKER_SCRIPT_NAME
                        )
                    except CloudflareAPIError as cleanup_exc:
                        # 409: a foreign-owned route was preserved (expected
                        # conflict path, not a cleanup failure).
                        if cleanup_exc.status_code != 409:
                            cleanup_errors.append(type(cleanup_exc).__name__)
                    except Exception as cleanup_exc:
                        cleanup_errors.append(type(cleanup_exc).__name__)
                if not dns_adopted and dns_record_id is not None:
                    cleanup_errors.extend(
                        await self._cleanup_created_dns_record(
                            client,
                            zone_id=zone_id,
                            hostname=hostname,
                            dns_record_id=dns_record_id,
                        )
                    )
                ambiguous_outcome = (
                    isinstance(exc, CloudflareAPIError) and exc.status_code >= 500
                )
                if cleanup_errors or ambiguous_outcome:
                    self._mark_rollback_review(
                        connection,
                        hostname,
                        zone_id,
                        dns_record_id,
                        route_cleanup_pending=routes_touched,
                        dns_cleanup_pending=not dns_adopted,
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
                    "Disconnect Cloudflare to remove its final domain"
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
                recovered_owned_id = self._owned_placeholder_id(
                    records, domain.hostname
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
                if record is not None and not self._dns_record_is_owned(
                    record,
                    record_id=cleanup_domain.external_id,
                    hostname=cleanup_domain.hostname,
                ):
                    raise CloudflareConflictError(
                        "The DNS record is no longer owned by lnSwitchboard and was preserved"
                    )
            await client.remove_workers_routes(
                zone_id, domain.hostname, WORKER_SCRIPT_NAME
            )
            if cleanup_domain.external_id and record is not None:
                latest_record = await client.get_dns_record(
                    zone_id, cleanup_domain.external_id
                )
                if latest_record is not None and not self._dns_record_is_owned(
                    latest_record,
                    record_id=cleanup_domain.external_id,
                    hostname=cleanup_domain.hostname,
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
        account_id = str(connection.account_id)
        node_id = connection.public_metadata.get("mesh_node_id")
        if not isinstance(node_id, str) or not node_id:
            found = await client.find_mesh_node_by_name(
                account_id, connection.external_id
            )
            node_id = (
                str(found["id"])
                if isinstance(found, dict) and found.get("id")
                else None
            )

        owned_records: list[tuple[ConnectedDomain, str]] = []
        route_targets: dict[str, str] = {}
        for domain in connection.domains:
            zone_id = domain.zone_id or str(
                connection.public_metadata.get("zone_id", "")
            )
            if zone_id:
                route_targets[domain.hostname] = zone_id
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
                    route_targets[hostname] = zone_id
                if item.get("dns_cleanup_pending") is True:
                    dns_domains.append(
                        ConnectedDomain(
                            hostname=hostname,
                            status="error",
                            external_id=(
                                dns_record_id
                                if isinstance(dns_record_id, str)
                                else None
                            ),
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
                    recovered_owned_id = self._owned_placeholder_id(
                        records, domain.hostname
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
                if record is not None and not self._dns_record_is_owned(
                    record,
                    record_id=cleanup_domain.external_id,
                    hostname=cleanup_domain.hostname,
                ):
                    raise CloudflareConflictError(
                        "The DNS record is no longer owned by lnSwitchboard and was preserved"
                    )
                if record is not None:
                    owned_records.append((cleanup_domain, zone_id))
            for hostname, zone_id in sorted(route_targets.items()):
                await client.remove_workers_routes(
                    zone_id, hostname, WORKER_SCRIPT_NAME
                )
            for domain, zone_id in owned_records:
                assert domain.external_id is not None
                latest_record = await client.get_dns_record(
                    zone_id, domain.external_id
                )
                if latest_record is not None and not self._dns_record_is_owned(
                    latest_record,
                    record_id=domain.external_id,
                    hostname=domain.hostname,
                ):
                    raise CloudflareConflictError(
                        "The DNS record changed during cleanup and was preserved"
                    )
                if latest_record is not None:
                    await client.delete_dns_record(zone_id, domain.external_id)

            route_id = connection.public_metadata.get("hostname_route_id")
            if not isinstance(route_id, str) or not route_id:
                route_id = self._owned_hostname_route_id(
                    await client.list_hostname_routes(account_id), node_id
                )
            if route_id is not None:
                route = await client.get_hostname_route(account_id, route_id)
                if route is not None:
                    if not self._hostname_route_is_owned(
                        route, route_id=route_id, node_id=node_id
                    ):
                        raise CloudflareConflictError(
                            "The hostname route is no longer owned by lnSwitchboard and was preserved"
                        )
                    await client.delete_hostname_route(account_id, route_id)

            content = await client.get_worker_script_content(
                account_id, WORKER_SCRIPT_NAME
            )
            if content is not None:
                if extract_worker_version(content) is None:
                    raise CloudflareConflictError(
                        "The lnswitchboard-proxy Worker is not managed by lnSwitchboard and was preserved"
                    )
                await client.delete_worker_script(account_id, WORKER_SCRIPT_NAME)

            if node_id is not None:
                await client.delete_mesh_node(account_id, node_id)
            self._remove_node_token()
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
    def _dns_record_is_owned(
        record: dict[str, Any],
        *,
        record_id: str | None,
        hostname: str,
    ) -> bool:
        return (
            record.get("id") == record_id
            and CloudflareService._is_managed_placeholder(record, hostname)
        )

    @staticmethod
    def _is_managed_placeholder(record: dict[str, Any], hostname: str) -> bool:
        try:
            content_matches = ip_address(
                str(record.get("content", "")).strip()
            ) == ip_address(PLACEHOLDER_DNS_CONTENT)
        except ValueError:
            content_matches = False
        return (
            str(record.get("type", "")).upper() == "AAAA"
            and str(record.get("name", "")).lower().rstrip(".") == hostname
            and content_matches
            and record.get("proxied") is True
            and record.get("comment") == MANAGED_COMMENT
        )

    @staticmethod
    def _owned_placeholder_id(
        records: list[dict[str, Any]], hostname: str
    ) -> str | None:
        for record in records:
            if CloudflareService._is_managed_placeholder(record, hostname):
                record_id = str(record.get("id", ""))
                return record_id or None
        return None

    @staticmethod
    def _hostname_route_matches(
        route: dict[str, Any], node_id: str | None
    ) -> bool:
        return (
            str(route.get("hostname", "")).lower().rstrip(".") == INTERNAL_HOSTNAME
            and route.get("comment") == MANAGED_COMMENT
            and (node_id is None or str(route.get("tunnel_id", "")) == node_id)
        )

    @staticmethod
    def _hostname_route_is_owned(
        route: dict[str, Any], *, route_id: str, node_id: str | None
    ) -> bool:
        return route.get("id") == route_id and CloudflareService._hostname_route_matches(
            route, node_id
        )

    @staticmethod
    def _owned_hostname_route_id(
        routes: list[dict[str, Any]], node_id: str | None
    ) -> str | None:
        for route in routes:
            if CloudflareService._hostname_route_matches(route, node_id):
                route_id = str(route.get("id", ""))
                return route_id or None
        return None

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
        if isinstance(api_token, str) and api_token:
            return self.client_factory(api_token)
        grant_id = payload.get("grant_id")
        if isinstance(grant_id, str) and grant_id:
            if self.access_token_resolver is None:
                raise CloudflareServiceError("Cloudflare OAuth access is unavailable")
            access_token = await self.access_token_resolver(grant_id)
            return self.client_factory(access_token)
        raise CloudflareServiceError("Cloudflare API token is unavailable")

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

        Current provisioning records a durable provider connection before any
        remote mutation and does not create these journals. A legacy journal is
        not sufficient proof that its resources are still owned: an operator
        may have repurposed them after a crash. Recovery is therefore
        deliberately non-destructive and requires operator review.
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
    async def _create_or_recover_mesh_node(
        cls,
        client: CloudflareClientProtocol,
        account_id: str,
        node_name: str,
    ) -> str:
        try:
            node = await client.create_mesh_node(account_id, node_name)
            node_id = str(node.get("id", ""))
            if not node_id:
                raise CloudflareServiceError(
                    "Cloudflare mesh node creation outcome could not be reconciled"
                )
            return node_id
        except CloudflareAPIError as exc:
            # Reconcile a successful create whose response was lost; the node
            # name was generated by this run, so a name match is ours.
            try:
                existing = await client.find_mesh_node_by_name(account_id, node_name)
            except CloudflareAPIError:
                existing = None
            if isinstance(existing, dict) and existing.get("id"):
                return str(existing["id"])
            raise exc

    @classmethod
    async def _create_or_adopt_hostname_route(
        cls,
        client: CloudflareClientProtocol,
        account_id: str,
        node_id: str,
    ) -> str:
        try:
            route = await client.create_hostname_route(account_id, node_id)
            route_id = str(route.get("id", ""))
            if not route_id:
                raise CloudflareServiceError(
                    "Cloudflare hostname route creation outcome could not be reconciled"
                )
            return route_id
        except CloudflareAPIError as exc:
            routes = await client.list_hostname_routes(account_id)
            owned_id = cls._owned_hostname_route_id(routes, node_id)
            if owned_id is not None:
                # Reconcile a successful create whose response was lost.
                return owned_id
            raise exc

    @classmethod
    async def _create_or_adopt_placeholder_dns(
        cls,
        client: CloudflareClientProtocol,
        zone_id: str,
        hostname: str,
    ) -> tuple[str | None, bool]:
        """Return (owned placeholder record id, adopted-existing-DNS flag).

        Any pre-existing record for the exact hostname is left untouched: the
        Workers Routes only intercept the two well-known paths, so operator
        DNS keeps serving everything else.
        """
        records = await client.list_dns_records(zone_id, hostname)
        owned_id = cls._owned_placeholder_id(records, hostname)
        if owned_id is not None:
            # Already ours (idempotent retry after an interrupted run).
            return owned_id, False
        if records:
            return None, True
        try:
            record = await client.create_placeholder_dns_record(zone_id, hostname)
            record_id = str(record.get("id", ""))
            if not record_id:
                raise CloudflareServiceError(
                    "Cloudflare DNS creation outcome could not be reconciled"
                )
            return record_id, False
        except CloudflareAPIError as exc:
            records = await client.list_dns_records(zone_id, hostname)
            owned_id = cls._owned_placeholder_id(records, hostname)
            if owned_id is not None:
                # Reconcile a successful create whose response was lost, rather
                # than downgrading lnSwitchboard's record to adopted ownership.
                return owned_id, False
            if records:
                # An operator record appeared concurrently; leave it untouched.
                return None, True
            raise exc

    @staticmethod
    def _mesh_node_name(hostname: str) -> str:
        base = re.sub(r"[^a-z0-9-]+", "-", hostname).strip("-")[:40]
        return f"lnswitchboard-{base}-{random_secrets.token_hex(4)}"

    def _write_node_token(self, token: str) -> None:
        value = token.strip()
        if not value:
            raise CloudflareServiceError("Cloudflare did not return a mesh node token")
        content = f"MESH_NODE_TOKEN={value}\n"
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
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(content.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.token_path)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
            raise

    def _remove_node_token(self) -> None:
        try:
            self.token_path.unlink()
        except FileNotFoundError:
            pass
