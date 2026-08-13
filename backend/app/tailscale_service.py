"""Tailscale Funnel onboarding and reconciliation helpers."""

from __future__ import annotations

import asyncio
import re
import secrets
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import parse_qs, urlsplit

from .connection_store import ConnectionStore, ProviderConnection
from .tailscale_lifecycle_store import TailscaleLifecycle, TailscaleLifecycleStore
from .tailscale_connector import TailscaleConnector, TailscaleProtocolError

DEFAULT_DEVICE_NAME = "lns"
FUNNEL_PORT = 443
FUNNEL_PORT_CAPABILITY = "https://tailscale.com/cap/funnel-ports"
_DEVICE_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def key_expiry_metadata(self_status: Mapping[str, Any]) -> dict[str, object]:
    """Return safe, user-facing key-expiry metadata from Tailscale status."""
    raw_expiry = self_status.get("KeyExpiry")
    if not isinstance(raw_expiry, str) or not raw_expiry:
        return {"key_expiry_enabled": False}
    try:
        expiry = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
    except ValueError:
        return {"key_expiry_enabled": False}
    if expiry.year <= 1:
        return {"key_expiry_enabled": False}
    remaining_seconds = max(0, (expiry - datetime.now(timezone.utc)).total_seconds())
    return {
        "key_expiry_enabled": True,
        "key_expiry_at": expiry.isoformat(),
        "key_expiry_days_remaining": int((remaining_seconds + 86399) // 86400),
    }


class TailscaleServiceError(RuntimeError):
    """Base error safe to map to an administrative API response."""


class TailscaleValidationError(TailscaleServiceError):
    """The caller or provider returned invalid data."""


class TailscaleUnavailableError(TailscaleServiceError):
    """The connector runtime is not installed."""


class TailscaleNotFoundError(TailscaleServiceError):
    """The flow or connection does not exist."""


class TailscaleOperationError(TailscaleServiceError):
    """A fixed runtime operation failed."""


@dataclass
class _LoginFlow:
    device_name: str
    expires_at: float
    auth_url: str | None = None
    authenticated: bool = False


def normalize_device_name(value: str | None) -> str:
    """Return a strict single-label Tailscale hostname."""
    if value is None:
        return DEFAULT_DEVICE_NAME
    normalized = value.strip().lower()
    if len(normalized) > 63 or not _DEVICE_NAME_RE.fullmatch(normalized):
        raise TailscaleValidationError(
            "device name must be 1-63 lowercase letters, numbers, or internal hyphens"
        )
    return normalized


def validate_tailscale_hostname(value: object) -> str:
    """Validate and canonicalize a daemon-owned Funnel hostname."""
    if not isinstance(value, str):
        raise TailscaleValidationError("Tailscale hostname is invalid")
    hostname = value.strip().lower().rstrip(".")
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or len(labels) < 4
        or labels[-2:] != ["ts", "net"]
        or any(
            len(label) > 63 or not _DNS_LABEL_RE.fullmatch(label) for label in labels
        )
    ):
        raise TailscaleValidationError("Tailscale hostname is invalid")
    return hostname


def _capability_keys(status: Mapping[str, Any]) -> set[str]:
    self_status = status.get("Self")
    if not isinstance(self_status, Mapping):
        return set()
    cap_map = self_status.get("CapMap")
    return {str(key) for key in cap_map} if isinstance(cap_map, Mapping) else set()


def _capability_allows_port(capability: str, wanted_port: int) -> bool:
    parsed = urlsplit(capability)
    if (
        f"{parsed.scheme}://{parsed.netloc}{parsed.path}" != FUNNEL_PORT_CAPABILITY
        or parsed.fragment
    ):
        return False
    ports = parse_qs(parsed.query, strict_parsing=False).get("ports", [])
    if not ports:
        return False
    for item in ports[0].split(","):
        if not item:
            continue
        first, separator, last = item.partition("-")
        try:
            lower = int(first)
            upper = int(last) if separator else lower
        except ValueError:
            continue
        if 0 <= lower <= wanted_port <= upper <= 65535:
            return True
    return False


def prerequisite_failures(status: Mapping[str, Any]) -> list[str]:
    """Report fixed prerequisite codes from pinned Tailscale status fields."""
    failures: list[str] = []
    tailnet = status.get("CurrentTailnet")
    magic_dns = isinstance(tailnet, Mapping) and tailnet.get("MagicDNSEnabled") is True
    if not magic_dns:
        failures.append("magic_dns")

    self_status = status.get("Self")
    dns_name: str | None = None
    if isinstance(self_status, Mapping):
        try:
            dns_name = validate_tailscale_hostname(self_status.get("DNSName"))
        except TailscaleValidationError:
            pass
    cert_domains = status.get("CertDomains")
    normalized_cert_domains = (
        {
            str(item).strip().lower().rstrip(".")
            for item in cert_domains
            if isinstance(item, str)
        }
        if isinstance(cert_domains, list)
        else set()
    )

    capabilities = _capability_keys(status)
    if "https" not in capabilities or dns_name not in normalized_cert_domains:
        failures.append("https_certificates")
    if "funnel" not in capabilities:
        failures.append("funnel_node_attribute")
    if not any(
        _capability_allows_port(capability, FUNNEL_PORT)
        for capability in capabilities
        if capability.startswith(FUNNEL_PORT_CAPABILITY)
    ):
        failures.append("funnel_port_443")
    return failures


_AUTH_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{6,256}$")
_DEFAULT_ORIGIN = "http://127.0.0.1:21212"


def _validated_auth_url(value: object) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise TailscaleOperationError(
            "Tailscale returned an invalid authorization response"
        )
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError:
        raise TailscaleOperationError(
            "Tailscale returned an invalid authorization response"
        ) from None
    token = parsed.path.removeprefix("/a/")
    if (
        parsed.scheme != "https"
        or hostname != "login.tailscale.com"
        or port is not None
        or username is not None
        or password is not None
        or not parsed.path.startswith("/a/")
        or "/" in token
        or not _AUTH_TOKEN_RE.fullmatch(token)
        or parsed.query
        or parsed.fragment
    ):
        raise TailscaleOperationError(
            "Tailscale returned an invalid authorization response"
        )
    return value


def funnel_status_matches(
    value: object, hostname: str, public_origin: str = _DEFAULT_ORIGIN
) -> bool:
    if not isinstance(value, Mapping):
        return False
    tcp = value.get("TCP")
    web = value.get("Web")
    allow_funnel = value.get("AllowFunnel")
    if (
        not isinstance(tcp, Mapping)
        or not isinstance(web, Mapping)
        or not isinstance(allow_funnel, Mapping)
    ):
        return False
    tcp_443 = tcp.get(str(FUNNEL_PORT))
    if not isinstance(tcp_443, Mapping) or tcp_443.get("HTTPS") is not True:
        return False
    host_port = f"{hostname}:{FUNNEL_PORT}"
    web_config = web.get(host_port)
    if not isinstance(web_config, Mapping):
        return False
    handlers = web_config.get("Handlers")
    if not isinstance(handlers, Mapping):
        return False
    root_handler = handlers.get("/")
    return (
        isinstance(root_handler, Mapping)
        and root_handler.get("Proxy") == public_origin
        and allow_funnel.get(host_port) is True
    )


class TailscaleService:
    """Coordinate short-lived web login and fail-closed Funnel lifecycle."""

    def __init__(
        self,
        *,
        connector: TailscaleConnector,
        store: ConnectionStore,
        connector_enabled: bool,
        public_origin: str = _DEFAULT_ORIGIN,
        poll_interval_seconds: float = 0.1,
        operation_timeout_seconds: float = 30,
        login_ttl_seconds: float = 300,
    ) -> None:
        self.connector = connector
        self.store = store
        self.connector_enabled = connector_enabled
        self.public_origin = public_origin
        self.poll_interval_seconds = poll_interval_seconds
        self.operation_timeout_seconds = operation_timeout_seconds
        self.login_ttl_seconds = login_ttl_seconds
        self.lifecycle = TailscaleLifecycleStore(
            self.store.path.with_name("tailscale-lifecycle.db")
        )
        self._flows: dict[str, _LoginFlow] = {}
        self._expiry_tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()

    def setup(self) -> dict[str, object]:
        return {
            "available": self.connector_enabled,
            "authorization_method": "web_login",
            "default_device_name": DEFAULT_DEVICE_NAME,
            "device_name_max_length": 63,
            "public_origin": self.public_origin,
            "public_port": FUNNEL_PORT,
            "prerequisites": [
                "magic_dns",
                "https_certificates",
                "funnel_node_attribute",
                "funnel_port_443",
            ],
        }

    def _require_available(self) -> None:
        if not self.connector_enabled:
            raise TailscaleUnavailableError("Tailscale connector is not installed")

    async def _sleep(self) -> None:
        await asyncio.sleep(self.poll_interval_seconds)

    async def _wait_command(
        self,
        command: str,
        operation_id: str,
        *,
        external_id: str | None = None,
        hostname: str | None = None,
        consume_result: bool = True,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self.operation_timeout_seconds
        while time.monotonic() <= deadline:
            status = self.connector.read_command_status(operation_id)
            if (
                status
                and status.get("command") == command
                and status.get("operation_id") == operation_id
                and (external_id is None or status.get("external_id") == external_id)
                and (hostname is None or status.get("hostname") == hostname)
            ):
                state = status.get("state")
                if not isinstance(state, str):
                    raise TailscaleProtocolError(
                        "Tailscale command result state is invalid"
                    )
                if state in {"complete", "started"}:
                    if consume_result:
                        self.connector.consume_command_result(operation_id)
                    return status
                if state == "error":
                    if consume_result:
                        self.connector.consume_command_result(operation_id)
                    raise TailscaleOperationError(
                        str(status.get("error") or "operation_failed")
                    )
            await self._sleep()
        raise TailscaleOperationError(f"Tailscale {command} operation timed out")

    async def _reconcile_disconnect_journal(
        self, journal: TailscaleLifecycle
    ) -> bool:
        result = self.connector.read_command_status(journal.operation_id)
        if result is not None:
            if (
                result.get("command") != "disconnect"
                or result.get("operation_id") != journal.operation_id
                or result.get("external_id") != journal.external_id
                or result.get("hostname") != journal.hostname
            ):
                raise TailscaleOperationError(
                    "Tailscale disconnect result does not match persisted intent"
                )
            if result.get("state") == "error":
                error = str(result.get("error") or "operation_failed")
                self.lifecycle.update(
                    journal.operation_id,
                    phase="prepared",
                    last_error=error,
                )
                raise TailscaleOperationError(error)
            if result.get("state") == "complete":
                self.lifecycle.update(journal.operation_id, phase="provider_acknowledged")

        current = self.lifecycle.get(journal.operation_id)
        if current is None:
            return True
        if current.phase == "provider_acknowledged":
            connection = self.store.get_connection(current.connection_id)
            if connection is not None:
                stored_identity = self._stored_identity(connection)
                if stored_identity != (current.external_id, current.hostname):
                    raise TailscaleOperationError(
                        "Persisted Tailscale disconnect identity changed"
                    )
                try:
                    self.store.delete_connection(current.connection_id)
                except Exception as exc:
                    raise TailscaleOperationError(
                        "Tailscale disconnected, but registry cleanup failed"
                    ) from exc
            self.connector.consume_command_result(current.operation_id)
            self.lifecycle.delete(current.operation_id)
            return True
        return False

    async def _run_disconnect_journal(self, journal: TailscaleLifecycle) -> bool:
        if journal.last_error is None and await self._reconcile_disconnect_journal(journal):
            return True
        try:
            operation_id = self.connector.disconnect(
                external_id=journal.external_id,
                hostname=journal.hostname,
                operation_id=journal.operation_id,
                retry=journal.last_error is not None,
            )
            if operation_id != journal.operation_id:
                raise TailscaleOperationError(
                    "Tailscale connector changed the persisted operation identity"
                )
            self.lifecycle.update(operation_id, phase="command_published")
            try:
                await self._wait_command(
                    "disconnect",
                    operation_id,
                    external_id=journal.external_id,
                    hostname=journal.hostname,
                    consume_result=False,
                )
            except TailscaleOperationError:
                await self._reconcile_disconnect_journal(
                    self.lifecycle.get(operation_id)  # type: ignore[arg-type]
                )
                raise
            self.lifecycle.update(operation_id, phase="provider_acknowledged")
            return await self._reconcile_disconnect_journal(
                self.lifecycle.get(operation_id)  # type: ignore[arg-type]
            )
        except OSError as exc:
            raise TailscaleOperationError(
                "Unable to request fail-closed Tailscale disconnect"
            ) from exc

    def _delete_tailscale_registry(self) -> None:
        try:
            for connection in self.store.list_connections():
                if connection.provider == "tailscale":
                    self.store.delete_connection(connection.id)
        except Exception as exc:
            raise TailscaleOperationError(
                "Tailscale disconnected, but registry cleanup failed"
            ) from exc

    def _stored_identity(
        self, connection: ProviderConnection
    ) -> tuple[str, str]:
        external_id = connection.external_id.strip()
        if not external_id or len(connection.domains) != 1:
            raise TailscaleOperationError("Stored Tailscale identity is invalid")
        hostname = validate_tailscale_hostname(connection.domains[0].hostname)
        return external_id, hostname

    def _runtime_identity(
        self, status: Mapping[str, Any] | None = None
    ) -> tuple[str, str]:
        status = status or self._node_status()
        self_status = status.get("Self")
        if not isinstance(self_status, Mapping):
            raise TailscaleOperationError("Tailscale status is missing node identity")
        external_id = str(
            self_status.get("ID") or self_status.get("PublicKey") or ""
        ).strip()
        raw_hostname = self_status.get("DNSName")
        hostname = (
            raw_hostname.strip().lower().rstrip(".")
            if isinstance(raw_hostname, str)
            else ""
        )
        if not external_id or not hostname or len(hostname) > 253:
            raise TailscaleOperationError("Tailscale status is missing node identity")
        return external_id, hostname

    def _require_matching_runtime_identity(
        self,
        connection: ProviderConnection,
        status: Mapping[str, Any] | None = None,
    ) -> tuple[str, str]:
        stored_external_id, stored_hostname = self._stored_identity(connection)
        runtime_external_id, runtime_hostname = self._runtime_identity(status)
        if (
            runtime_external_id != stored_external_id
            or runtime_hostname != stored_hostname
        ):
            raise TailscaleOperationError(
                "Tailscale runtime identity does not match the stored connection"
            )
        return runtime_external_id, runtime_hostname

    async def _cancel_pending_login(self) -> None:
        try:
            operation_id = self.connector.cancel_login()
        except OSError as exc:
            raise TailscaleOperationError(
                "Unable to request Tailscale login cancellation"
            ) from exc
        await self._wait_command("cancel_login", operation_id)

    async def _disconnect_authenticated_runtime(
        self, *, external_id: str, hostname: str
    ) -> None:
        try:
            operation_id = self.connector.disconnect(
                external_id=external_id, hostname=hostname
            )
            await self._wait_command(
                "disconnect",
                operation_id,
                external_id=external_id,
                hostname=hostname,
            )
        except OSError as exc:
            raise TailscaleOperationError(
                "Unable to request fail-closed Tailscale disconnect"
            ) from exc
        except TailscaleOperationError as exc:
            raise TailscaleOperationError(
                "Unable to disable Funnel before disconnect"
            ) from exc
        self._delete_tailscale_registry()

    async def _cleanup_flow(self, flow_id: str, flow: _LoginFlow) -> None:
        if flow.authenticated:
            external_id, hostname = self._runtime_identity()
            await self._disconnect_authenticated_runtime(
                external_id=external_id, hostname=hostname
            )
        else:
            await self._cancel_pending_login()
        self._forget_flow(flow_id)

    async def _disable_funnel(self) -> None:
        try:
            external_id, hostname = self._runtime_identity()
            operation_id = self.connector.disable_funnel(
                external_id=external_id, hostname=hostname
            )
            await self._wait_command(
                "disable",
                operation_id,
                external_id=external_id,
                hostname=hostname,
            )
        except OSError as exc:
            raise TailscaleOperationError(
                "Unable to request Tailscale Funnel reset"
            ) from exc
        except TailscaleOperationError as exc:
            raise TailscaleOperationError("Unable to reset Tailscale Funnel") from exc

    async def _clear_login_artifact(self) -> None:
        deadline = time.monotonic() + self.operation_timeout_seconds
        while time.monotonic() <= deadline:
            try:
                operation_id = self.connector.clear_login()
            except OSError as exc:
                raise TailscaleOperationError(
                    "Unable to request Tailscale login artifact cleanup"
                ) from exc
            try:
                await self._wait_command("clear_login", operation_id)
                return
            except TailscaleOperationError as exc:
                if "login_active" not in str(exc):
                    raise
            await self._sleep()
        raise TailscaleOperationError("Tailscale clear_login operation timed out")

    def _forget_flow(self, flow_id: str) -> None:
        self._flows.pop(flow_id, None)
        task = self._expiry_tasks.pop(flow_id, None)
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _expire_flow(self, flow_id: str) -> None:
        try:
            while True:
                flow = self._flows.get(flow_id)
                if flow is None:
                    return
                await asyncio.sleep(max(0.0, flow.expires_at - time.monotonic()))
                async with self._lock:
                    flow = self._flows.get(flow_id)
                    if flow is None:
                        return
                    if time.monotonic() < flow.expires_at:
                        continue
                    try:
                        await self._cleanup_flow(flow_id, flow)
                        return
                    except (TailscaleOperationError, TailscaleProtocolError):
                        # Keep the flow guard and retry fail-closed cleanup. A malformed
                        # acknowledgement is not evidence that the runtime is safe.
                        flow.expires_at = time.monotonic() + max(
                            0.1, self.poll_interval_seconds
                        )
        except asyncio.CancelledError:
            return
        finally:
            if self._expiry_tasks.get(flow_id) is asyncio.current_task():
                self._expiry_tasks.pop(flow_id, None)

    def _flow(self, flow_id: str) -> _LoginFlow:
        flow = self._flows.get(flow_id)
        if flow is None:
            raise TailscaleNotFoundError("Tailscale login flow was not found")
        return flow

    def _login_snapshot(self, flow: _LoginFlow) -> tuple[str | None, str | None]:
        backend_state: str | None = "Running" if flow.authenticated else None
        auth_url: str | None = None
        for record in self.connector.read_login_records():
            state = record.get("BackendState")
            if isinstance(state, str):
                backend_state = state
            if "AuthURL" in record and backend_state != "Running":
                auth_url = _validated_auth_url(record.get("AuthURL"))
        if backend_state == "Running":
            flow.authenticated = True
            flow.auth_url = None
        elif auth_url is not None:
            flow.auth_url = auth_url
        return backend_state, flow.auth_url

    async def begin_login(
        self, device_name: str | None
    ) -> tuple[str, dict[str, object]]:
        self._require_available()
        normalized = normalize_device_name(device_name)
        async with self._lock:
            if self._flows or any(
                connection.provider == "tailscale"
                for connection in self.store.list_connections()
            ):
                raise TailscaleOperationError(
                    "A Tailscale login or connection is already in progress"
                )
            flow_id = secrets.token_urlsafe(32)
            flow = _LoginFlow(
                device_name=normalized,
                expires_at=time.monotonic() + self.login_ttl_seconds,
            )
            self._flows[flow_id] = flow
            self._expiry_tasks[flow_id] = asyncio.create_task(
                self._expire_flow(flow_id)
            )
            try:
                operation_id = self.connector.begin_login(normalized)
                await self._wait_command("begin_login", operation_id)
            except OSError as exc:
                await self._cleanup_flow(flow_id, flow)
                raise TailscaleOperationError(
                    "Unable to start Tailscale login"
                ) from exc
            deadline = time.monotonic() + self.operation_timeout_seconds
            try:
                while time.monotonic() <= deadline:
                    backend_state, auth_url = self._login_snapshot(flow)
                    if auth_url:
                        return flow_id, {
                            "state": "needs_login",
                            "device_name": normalized,
                            "auth_url": auth_url,
                            "expires_in_seconds": self.login_ttl_seconds,
                        }
                    if backend_state == "Running":
                        return flow_id, await self._finalize_running(flow)
                    await self._sleep()
            except (TailscaleProtocolError, TailscaleOperationError):
                await self._cleanup_flow(flow_id, flow)
                raise
            await self._cleanup_flow(flow_id, flow)
            raise TailscaleOperationError("Tailscale authorization response timed out")

    async def poll_login(self, flow_id: str) -> dict[str, object]:
        self._require_available()
        async with self._lock:
            flow = self._flow(flow_id)
            if time.monotonic() >= flow.expires_at:
                await self._cleanup_flow(flow_id, flow)
                return {"state": "expired", "device_name": flow.device_name}
            try:
                backend_state, auth_url = self._login_snapshot(flow)
            except (TailscaleProtocolError, TailscaleOperationError):
                await self._cleanup_flow(flow_id, flow)
                raise
            if backend_state == "Running":
                try:
                    response = await self._finalize_running(flow)
                except (TailscaleServiceError, TailscaleProtocolError):
                    await self._cleanup_flow(flow_id, flow)
                    raise
                if response["state"] == "connected":
                    self._forget_flow(flow_id)
                return response
            return {
                "state": "needs_login",
                "device_name": flow.device_name,
                "auth_url": auth_url,
                "expires_in_seconds": max(0, int(flow.expires_at - time.monotonic())),
            }

    async def cancel_login(self, flow_id: str) -> bool:
        async with self._lock:
            flow = self._flow(flow_id)
            await self._cleanup_flow(flow_id, flow)
            return True

    def _node_status(self) -> dict[str, Any]:
        try:
            status = self.connector.read_node_status()
        except OSError as exc:
            raise TailscaleOperationError(
                "Unable to read Tailscale node status"
            ) from exc
        if status is None or status.get("BackendState") != "Running":
            raise TailscaleOperationError("Tailscale node is not connected")
        return status

    async def _finalize_running(
        self,
        flow: _LoginFlow,
        *,
        preserve_existing_on_prerequisite_failure: bool = False,
    ) -> dict[str, object]:
        status = self._node_status()
        self_status = status.get("Self")
        if not isinstance(self_status, Mapping):
            raise TailscaleOperationError("Tailscale status is missing node identity")
        try:
            hostname = validate_tailscale_hostname(self_status.get("DNSName"))
        except TailscaleValidationError as exc:
            raise TailscaleOperationError(
                "Tailscale returned an invalid authoritative hostname"
            ) from exc
        missing = prerequisite_failures(status)
        if missing:
            if preserve_existing_on_prerequisite_failure:
                raise TailscaleOperationError(
                    "Tailscale status is missing required Funnel prerequisites"
                )
            await self._disable_funnel()
            try:
                self._register_prerequisite_connection(
                    status, flow.device_name, hostname, missing
                )
            except TailscaleServiceError:
                raise
            except Exception as exc:
                raise TailscaleOperationError(
                    "Unable to persist Tailscale prerequisite state"
                ) from exc
            if self.connector.has_login_artifact():
                await self._clear_login_artifact()
            return {
                "state": "prerequisites_required",
                "device_name": flow.device_name,
                "hostname": hostname,
                "missing_prerequisites": missing,
            }

        try:
            external_id = str(
                self_status.get("ID") or self_status.get("PublicKey") or ""
            ).strip()
            if not external_id:
                raise TailscaleOperationError("Tailscale status is missing node identity")
            operation_id = self.connector.enable_funnel(
                external_id=external_id, hostname=hostname
            )
            await self._wait_command(
                "enable",
                operation_id,
                external_id=external_id,
                hostname=hostname,
            )
        except OSError as exc:
            raise TailscaleOperationError(
                "Unable to request Tailscale Funnel enablement"
            ) from exc
        except TailscaleOperationError as exc:
            raise TailscaleOperationError("Unable to enable Tailscale Funnel") from exc

        deadline = time.monotonic() + self.operation_timeout_seconds
        while time.monotonic() <= deadline:
            try:
                funnel_status = self.connector.read_funnel_status()
            except OSError as exc:
                raise TailscaleOperationError(
                    "Unable to read Tailscale Funnel status"
                ) from exc
            if funnel_status is not None and funnel_status_matches(
                funnel_status, hostname, self.public_origin
            ):
                try:
                    connection = self._register_connection(
                        status, flow.device_name, hostname
                    )
                except TailscaleServiceError:
                    raise
                except Exception as exc:
                    raise TailscaleOperationError(
                        "Unable to persist Tailscale connection"
                    ) from exc
                if self.connector.has_login_artifact():
                    await self._clear_login_artifact()
                return {"state": "connected", "connection": asdict(connection)}
            await self._sleep()
        raise TailscaleOperationError("Tailscale Funnel status did not reconcile")

    def _register_prerequisite_connection(
        self,
        status: Mapping[str, Any],
        device_name: str,
        hostname: str,
        missing: list[str],
    ) -> ProviderConnection:
        self_status = status["Self"]
        external_id = str(
            self_status.get("ID") or self_status.get("PublicKey") or ""
        ).strip()
        if not external_id:
            raise TailscaleOperationError("Tailscale status is missing node identity")
        connection = self.store.upsert_connection(
            provider="tailscale",
            external_id=external_id,
            label="Tailscale Funnel",
            status="error",
            public_metadata={"device_name": device_name, "origin": self.public_origin, **key_expiry_metadata(self_status)},
            last_error="Missing Tailscale prerequisites: " + ", ".join(missing),
        )
        self.store.replace_domains(
            connection.id,
            [
                {
                    "hostname": hostname,
                    "status": "error",
                    "last_error": connection.last_error,
                }
            ],
        )
        registered = self.store.get_connection(connection.id)
        if registered is None:  # pragma: no cover
            raise TailscaleOperationError("Tailscale connection registration failed")
        return registered

    def _register_connection(
        self, status: Mapping[str, Any], device_name: str, hostname: str
    ) -> ProviderConnection:
        self_status = status["Self"]
        external_id = str(
            self_status.get("ID") or self_status.get("PublicKey") or ""
        ).strip()
        if not external_id:
            raise TailscaleOperationError("Tailscale status is missing node identity")
        connection = self.store.upsert_connection(
            provider="tailscale",
            external_id=external_id,
            label="Tailscale Funnel",
            status="connected",
            public_metadata={"device_name": device_name, "origin": self.public_origin, **key_expiry_metadata(self_status)},
        )
        self.store.replace_domains(
            connection.id,
            [{"hostname": hostname, "status": "active"}],
        )
        registered = self.store.get_connection(connection.id)
        if registered is None:  # pragma: no cover - defensive database check
            raise TailscaleOperationError("Tailscale connection registration failed")
        return registered

    async def _observe_existing_funnel(
        self,
        connection: ProviderConnection,
        status: Mapping[str, Any],
        device_name: str,
        hostname: str,
    ) -> ProviderConnection:
        missing = prerequisite_failures(status)
        if missing:
            raise TailscaleOperationError(
                "Tailscale status is missing required Funnel prerequisites"
            )
        deadline = time.monotonic() + self.operation_timeout_seconds
        while time.monotonic() <= deadline:
            try:
                funnel_status = self.connector.read_funnel_status()
            except OSError as exc:
                raise TailscaleOperationError(
                    "Unable to read Tailscale Funnel status"
                ) from exc
            if funnel_status is not None and funnel_status_matches(
                funnel_status, hostname, self.public_origin
            ):
                return connection
            await self._sleep()
        raise TailscaleOperationError("Tailscale Funnel status did not reconcile")

    async def refresh(self, connection_id: str) -> ProviderConnection:
        self._require_available()
        async with self._lock:
            existing = self.store.get_connection(connection_id)
            if existing is None or existing.provider != "tailscale":
                raise TailscaleNotFoundError("Tailscale connection was not found")
            device_name = normalize_device_name(
                str(existing.public_metadata.get("device_name") or DEFAULT_DEVICE_NAME)
            )
            status = self._node_status()
            self._require_matching_runtime_identity(existing, status)
            self_status = status["Self"]
            hostname = validate_tailscale_hostname(self_status.get("DNSName"))
            return await self._observe_existing_funnel(
                existing, status, device_name, hostname
            )

    async def recover_incomplete_provisioning(self) -> None:
        if not self.connector_enabled:
            return
        has_artifact = self.connector.has_login_artifact()
        async with self._lock:
            for journal in self.lifecycle.list_pending():
                try:
                    await self._run_disconnect_journal(journal)
                except (TailscaleOperationError, TailscaleProtocolError):
                    # Keep the durable intent for the next startup or explicit retry.
                    return
            try:
                status = self.connector.read_node_status()
            except (TailscaleProtocolError, OSError):
                # Startup may race the connector sidecar. Never convert a
                # transiently unavailable/malformed status snapshot into a
                # durable disconnect marker: the sidecar can consume that
                # marker later and erase an otherwise valid node identity.
                return
            if status is None:
                return
            backend_state = status.get("BackendState")
            if backend_state == "NeedsLogin":
                if has_artifact:
                    await self._cancel_pending_login()
                return
            if backend_state != "Running":
                return
            self_status = status.get("Self")
            if not isinstance(self_status, Mapping):
                return
            flow = _LoginFlow(
                device_name=DEFAULT_DEVICE_NAME,
                expires_at=time.monotonic(),
                authenticated=True,
            )
            try:
                existing = next(
                    (
                        item
                        for item in self.store.list_connections()
                        if item.provider == "tailscale"
                    ),
                    None,
                )
                if existing is not None:
                    self._require_matching_runtime_identity(existing, status)
                stored_name = (
                    existing.public_metadata.get("device_name") if existing else None
                )
                dns_name = str(self_status.get("DNSName") or "").rstrip(".")
                flow.device_name = normalize_device_name(
                    str(
                        stored_name
                        or self_status.get("HostName")
                        or dns_name.split(".", 1)[0]
                    )
                )
                if existing is not None:
                    hostname = validate_tailscale_hostname(self_status.get("DNSName"))
                    await self._observe_existing_funnel(
                        existing, status, flow.device_name, hostname
                    )
                else:
                    await self._finalize_running(flow)
            except (TailscaleServiceError, TailscaleProtocolError):
                raise
            except Exception as exc:
                raise TailscaleOperationError(
                    "Unable to reconcile authenticated Tailscale runtime"
                ) from exc

    async def disconnect(self, connection_id: str) -> bool:
        self._require_available()
        async with self._lock:
            connection = self.store.get_connection(connection_id)
            if connection is None or connection.provider != "tailscale":
                raise TailscaleNotFoundError("Tailscale connection was not found")
            external_id, hostname = self._stored_identity(connection)
            journal = self.lifecycle.create_disconnect(
                operation_id=uuid.uuid4().hex,
                connection_id=connection_id,
                external_id=external_id,
                hostname=hostname,
            )
            try:
                return await self._run_disconnect_journal(journal)
            except TailscaleProtocolError as exc:
                raise TailscaleOperationError(
                    "Tailscale returned an invalid disconnect result"
                ) from exc
            except TailscaleOperationError as exc:
                if "registry cleanup failed" in str(exc):
                    raise
                raise TailscaleOperationError(
                    "Unable to disable Funnel before disconnect"
                ) from exc
