"""Application-side lifecycle for an isolated zrok public-share connector."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlsplit

from .connection_store import ConnectionStore, ProviderConnection
from .zrok_connector import ZrokConnector, ZrokProtocolError

CLOUD_API_ENDPOINT = "https://api-v2.zrok.io"
_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NAMESPACE_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class ZrokServiceError(RuntimeError):
    pass


class ZrokUnavailableError(ZrokServiceError):
    pass


class ZrokValidationError(ZrokServiceError):
    pass


class ZrokNotFoundError(ZrokServiceError):
    pass


class ZrokOperationError(ZrokServiceError):
    pass


class ZrokService:
    def __init__(
        self,
        *,
        connector: ZrokConnector,
        store: ConnectionStore,
        connector_enabled: bool,
        cloud_api_endpoint: str = CLOUD_API_ENDPOINT,
        public_origin: str = "http://public:21212",
        operation_timeout_seconds: int = 30,
    ) -> None:
        self.connector = connector
        self.store = store
        self.connector_enabled = connector_enabled
        self.cloud_api_endpoint = cloud_api_endpoint
        self.public_origin = public_origin
        self.operation_timeout_seconds = operation_timeout_seconds
        self._operation_lock = asyncio.Lock()

    def setup(self) -> dict[str, object]:
        return {
            "available": self.connector_enabled,
            "modes": ["cloud", "self_hosted"],
            "cloud_api_endpoint": self.cloud_api_endpoint,
            "default_namespace": "public",
            "public_origin": self.public_origin,
            "cloud_interstitial_warning": True,
        }

    async def provision(
        self,
        *,
        mode: str,
        account_token: str,
        api_endpoint: str,
        namespace: str,
        name: str,
    ) -> ProviderConnection:
        self._require_available()
        mode, endpoint, namespace, name = self._validate(
            mode=mode,
            account_token=account_token,
            api_endpoint=api_endpoint,
            namespace=namespace,
            name=name,
        )
        async with self._operation_lock:
            existing = [item for item in self.store.list_connections() if item.provider == "zrok"]
            if existing:
                raise ZrokValidationError("Disconnect the existing zrok connection first")
            operation_id = self.connector.configure(
                {
                    "mode": mode,
                    "account_token": account_token,
                    "api_endpoint": endpoint,
                    "namespace": namespace,
                    "name": name,
                }
            )
            account_token = ""
            status = await self._wait_for_terminal_status(operation_id)
            return self._persist(status, mode=mode, endpoint=endpoint, namespace=namespace, name=name)

    async def refresh(self, connection_id: str) -> ProviderConnection:
        async with self._operation_lock:
            connection = self._get(connection_id)
            self._require_available()
            operation_id = self.connector.refresh()
            try:
                status = await self._wait_for_state(
                    {"refresh_complete", "error"}, operation_id
                )
            except Exception:
                self.connector.clear_refresh()
                raise
            status = dict(status)
            metadata = connection.public_metadata
            expected_namespace = str(metadata.get("namespace", "public"))
            expected_name = str(metadata.get("name", ""))
            if (
                status.get("namespace") != expected_namespace
                or status.get("name") != expected_name
            ):
                raise ZrokOperationError(
                    "zrok connector reported a different reserved name"
                )
            status["state"] = "connected"
            return self._persist(
                status,
                mode=str(metadata.get("mode", "cloud")),
                endpoint=str(metadata.get("api_endpoint", self.cloud_api_endpoint)),
                namespace=expected_namespace,
                name=expected_name,
            )

    async def disconnect(self, connection_id: str) -> bool:
        async with self._operation_lock:
            connection = self._get(connection_id)
            self._require_available()
            metadata = connection.public_metadata
            expected_namespace = str(metadata.get("namespace", "public"))
            expected_name = str(metadata.get("name", ""))
            operation_id = self.connector.disconnect(
                namespace=expected_namespace,
                name=expected_name,
            )
            status = await self._wait_for_state({"disconnected", "error"}, operation_id)
            if (
                status.get("namespace") != expected_namespace
                or status.get("name") != expected_name
            ):
                raise ZrokOperationError(
                    "zrok connector reported a different reserved name"
                )
            return self.store.delete_connection(connection_id)

    def _require_available(self) -> None:
        if not self.connector_enabled:
            raise ZrokUnavailableError("zrok connector is not installed")

    def _get(self, connection_id: str) -> ProviderConnection:
        connection = self.store.get_connection(connection_id)
        if connection is None or connection.provider != "zrok":
            raise ZrokNotFoundError("zrok connection not found")
        return connection

    def _validate_public_endpoint_host(self, hostname: str) -> None:
        try:
            addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ZrokValidationError("zrok API endpoint hostname could not be resolved") from exc
        for address in addresses:
            try:
                ip = ipaddress.ip_address(str(address[4][0]).split("%", 1)[0])
            except ValueError as exc:
                raise ZrokValidationError("zrok API endpoint resolved to an invalid address") from exc
            if not ip.is_global:
                raise ZrokValidationError("zrok API endpoint must resolve only to public addresses")

    def _validate(self, *, mode: str, account_token: str, api_endpoint: str, namespace: str, name: str) -> tuple[str, str, str, str]:
        mode = mode.strip().lower()
        if mode not in {"cloud", "self_hosted"}:
            raise ZrokValidationError("mode must be cloud or self_hosted")
        if not account_token or account_token != account_token.strip() or len(account_token) > 4096:
            raise ZrokValidationError("A valid zrok account token is required")
        endpoint = self.cloud_api_endpoint if mode == "cloud" else api_endpoint.strip().rstrip("/")
        parsed = urlsplit(endpoint)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ZrokValidationError("zrok API endpoint has an invalid port") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or port not in {None, 443}
            or parsed.hostname in {"localhost", "localhost.localdomain"}
            or parsed.hostname.endswith(".local")
        ):
            raise ZrokValidationError("zrok API endpoint must be a public HTTPS origin on port 443 without credentials, path, query, or fragment")
        if mode == "self_hosted":
            self._validate_public_endpoint_host(parsed.hostname)
        namespace = namespace.strip()
        name = name.strip().lower()
        if not _NAMESPACE_RE.fullmatch(namespace):
            raise ZrokValidationError("Invalid zrok namespace token")
        if not _NAME_RE.fullmatch(name):
            raise ZrokValidationError("Name must contain only lowercase letters, numbers, and interior hyphens")
        return mode, endpoint, namespace, name

    async def _wait_for_terminal_status(self, operation_id: str) -> dict[str, object]:
        return await self._wait_for_state({"connected", "error"}, operation_id)

    async def _wait_for_state(
        self, states: set[str], operation_id: str
    ) -> dict[str, object]:
        deadline = asyncio.get_running_loop().time() + self.operation_timeout_seconds
        try:
            status = self.connector.read_status()
        except (OSError, ZrokProtocolError):
            status = None
        if (
            status is not None
            and status.get("operation_id") == operation_id
            and str(status.get("state")) in states
        ):
            if status.get("state") == "error":
                raise ZrokOperationError("zrok connector operation failed")
            return status
        while asyncio.get_running_loop().time() < deadline:
            try:
                status = self.connector.read_status()
            except (OSError, ZrokProtocolError):
                status = None
            if (
                status is not None
                and status.get("operation_id") == operation_id
                and str(status.get("state")) in states
            ):
                if status.get("state") == "error":
                    raise ZrokOperationError("zrok connector operation failed")
                return status
            await asyncio.sleep(0.1)
        raise ZrokOperationError("zrok connector operation timed out")

    def _persist(self, status: dict[str, object], *, mode: str, endpoint: str, namespace: str, name: str) -> ProviderConnection:
        frontend_endpoints = status.get("frontend_endpoints")
        if not isinstance(frontend_endpoints, list) or not (1 <= len(frontend_endpoints) <= 8):
            raise ZrokOperationError("zrok connector did not return a public endpoint")
        hostnames: list[str] = []
        for value in frontend_endpoints:
            if not isinstance(value, str) or len(value) > 2048:
                raise ZrokOperationError("zrok connector returned an invalid public endpoint")
            parsed = urlsplit(str(value))
            try:
                port = parsed.port
            except ValueError as exc:
                raise ZrokOperationError("zrok connector returned an invalid public endpoint") from exc
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
                or port not in {None, 443}
            ):
                raise ZrokOperationError("zrok connector returned an invalid public endpoint")
            hostnames.append(parsed.hostname.lower())
        metadata = {"mode": mode, "api_endpoint": endpoint, "namespace": namespace, "name": name}
        reserved_name = f"{namespace}:{name}"
        connection = self.store.upsert_connection(
            provider="zrok",
            external_id=reserved_name,
            label="zrok Cloud" if mode == "cloud" else "Self-hosted zrok",
            status="connected",
            public_metadata=metadata,
        )
        self.store.replace_domains(
            connection.id,
            [
                {"hostname": hostname, "status": "active", "external_id": reserved_name}
                for hostname in sorted(set(hostnames))
            ],
        )
        return self.store.get_connection(connection.id)  # type: ignore[return-value]
