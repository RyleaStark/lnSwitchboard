"""Minimal, secret-safe Cloudflare REST client for Mesh + Worker provisioning."""

from __future__ import annotations

import json
from typing import Any

import httpx

from .cloudflare_worker_source import (
    INTERNAL_HOSTNAME,
    MANAGED_COMMENT,
    MESH_BINDING_NAME,
    MESH_NETWORK_ID,
    WORKER_COMPATIBILITY_DATE,
    WORKER_SOURCE,
)

# Originless placeholder content for proxied DNS records lnSwitchboard creates
# when a hostname has no DNS at all. Workers Routes only need any proxied
# record to activate; 100:: (discard-only, RFC 6666) never receives traffic.
PLACEHOLDER_DNS_CONTENT = "100::"


class CloudflareAPIError(RuntimeError):
    """A Cloudflare API failure safe to surface to administrators.

    Provider error messages are carried verbatim for user-facing setup errors
    (owner preference); transport failures and malformed responses raise the
    sanitized fixed message with no provider or exception detail.
    """

    def __init__(
        self,
        status_code: int,
        error_codes: list[int] | None = None,
        messages: list[str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.error_codes = error_codes or []
        self.messages = messages or []
        suffix = (
            f" (codes: {', '.join(map(str, self.error_codes))})"
            if self.error_codes
            else ""
        )
        detail = f": {'; '.join(self.messages)}" if self.messages else ""
        super().__init__(
            f"Cloudflare rejected the request with HTTP {status_code}{suffix}{detail}"
        )


class CloudflareRollbackError(CloudflareAPIError):
    """A remote mutation whose rollback could not be safely completed."""


class CloudflareWorkersRouteProvisionError(CloudflareAPIError):
    """Workers Route provisioning failed after creating known route IDs."""

    def __init__(
        self,
        cause: CloudflareAPIError,
        created_routes: list[tuple[str, str]],
    ) -> None:
        super().__init__(cause.status_code, cause.error_codes, cause.messages)
        self.created_routes = tuple(created_routes)


class CloudflareClient:
    def __init__(
        self,
        api_token: str,
        *,
        base_url: str = "https://api.cloudflare.com/client/v4",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        token = api_token.strip()
        if not token:
            raise ValueError("Cloudflare API token is required")
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._transport = transport

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        raw_text: bool = False,
        allow_not_found: bool = False,
    ) -> Any:
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=15.0,
                transport=self._transport,
            ) as client:
                response = await client.request(
                    method, path, params=params, json=json, files=files
                )
        except httpx.HTTPError as exc:
            raise CloudflareAPIError(503) from exc

        if response.status_code == 404 and allow_not_found:
            return None
        if raw_text:
            if response.is_error:
                codes, messages = self._error_details(response)
                raise CloudflareAPIError(response.status_code, codes, messages)
            return response.text

        payload: dict[str, Any] = {}
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                payload = parsed
        except ValueError:
            pass
        if response.is_error or payload.get("success") is False:
            codes, messages = self._error_details(response, payload)
            raise CloudflareAPIError(response.status_code, codes, messages)
        return payload.get("result")

    @staticmethod
    def _error_details(
        response: httpx.Response, payload: dict[str, Any] | None = None
    ) -> tuple[list[int], list[str]]:
        if payload is None:
            try:
                parsed = response.json()
                payload = parsed if isinstance(parsed, dict) else {}
            except ValueError:
                payload = {}
        codes: list[int] = []
        messages: list[str] = []
        for item in payload.get("errors", []):
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("code"), int):
                codes.append(int(item["code"]))
            if isinstance(item.get("message"), str) and item["message"]:
                messages.append(item["message"])
        return codes, messages

    async def verify_token(self) -> None:
        result = await self._request("GET", "/user/tokens/verify")
        if not isinstance(result, dict) or result.get("status") != "active":
            raise CloudflareAPIError(403)

    async def _list_pages(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        for page in range(1, 101):
            page_params = {**(params or {}), "per_page": 50, "page": page}
            result = await self._request("GET", path, params=page_params)
            items = (
                [item for item in result if isinstance(item, dict)]
                if isinstance(result, list)
                else []
            )
            collected.extend(items)
            if len(items) < 50:
                return collected
        raise CloudflareAPIError(502)

    async def list_accounts(self) -> list[dict[str, Any]]:
        return await self._list_pages("/accounts")

    async def list_zones(self, account_id: str) -> list[dict[str, Any]]:
        return await self._list_pages(
            "/zones",
            params={"account.id": account_id, "status": "active"},
        )

    async def get_zone(self, zone_id: str) -> dict[str, Any]:
        result = await self._request("GET", f"/zones/{zone_id}")
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    # ------------------------------------------------------------------
    # Mesh node (WARP connector)
    # ------------------------------------------------------------------

    async def create_mesh_node(self, account_id: str, name: str) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/accounts/{account_id}/warp_connector",
            json={"name": name},
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def find_mesh_node_by_name(
        self, account_id: str, name: str
    ) -> dict[str, Any] | None:
        result = await self._request(
            "GET",
            f"/accounts/{account_id}/warp_connector",
            params={"name": name, "per_page": 50},
        )
        if not isinstance(result, list):
            raise CloudflareAPIError(502)
        return next(
            (
                item
                for item in result
                if isinstance(item, dict) and item.get("name") == name
            ),
            None,
        )

    async def get_mesh_node(
        self, account_id: str, node_id: str
    ) -> dict[str, Any] | None:
        result = await self._request(
            "GET",
            f"/accounts/{account_id}/warp_connector/{node_id}",
            allow_not_found=True,
        )
        return result if isinstance(result, dict) else None

    async def get_mesh_node_token(self, account_id: str, node_id: str) -> str:
        result = await self._request(
            "GET", f"/accounts/{account_id}/warp_connector/{node_id}/token"
        )
        if isinstance(result, dict) and isinstance(result.get("token"), str):
            result = result["token"]
        if not isinstance(result, str) or not result:
            raise CloudflareAPIError(502)
        return result

    async def list_mesh_node_connections(
        self, account_id: str, node_id: str
    ) -> list[dict[str, Any]]:
        result = await self._request(
            "GET", f"/accounts/{account_id}/warp_connector/{node_id}/connections"
        )
        return list(result) if isinstance(result, list) else []

    async def delete_mesh_node(self, account_id: str, node_id: str) -> None:
        await self._request(
            "DELETE",
            f"/accounts/{account_id}/warp_connector/{node_id}",
            allow_not_found=True,
        )

    # ------------------------------------------------------------------
    # Cloudflare One account prerequisites (device enrollment, device
    # profiles, device/connectivity settings)
    # ------------------------------------------------------------------

    async def list_access_apps(self, account_id: str) -> list[dict[str, Any]]:
        return await self._list_pages(f"/accounts/{account_id}/access/apps")

    async def create_access_app(
        self, account_id: str, app: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/accounts/{account_id}/access/apps",
            json=app,
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def list_device_policies(self, account_id: str) -> list[dict[str, Any]]:
        result = await self._request(
            "GET",
            f"/accounts/{account_id}/devices/policies",
            params={"per_page": 50},
        )
        if not isinstance(result, list):
            raise CloudflareAPIError(502)
        return [item for item in result if isinstance(item, dict)]

    async def get_default_device_policy(self, account_id: str) -> dict[str, Any]:
        result = await self._request(
            "GET", f"/accounts/{account_id}/devices/policy"
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def patch_default_device_policy(
        self, account_id: str, fields: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/accounts/{account_id}/devices/policy",
            json=fields,
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def get_device_settings(self, account_id: str) -> dict[str, Any]:
        result = await self._request(
            "GET", f"/accounts/{account_id}/devices/settings"
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def patch_device_settings(
        self, account_id: str, fields: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/accounts/{account_id}/devices/settings",
            json=fields,
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def get_connectivity_settings(self, account_id: str) -> dict[str, Any]:
        result = await self._request(
            "GET", f"/accounts/{account_id}/zerotrust/connectivity_settings"
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def patch_connectivity_settings(
        self, account_id: str, fields: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/accounts/{account_id}/zerotrust/connectivity_settings",
            json=fields,
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    # ------------------------------------------------------------------
    # Hostname route (internal reachability of the app over the mesh)
    # ------------------------------------------------------------------

    async def create_hostname_route(
        self, account_id: str, node_id: str, hostname: str = INTERNAL_HOSTNAME
    ) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/accounts/{account_id}/zerotrust/routes/hostname",
            json={
                "hostname": hostname,
                "tunnel_id": node_id,
                "comment": MANAGED_COMMENT,
            },
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def list_hostname_routes(
        self, account_id: str, hostname: str | None = None
    ) -> list[dict[str, Any]]:
        params = {"hostname": hostname} if hostname else None
        result = await self._request(
            "GET", f"/accounts/{account_id}/zerotrust/routes/hostname", params=params
        )
        return list(result) if isinstance(result, list) else []

    async def get_hostname_route(
        self, account_id: str, route_id: str
    ) -> dict[str, Any] | None:
        result = await self._request(
            "GET",
            f"/accounts/{account_id}/zerotrust/routes/hostname/{route_id}",
            allow_not_found=True,
        )
        return result if isinstance(result, dict) else None

    async def delete_hostname_route(self, account_id: str, route_id: str) -> None:
        await self._request(
            "DELETE",
            f"/accounts/{account_id}/zerotrust/routes/hostname/{route_id}",
            allow_not_found=True,
        )

    # ------------------------------------------------------------------
    # Proxy Worker script
    # ------------------------------------------------------------------

    async def deploy_proxy_worker(
        self, account_id: str, script_name: str, mesh_ingress_key: str
    ) -> None:
        metadata = {
            "main_module": "worker.js",
            "bindings": [
                {
                    "name": MESH_BINDING_NAME,
                    "type": "vpc_network",
                    "network_id": MESH_NETWORK_ID,
                },
                {
                    "name": "LNS_MESH_INGRESS_KEY",
                    "type": "secret_text",
                    "text": mesh_ingress_key,
                },
            ],
            "compatibility_date": WORKER_COMPATIBILITY_DATE,
        }
        files = {
            "metadata": (None, json.dumps(metadata), "application/json"),
            "worker.js": (
                "worker.js",
                WORKER_SOURCE,
                "application/javascript+module",
            ),
        }
        await self._request(
            "PUT",
            f"/accounts/{account_id}/workers/scripts/{script_name}",
            files=files,
        )

    async def get_worker_script_content(
        self, account_id: str, script_name: str
    ) -> str | None:
        return await self._request(
            "GET",
            f"/accounts/{account_id}/workers/scripts/{script_name}/content/v2",
            raw_text=True,
            allow_not_found=True,
        )

    async def configure_worker_subdomain(
        self, account_id: str, script_name: str
    ) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/accounts/{account_id}/workers/scripts/{script_name}/subdomain",
            json={"enabled": False, "previews_enabled": False},
        )
        return result if isinstance(result, dict) else {}

    async def get_worker_subdomain(
        self, account_id: str, script_name: str
    ) -> dict[str, Any] | None:
        result = await self._request(
            "GET",
            f"/accounts/{account_id}/workers/scripts/{script_name}/subdomain",
            allow_not_found=True,
        )
        if result is None:
            return None
        return result if isinstance(result, dict) else {}

    async def delete_worker_script(self, account_id: str, script_name: str) -> None:
        await self._request(
            "DELETE",
            f"/accounts/{account_id}/workers/scripts/{script_name}",
            allow_not_found=True,
        )

    # ------------------------------------------------------------------
    # Per-hostname Workers Routes
    # ------------------------------------------------------------------

    @staticmethod
    def workers_route_patterns(hostname: str) -> tuple[str, str]:
        return (
            f"{hostname}/.well-known/lnurlp/*",
            f"{hostname}/.well-known/nostr.json",
        )

    async def list_workers_routes(self, zone_id: str) -> list[dict[str, Any]]:
        return await self._list_pages(f"/zones/{zone_id}/workers/routes")

    async def _create_workers_route(
        self, zone_id: str, pattern: str, script_name: str
    ) -> str:
        result = await self._request(
            "POST",
            f"/zones/{zone_id}/workers/routes",
            json={"pattern": pattern, "script": script_name},
        )
        route_id = str(result.get("id", "")) if isinstance(result, dict) else ""
        if not route_id:
            raise CloudflareAPIError(502)
        return route_id

    async def ensure_workers_routes(
        self, zone_id: str, hostname: str, script_name: str
    ) -> list[tuple[str, str]]:
        """Create the two managed routes, adopting our own and refusing foreign.

        Workers Routes use most-specific-wins semantics: these exact path
        patterns take precedence over operator ``host/*`` wildcard routes, so
        foreign wildcard routes can never shadow the two well-known endpoints
        and are left untouched. An identical exact pattern already attached to
        a DIFFERENT script is a 409 conflict and is never overwritten; one
        attached to OUR script is adopted (idempotent retry).
        """
        existing = await self.list_workers_routes(zone_id)
        missing: list[str] = []
        for pattern in self.workers_route_patterns(hostname):
            matches = [
                route for route in existing if route.get("pattern") == pattern
            ]
            if any(route.get("script") == script_name for route in matches):
                continue
            if matches:
                raise CloudflareAPIError(
                    409,
                    messages=[
                        f"Workers route {pattern} is already attached to another script"
                    ],
                )
            missing.append(pattern)

        created: list[tuple[str, str]] = []
        for pattern in missing:
            try:
                route_id = await self._create_workers_route(
                    zone_id, pattern, script_name
                )
                created.append((route_id, pattern))
            except CloudflareAPIError as exc:
                # The create may have succeeded despite a lost/errored
                # response; reconcile by re-listing before surfacing failure.
                refreshed = await self.list_workers_routes(zone_id)
                if not any(
                    route.get("pattern") == pattern
                    and route.get("script") == script_name
                    for route in refreshed
                ):
                    if created:
                        raise CloudflareWorkersRouteProvisionError(
                            exc, created
                        ) from exc
                    raise
                # An errored response is not sufficient proof that this
                # operation created the route, so rollback must preserve it.
                existing = refreshed
        return created

    async def remove_worker_route(
        self,
        zone_id: str,
        route_id: str,
        pattern: str,
        script_name: str,
    ) -> None:
        current = await self._request(
            "GET",
            f"/zones/{zone_id}/workers/routes/{route_id}",
            allow_not_found=True,
        )
        if current is None:
            return
        if (
            not isinstance(current, dict)
            or current.get("pattern") != pattern
            or current.get("script") != script_name
        ):
            raise CloudflareAPIError(
                409,
                messages=[
                    f"Workers route {pattern} changed ownership and was preserved"
                ],
            )
        await self._request(
            "DELETE",
            f"/zones/{zone_id}/workers/routes/{route_id}",
            allow_not_found=True,
        )

    async def verify_workers_routes(
        self, zone_id: str, hostname: str, script_name: str
    ) -> bool:
        existing = await self.list_workers_routes(zone_id)
        for pattern in self.workers_route_patterns(hostname):
            matches = [
                route for route in existing if route.get("pattern") == pattern
            ]
            if len(matches) != 1 or matches[0].get("script") != script_name:
                return False
        return True

    async def remove_workers_routes(
        self, zone_id: str, hostname: str, script_name: str
    ) -> None:
        """Delete only routes matching an exact managed pattern AND our script."""
        existing = await self.list_workers_routes(zone_id)
        for pattern in self.workers_route_patterns(hostname):
            matches = [
                route for route in existing if route.get("pattern") == pattern
            ]
            if any(route.get("script") != script_name for route in matches):
                raise CloudflareAPIError(
                    409,
                    messages=[
                        f"Workers route {pattern} is attached to another script and was preserved"
                    ],
                )
            for route in matches:
                route_id = str(route.get("id", ""))
                if not route_id:
                    raise CloudflareAPIError(502)
                await self.remove_worker_route(
                    zone_id, route_id, pattern, script_name
                )

    # ------------------------------------------------------------------
    # DNS (originless placeholders only; operator records are never touched)
    # ------------------------------------------------------------------

    async def list_dns_records(
        self, zone_id: str, hostname: str
    ) -> list[dict[str, Any]]:
        result = await self._request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"name.exact": hostname, "per_page": 50},
        )
        return list(result) if isinstance(result, list) else []

    async def create_placeholder_dns_record(
        self, zone_id: str, hostname: str
    ) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/zones/{zone_id}/dns_records",
            json={
                "type": "AAAA",
                "name": hostname,
                "content": PLACEHOLDER_DNS_CONTENT,
                "proxied": True,
                "comment": MANAGED_COMMENT,
            },
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def get_dns_record(
        self, zone_id: str, record_id: str
    ) -> dict[str, Any] | None:
        result = await self._request(
            "GET",
            f"/zones/{zone_id}/dns_records/{record_id}",
            allow_not_found=True,
        )
        return result if isinstance(result, dict) else None

    async def delete_dns_record(self, zone_id: str, record_id: str) -> None:
        await self._request(
            "DELETE",
            f"/zones/{zone_id}/dns_records/{record_id}",
            allow_not_found=True,
        )
