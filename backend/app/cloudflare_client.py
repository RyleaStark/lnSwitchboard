"""Minimal, secret-safe Cloudflare REST client for Tunnel provisioning."""

from __future__ import annotations

from typing import Any

import httpx


class CloudflareAPIError(RuntimeError):
    """A sanitized Cloudflare API failure safe to surface to administrators."""

    def __init__(self, status_code: int, error_codes: list[int] | None = None) -> None:
        self.status_code = status_code
        self.error_codes = error_codes or []
        suffix = (
            f" (codes: {', '.join(map(str, self.error_codes))})"
            if self.error_codes
            else ""
        )
        super().__init__(
            f"Cloudflare rejected the request with HTTP {status_code}{suffix}"
        )


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
        allow_not_found: bool = False,
    ) -> Any:
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=15.0,
                transport=self._transport,
            ) as client:
                response = await client.request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            raise CloudflareAPIError(503) from exc

        payload: dict[str, Any] = {}
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                payload = parsed
        except ValueError:
            pass
        if response.status_code == 404 and allow_not_found:
            return None
        if response.is_error or payload.get("success") is False:
            codes = [
                int(item["code"])
                for item in payload.get("errors", [])
                if isinstance(item, dict) and isinstance(item.get("code"), int)
            ]
            raise CloudflareAPIError(response.status_code, codes)
        return payload.get("result")

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

    async def list_dns_records(
        self, zone_id: str, hostname: str
    ) -> list[dict[str, Any]]:
        result = await self._request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"name.exact": hostname, "per_page": 50},
        )
        return list(result) if isinstance(result, list) else []

    async def create_tunnel(self, account_id: str, name: str) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/accounts/{account_id}/cfd_tunnel",
            json={"name": name, "config_src": "cloudflare"},
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def find_tunnel_by_name(
        self, account_id: str, name: str
    ) -> dict[str, Any] | None:
        result = await self._request(
            "GET",
            f"/accounts/{account_id}/cfd_tunnel",
            params={"name": name, "is_deleted": "false", "per_page": 50},
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

    async def get_tunnel(
        self, account_id: str, tunnel_id: str
    ) -> dict[str, Any] | None:
        result = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}", allow_not_found=True
        )
        return result if isinstance(result, dict) else None

    async def configure_tunnel(
        self,
        account_id: str,
        tunnel_id: str,
        hostname: str,
        origin_url: str,
    ) -> None:
        current = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        if not isinstance(current, dict) or not isinstance(current.get("config"), dict):
            raise CloudflareAPIError(502)
        config = dict(current["config"])
        ingress = self._override_ingress_routes(
            config.get("ingress"), hostname, origin_url
        )
        config["ingress"] = ingress
        await self._request(
            "PUT",
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            json={"config": config},
        )
        verified = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        verified_config = verified.get("config") if isinstance(verified, dict) else None
        verified_ingress = (
            verified_config.get("ingress") if isinstance(verified_config, dict) else None
        )
        if not isinstance(verified_ingress, list):
            raise CloudflareAPIError(502)
        required_paths = {
            r"^/\.well-known/lnurlp/.*$",
            r"^/\.well-known/nostr\.json$",
        }
        configured_paths = {
            route.get("path")
            for route in verified_ingress
            if isinstance(route, dict)
            and route.get("hostname") == hostname
            and route.get("service") == origin_url
        }
        if not required_paths.issubset(configured_paths):
            raise CloudflareAPIError(502)

    @staticmethod
    def _override_ingress_routes(
        ingress: Any, hostname: str, origin_url: str
    ) -> list[dict[str, Any]]:
        """Set the two lnSwitchboard Zero Trust public-hostname routes."""
        if ingress is None:
            ingress = []
        if not isinstance(ingress, list):
            raise CloudflareAPIError(502)

        managed_paths = {
            r"^/\.well-known/lnurlp/.*$",
            r"^/\.well-known/nostr\.json$",
        }
        routes: list[dict[str, Any]] = []
        fallback: dict[str, Any] | None = None
        for index, route in enumerate(ingress):
            if not isinstance(route, dict):
                raise CloudflareAPIError(502)
            copied = dict(route)
            route_hostname = copied.get("hostname")
            if route_hostname is None:
                if index != len(ingress) - 1 or fallback is not None:
                    raise CloudflareAPIError(502)
                fallback = copied
                continue
            if not isinstance(route_hostname, str):
                raise CloudflareAPIError(502)
            route_path = copied.get("path")
            if (
                route_hostname.strip().lower().rstrip(".") == hostname
                and route_path in managed_paths
            ):
                continue
            routes.append(copied)

        routes.extend(
            {"hostname": hostname, "path": path, "service": origin_url}
            for path in sorted(managed_paths)
        )
        routes.append(fallback or {"service": "http_status:404"})
        return routes

    async def remove_tunnel_route(
        self, account_id: str, tunnel_id: str, hostname: str
    ) -> None:
        current = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        config = current.get("config") if isinstance(current, dict) else None
        if not isinstance(config, dict):
            raise CloudflareAPIError(502)
        ingress = config.get("ingress")
        if not isinstance(ingress, list):
            raise CloudflareAPIError(502)
        managed_paths = {
            r"^/\.well-known/lnurlp/.*$",
            r"^/\.well-known/nostr\.json$",
        }
        normalized = hostname.lower().rstrip(".")
        retained = [
            dict(route) for route in ingress
            if isinstance(route, dict)
            and not (
                str(route.get("hostname", "")).lower().rstrip(".") == normalized
                and route.get("path") in managed_paths
            )
        ]
        if len(retained) == len(ingress):
            return
        await self._request(
            "PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            json={"config": {**config, "ingress": retained}},
        )

    async def disable_tunnel(self, account_id: str, tunnel_id: str) -> None:
        await self._request(
            "PUT",
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            json={"config": {"ingress": [{"service": "http_status:404"}]}},
            allow_not_found=True,
        )

    async def create_dns_record(
        self,
        zone_id: str,
        hostname: str,
        tunnel_id: str,
    ) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/zones/{zone_id}/dns_records",
            json={
                "type": "CNAME",
                "name": hostname,
                "content": f"{tunnel_id}.cfargotunnel.com",
                "proxied": True,
                "comment": "Managed by lnSwitchboard",
            },
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError(502)
        return result

    async def get_tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        result = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token"
        )
        if not isinstance(result, str) or not result:
            raise CloudflareAPIError(502)
        return result

    async def list_tunnel_connections(
        self,
        account_id: str,
        tunnel_id: str,
    ) -> list[dict[str, Any]]:
        result = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections"
        )
        return list(result) if isinstance(result, list) else []

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

    async def cleanup_tunnel_connections(self, account_id: str, tunnel_id: str) -> None:
        await self._request(
            "DELETE",
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections",
            json={},
            allow_not_found=True,
        )

    async def delete_tunnel(self, account_id: str, tunnel_id: str) -> None:
        await self._request(
            "DELETE",
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}",
            allow_not_found=True,
        )
