"""Minimal, secret-safe Cloudflare REST client for Tunnel provisioning."""

from __future__ import annotations

import copy
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


class CloudflareRollbackError(CloudflareAPIError):
    """A remote mutation whose rollback could not be safely completed."""


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
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        current = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        if not isinstance(current, dict):
            raise CloudflareAPIError(502)
        current_config = current.get("config")
        if current_config is None:
            # Cloudflare represents a valid, not-yet-configured remote tunnel
            # as result.config=null until its first configuration PUT.
            config: dict[str, Any] = {
                "ingress": [{"service": "http_status:404"}]
            }
        elif isinstance(current_config, dict):
            config = copy.deepcopy(current_config)
        else:
            raise CloudflareAPIError(502)
        original_config = copy.deepcopy(config)
        ingress = self._override_ingress_routes(
            config.get("ingress"), hostname, origin_url
        )
        config["ingress"] = ingress
        # Cloudflare exposes a configuration version on GET but its PUT endpoint
        # has no ETag, If-Match, version parameter, or other conditional-write
        # primitive. Re-read immediately before the whole-config PUT and fail
        # closed if an operator changed the snapshot while we prepared it.
        latest = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        latest_config = latest.get("config") if isinstance(latest, dict) else None
        if latest_config != current_config:
            raise CloudflareAPIError(409)
        try:
            await self._request(
                "PUT",
                f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
                json={"config": config},
            )
            verified = await self._request(
                "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
            )
            verified_config = (
                verified.get("config") if isinstance(verified, dict) else None
            )
            if verified_config != config:
                raise CloudflareAPIError(502)
            verified_ingress = (
                verified_config.get("ingress")
                if isinstance(verified_config, dict)
                else None
            )
            if not isinstance(verified_ingress, list):
                raise CloudflareAPIError(502)
            required_paths = {
                r"^/\.well-known/lnurlp/.*$",
                r"^/\.well-known/nostr\.json$",
            }
            configured_routes = [
                route
                for route in verified_ingress
                if isinstance(route, dict)
                and str(route.get("hostname", "")).lower().rstrip(".") == hostname
                and route.get("path") in required_paths
            ]
            if (
                len(configured_routes) != len(required_paths)
                or {route.get("path") for route in configured_routes} != required_paths
                or any(
                    route.get("service") != origin_url for route in configured_routes
                )
            ):
                raise CloudflareAPIError(502)
        except Exception as exc:
            try:
                await self.restore_tunnel_configuration(
                    account_id, tunnel_id, original_config, config
                )
            except Exception as rollback_exc:
                raise CloudflareRollbackError(502) from rollback_exc
            raise exc
        return original_config, copy.deepcopy(config)

    async def restore_tunnel_configuration(
        self,
        account_id: str,
        tunnel_id: str,
        original_config: dict[str, Any],
        written_config: dict[str, Any],
    ) -> None:
        current = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        current_config = current.get("config") if isinstance(current, dict) else None
        if current_config == original_config:
            return
        if current_config != written_config:
            raise CloudflareAPIError(409)
        latest = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        latest_config = latest.get("config") if isinstance(latest, dict) else None
        if latest_config != current_config:
            raise CloudflareAPIError(409)
        await self._request(
            "PUT",
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            json={"config": original_config},
        )
        verified = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        verified_config = verified.get("config") if isinstance(verified, dict) else None
        if verified_config != original_config:
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
                # Cloudflare ingress entries have no ownership marker. Never
                # overwrite or adopt an operator-created exact route, even when
                # its service currently matches ours.
                raise CloudflareAPIError(409)
            routes.append(copied)

        managed_routes = [
            {"hostname": hostname, "path": path, "service": origin_url}
            for path in sorted(managed_paths)
        ]
        # Exact well-known routes must precede broader hostname rules because
        # Cloudflare evaluates ingress in order using first-match semantics.
        return managed_routes + routes + [fallback or {"service": "http_status:404"}]

    async def verify_tunnel_route(
        self,
        account_id: str,
        tunnel_id: str,
        hostname: str,
        origin_url: str,
    ) -> bool:
        result = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        config = result.get("config") if isinstance(result, dict) else None
        ingress = config.get("ingress") if isinstance(config, dict) else None
        if not isinstance(ingress, list) or any(
            not isinstance(route, dict) for route in ingress
        ):
            return False

        normalized = hostname.lower().rstrip(".")
        managed_paths = {
            r"^/\.well-known/lnurlp/.*$",
            r"^/\.well-known/nostr\.json$",
        }
        managed_indexes: dict[str, int] = {}
        for path in managed_paths:
            matches = [
                (index, route)
                for index, route in enumerate(ingress)
                if str(route.get("hostname", "")).lower().rstrip(".")
                == normalized
                and route.get("path") == path
            ]
            if len(matches) != 1 or matches[0][1].get("service") != origin_url:
                return False
            managed_indexes[path] = matches[0][0]

        for path, managed_index in managed_indexes.items():
            for route in ingress[:managed_index]:
                route_hostname = str(route.get("hostname", "")).lower().rstrip(".")
                if not self._ingress_hostname_could_match(route_hostname, normalized):
                    continue
                if (
                    route_hostname == normalized
                    and route.get("path") in managed_paths
                    and route.get("path") != path
                    and route.get("service") == origin_url
                ):
                    continue
                return False
        return True

    @staticmethod
    def _ingress_hostname_could_match(candidate: str, hostname: str) -> bool:
        if candidate in {"", "*"}:
            return True
        if candidate == hostname:
            return True
        if candidate.startswith("*."):
            suffix = candidate[1:]
            return hostname.endswith(suffix) and hostname != suffix[1:]
        return False

    async def remove_tunnel_route(
        self,
        account_id: str,
        tunnel_id: str,
        hostname: str,
        origin_url: str,
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
        if any(not isinstance(route, dict) for route in ingress):
            raise CloudflareAPIError(502)
        managed_paths = {
            r"^/\.well-known/lnurlp/.*$",
            r"^/\.well-known/nostr\.json$",
        }
        normalized = hostname.lower().rstrip(".")
        conflicting_routes = [
            route
            for route in ingress
            if str(route.get("hostname", "")).lower().rstrip(".") == normalized
            and route.get("path") in managed_paths
            and route.get("service") != origin_url
        ]
        if conflicting_routes:
            raise CloudflareAPIError(409)
        retained = [
            dict(route) for route in ingress
            if isinstance(route, dict)
            and not (
                str(route.get("hostname", "")).lower().rstrip(".") == normalized
                and route.get("path") in managed_paths
                and route.get("service") == origin_url
            )
        ]
        if len(retained) == len(ingress):
            return
        latest = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        latest_config = latest.get("config") if isinstance(latest, dict) else None
        if latest_config != config:
            raise CloudflareAPIError(409)
        await self._request(
            "PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            json={"config": {**config, "ingress": retained}},
        )
        verified = await self._request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        verified_config = verified.get("config") if isinstance(verified, dict) else None
        intended_config = {**config, "ingress": retained}
        if verified_config != intended_config:
            raise CloudflareAPIError(502)
        verified_ingress = (
            verified_config.get("ingress") if isinstance(verified_config, dict) else None
        )
        if not isinstance(verified_ingress, list) or any(
            not isinstance(route, dict) for route in verified_ingress
        ):
            raise CloudflareAPIError(502)
        if any(
            str(route.get("hostname", "")).lower().rstrip(".") == normalized
            and route.get("path") in managed_paths
            for route in verified_ingress
        ):
            raise CloudflareAPIError(502)

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
