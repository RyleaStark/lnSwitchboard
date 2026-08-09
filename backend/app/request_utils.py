"""Utilities for extracting client and proxy context from FastAPI requests."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from fastapi import Request


def _first_forwarded_value(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None
    return header_value.split(",")[0].strip()


def _parse_forwarded_header(header_value: Optional[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    first_segment = _first_forwarded_value(header_value)
    if not first_segment:
        return result
    for part in first_segment.split(";"):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        result[key.strip().lower()] = value.strip().strip('"')
    return result


def _strip_brackets(value: str) -> str:
    if value.startswith("[") and "]" in value:
        closing = value.find("]")
        return value[1:closing]
    return value


def _clean_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    cleaned = value.strip().strip('"')
    if cleaned.startswith("for="):
        cleaned = cleaned[4:].strip()
    cleaned = _strip_brackets(cleaned)
    if cleaned.count(":") == 1:
        host, maybe_port = cleaned.rsplit(":", 1)
        if maybe_port.isdigit():
            cleaned = host
    return cleaned or None


def _select_value(
    candidates: List[Tuple[Optional[str], str]],
    default_value: str,
    default_source: str,
) -> Tuple[str, str]:
    for value, source in candidates:
        if value:
            return value, source
    return default_value, default_source


def _select_optional_value(
    candidates: List[Tuple[Optional[str], str]]
) -> Tuple[Optional[str], Optional[str]]:
    for value, source in candidates:
        if value:
            return value, source
    return None, None


def _collect_header_values(request: Request) -> Dict[str, str]:
    header_names = [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-port",
        "cf-connecting-ip",
        "true-client-ip",
        "x-real-ip",
    ]
    collected: Dict[str, str] = {}
    for name in header_names:
        value = request.headers.get(name)
        if value:
            collected[name] = value
    return collected


def _resolve_client_ip(
    request: Request,
) -> Tuple[str, str, List[Dict[str, Optional[str]]]]:
    """Resolve the client IP by walking X-Forwarded-For right-to-left.

    The immediate peer is trusted only when it sits inside TRUSTED_PROXY_CIDRS
    (the security middleware has already stripped forwarding headers from
    untrusted peers). Each hop leftward is accepted only while the current hop
    is itself a trusted proxy, so the leftmost client-supplied entries — which
    Cloudflare and other edges preserve but do not vouch for — can no longer
    spoof the rate-limit identity.
    """
    from ipaddress import ip_address

    from .config import get_settings, parse_trusted_proxy_cidrs

    internal_client = getattr(request.state, "internal_client_ip", None)
    if internal_client:
        return internal_client, "internal-public-gateway", [
            {"source": "internal-public-gateway", "value": internal_client}
        ]
    headers = request.headers
    peer = request.client.host if request.client else None

    def _trusted(value: Optional[str]) -> bool:
        if not value:
            return False
        try:
            address = ip_address(value)
        except ValueError:
            return False
        networks = parse_trusted_proxy_cidrs(get_settings().trusted_proxy_cidrs)
        return any(
            address in network for network in networks if address.version == network.version
        )

    candidates: List[Dict[str, Optional[str]]] = []
    xff_raw = headers.get("x-forwarded-for")
    hops = [part.strip() for part in xff_raw.split(",") if part.strip()] if xff_raw else []
    if xff_raw:
        candidates.append({"source": "x-forwarded-for", "value": hops[-1] if hops else None, "raw": xff_raw})

    current = peer
    for hop in reversed(hops):
        if not _trusted(current):
            break
        cleaned = _clean_ip(hop)
        if not cleaned:
            break
        try:
            ip_address(cleaned)
        except ValueError:
            break
        current = cleaned

    if current:
        source = "x-forwarded-for" if current != peer else "request.client"
        candidates.append({"source": source, "value": current})
        return current, source, candidates

    candidates.append({"source": "default", "value": "unknown"})
    return "unknown", "default", candidates


def _resolve_request_context(request: Request) -> Dict[str, Any]:
    url = request.url.replace(query=None)
    headers = request.headers

    forwarded_raw = headers.get("forwarded")
    forwarded = _parse_forwarded_header(forwarded_raw)
    header_values = _collect_header_values(request)

    proto_candidates: List[Tuple[Optional[str], str]] = [
        (_first_forwarded_value(headers.get("x-forwarded-proto")), "x-forwarded-proto"),
        (forwarded.get("proto"), "Forwarded proto"),
    ]
    proto, proto_source = _select_value(proto_candidates, url.scheme, "request.url")

    host_candidates: List[Tuple[Optional[str], str]] = [
        (_first_forwarded_value(headers.get("x-forwarded-host")), "x-forwarded-host"),
        (forwarded.get("host"), "Forwarded host"),
        (headers.get("host"), "Host header"),
    ]
    host, host_source = _select_value(host_candidates, url.netloc, "request.url")

    port_candidates: List[Tuple[Optional[str], str]] = [
        (_first_forwarded_value(headers.get("x-forwarded-port")), "x-forwarded-port"),
    ]
    port, port_source = _select_optional_value(port_candidates)

    host_includes_port = ":" in host and not host.startswith("[")
    netloc = host
    port_applied = False
    if port and not host_includes_port:
        if not (proto == "http" and port == "80") and not (proto == "https" and port == "443"):
            netloc = f"{host}:{port}"
            port_applied = True

    client_ip, client_source, ip_candidates = _resolve_client_ip(request)

    context: Dict[str, Any] = {
        "original_scheme": url.scheme,
        "original_netloc": url.netloc,
        "proto": proto,
        "proto_source": proto_source,
        "host": host,
        "host_source": host_source,
        "port": port,
        "port_source": port_source,
        "netloc": netloc,
        "port_applied": port_applied,
        "host_includes_port": host_includes_port,
        "headers": header_values,
        "forwarded": forwarded if forwarded else None,
        "forwarded_raw": forwarded_raw,
        "client_ip": client_ip,
        "client_ip_source": client_source,
        "client_ip_candidates": ip_candidates,
        "client_host": request.client.host if request.client else None,
    }
    return context


def get_client_ip(request: Request) -> str:
    ip, _, _ = _resolve_client_ip(request)
    return ip


def get_public_host(request: Request) -> str:
    """Return the host selected by the same precedence as public URL generation."""

    mesh_public_host = getattr(request.state, "mesh_public_host", None)
    if isinstance(mesh_public_host, str) and mesh_public_host:
        return mesh_public_host
    return str(_resolve_request_context(request)["host"])


def get_public_domain(request: Request) -> str:
    """Return a normalized hostname from the trusted public host context."""

    host = get_public_host(request).split(",", 1)[0].strip()
    return (urlsplit(f"//{host}").hostname or "").lower().rstrip(".")


def build_public_url(request: Request) -> str:
    context = _resolve_request_context(request)
    url = request.url.replace(query=None)
    mesh_public_host = getattr(request.state, "mesh_public_host", None)
    if isinstance(mesh_public_host, str) and mesh_public_host:
        return str(url.replace(scheme="https", netloc=mesh_public_host))
    return str(url.replace(scheme=context["proto"], netloc=context["netloc"]))


def get_proxy_debug_info(request: Request) -> Dict[str, Any]:
    context = _resolve_request_context(request)

    resolved: Dict[str, Any] = {
        "proto": context["proto"],
        "host": context["host"],
    }
    if context["port"]:
        resolved["port"] = context["port"]
    if context["netloc"] != context["host"]:
        resolved["netloc"] = context["netloc"]

    debug: Dict[str, Any] = {
        "resolved": resolved,
        "original": {
            "proto": context["original_scheme"],
            "host": context["original_netloc"],
        },
        "sources": {
            "proto": context["proto_source"],
            "host": context["host_source"],
        },
        "client": {
            "ip": context["client_ip"],
            "source": context["client_ip_source"],
            "candidates": context["client_ip_candidates"],
        },
    }

    if context["port"] and context["port_source"]:
        debug["sources"]["port"] = context["port_source"]

    headers = context["headers"]
    if headers:
        debug["headers"] = headers

    if context["forwarded"]:
        debug["forwarded"] = context["forwarded"]

    notes: List[str] = []
    if context["port_applied"]:
        notes.append("port_appended")
    if context["host_includes_port"]:
        notes.append("host_already_includes_port")
    if notes:
        debug["notes"] = notes

    if context["client_host"] and context["client_host"] != context["client_ip"]:
        debug["client"]["connection_host"] = context["client_host"]

    return debug
