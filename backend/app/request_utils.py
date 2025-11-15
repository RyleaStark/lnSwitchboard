"""Utilities for extracting client and proxy context from FastAPI requests."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

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
    headers = request.headers
    forwarded_raw = headers.get("forwarded")
    forwarded = _parse_forwarded_header(forwarded_raw)

    candidate_specs: List[Tuple[str, Optional[str], Optional[str]]] = [
        ("Forwarded for", forwarded.get("for"), forwarded_raw),
        ("cf-connecting-ip", headers.get("cf-connecting-ip"), None),
        ("true-client-ip", headers.get("true-client-ip"), None),
        ("x-forwarded-for", headers.get("x-forwarded-for"), headers.get("x-forwarded-for")),
        ("x-real-ip", headers.get("x-real-ip"), None),
    ]

    candidates: List[Dict[str, Optional[str]]] = []
    for label, raw_value, raw_header in candidate_specs:
        cleaned_value = _clean_ip(
            raw_value if label != "x-forwarded-for" else _first_forwarded_value(raw_value)
        )
        record: Dict[str, Optional[str]] = {"source": label, "value": cleaned_value}
        if raw_value and raw_value != cleaned_value:
            record["raw"] = raw_value
        if label == "x-forwarded-for" and raw_header:
            record["raw"] = raw_header
        if label == "Forwarded for" and forwarded_raw:
            record["raw_header"] = forwarded_raw
        candidates.append(record)
        if cleaned_value:
            return cleaned_value, label, candidates

    client_host = request.client.host if request.client else None
    candidates.append({"source": "request.client", "value": client_host})
    if client_host:
        return client_host, "request.client", candidates

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


def build_public_url(request: Request) -> str:
    context = _resolve_request_context(request)
    url = request.url.replace(query=None)
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
