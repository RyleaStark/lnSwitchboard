"""Helpers for validating and proxying forwarded Lightning Addresses."""

from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote, urlsplit

from .config import get_settings
from .outbound_security import (
    OutboundHTTPStatusError,
    UnsafeOutboundTarget,
    ensure_public_endpoint,
    get_json_from_pinned_endpoint,
)


LOCAL_PART_PATTERN = re.compile(r"^[a-z0-9._+-]+$")
DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")
HTTP_SCHEMES = {"http", "https"}
DEFAULT_TIMEOUT_SECONDS = 6.0


class ForwardingTargetError(ValueError):
    """Raised when a forwarded Lightning Address cannot be used."""


@dataclass(frozen=True)
class ForwardingTarget:
    address: str
    local_part: str
    domain: str
    discovery_url: str
    payload: dict[str, Any]


def normalize_forward_to(value: Optional[str]) -> str:
    if not isinstance(value, str):
        raise ForwardingTargetError("Forwarding address is required")
    candidate = value.strip().lower()
    if not candidate:
        raise ForwardingTargetError("Forwarding address is required")
    if "://" in candidate or "/" in candidate or " " in candidate:
        raise ForwardingTargetError("Forwarding address must be a Lightning Address like user@example.com")
    if candidate.count("@") != 1:
        raise ForwardingTargetError("Forwarding address must include one @")
    local_part, domain = candidate.split("@", 1)
    domain = domain.rstrip(".")
    if not local_part or not domain:
        raise ForwardingTargetError("Forwarding address must include a local-part and domain")
    if not LOCAL_PART_PATTERN.fullmatch(local_part):
        raise ForwardingTargetError("Forwarding local-part may include letters, numbers, dot, dash, underscore, or plus")
    if not DOMAIN_PATTERN.fullmatch(domain):
        raise ForwardingTargetError("Forwarding domain may include letters, numbers, dashes, and dots")
    return f"{local_part}@{domain}"


def build_lnurlp_discovery_url(address: str) -> str:
    normalized = normalize_forward_to(address)
    local_part, domain = normalized.split("@", 1)
    encoded_local = quote(local_part, safe="._-+~")
    return f"https://{domain}/.well-known/lnurlp/{encoded_local}"


def is_http_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value.strip())
    return parsed.scheme.lower() in HTTP_SCHEMES and bool(parsed.netloc)


def is_usable_verify_url(value: Any) -> bool:
    return is_http_url(value)


def extract_payment_hash_from_verify_url(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value.strip())
    candidate = parsed.path.rstrip("/").rsplit("/", 1)[-1].lower()
    if len(candidate) == 64 and all(ch in "0123456789abcdef" for ch in candidate):
        return candidate
    return None


def validate_discovery_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ForwardingTargetError("Forwarding target did not return a JSON object")
    status_value = payload.get("status")
    if isinstance(status_value, str) and status_value.upper() == "ERROR":
        reason = payload.get("reason") if isinstance(payload.get("reason"), str) else "Forwarding target returned an error"
        raise ForwardingTargetError(reason)
    if payload.get("tag") != "payRequest":
        raise ForwardingTargetError("Forwarding target is not an LNURL-pay endpoint")
    if not is_http_url(payload.get("callback")):
        raise ForwardingTargetError("Forwarding target did not return a valid callback")
    min_sendable = payload.get("minSendable")
    max_sendable = payload.get("maxSendable")
    if not isinstance(min_sendable, int) or not isinstance(max_sendable, int):
        raise ForwardingTargetError("Forwarding target did not return valid sendable limits")
    if min_sendable < 0 or max_sendable < min_sendable:
        raise ForwardingTargetError("Forwarding target returned invalid sendable limits")
    metadata = payload.get("metadata")
    if not isinstance(metadata, str) or not metadata.strip():
        raise ForwardingTargetError("Forwarding target did not return metadata")
    try:
        metadata_entries = json.loads(metadata)
    except json.JSONDecodeError as exc:
        raise ForwardingTargetError("Forwarding target returned invalid metadata") from exc
    if not isinstance(metadata_entries, list) or not metadata_entries:
        raise ForwardingTargetError("Forwarding target returned invalid metadata")
    return dict(payload)


def validate_invoice_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ForwardingTargetError("Forwarding target did not return a JSON object")
    status_value = payload.get("status")
    if isinstance(status_value, str) and status_value.upper() == "ERROR":
        reason = payload.get("reason") if isinstance(payload.get("reason"), str) else "Forwarding target returned an error"
        raise ForwardingTargetError(reason)
    payment_request = payload.get("pr")
    if not isinstance(payment_request, str) or not payment_request.strip():
        raise ForwardingTargetError("Forwarding target did not return an invoice")
    return dict(payload)


async def _fetch_json(
    url: str,
    *,
    params: Any = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> Any:
    """Fetch JSON through the pinned outbound policy.

    The URL is resolved and rejected when it reaches credentials or
    non-public networks (unless ALLOW_PRIVATE_FORWARDING opts in), then the
    request connects to the validated address directly — no redirects, no
    second DNS lookup, and a bounded response size.
    """
    try:
        connect_host = await ensure_public_endpoint(
            url,
            allowed_schemes=("http", "https"),
            allow_private=get_settings().allow_private_forwarding,
        )
        return await get_json_from_pinned_endpoint(
            url,
            connect_host=connect_host,
            params=params,
            timeout=timeout_seconds,
        )
    except UnsafeOutboundTarget as exc:
        raise ForwardingTargetError(
            "Forwarding target is not an allowed public endpoint"
        ) from exc
    except OutboundHTTPStatusError as exc:
        raise ForwardingTargetError(
            f"Forwarding target returned HTTP {exc.status_code}"
        ) from exc
    except (TimeoutError, socket.timeout) as exc:
        raise ForwardingTargetError("Forwarding target timed out") from exc
    except OSError as exc:
        raise ForwardingTargetError("Forwarding target could not be reached") from exc


async def fetch_forwarding_discovery(forward_to: str) -> ForwardingTarget:
    normalized = normalize_forward_to(forward_to)
    local_part, domain = normalized.split("@", 1)
    discovery_url = build_lnurlp_discovery_url(normalized)
    payload = validate_discovery_payload(await _fetch_json(discovery_url))
    return ForwardingTarget(
        address=normalized,
        local_part=local_part,
        domain=domain,
        discovery_url=discovery_url,
        payload=payload,
    )


async def fetch_forwarding_invoice(callback_url: str, params: Any) -> dict[str, Any]:
    if not is_http_url(callback_url):
        raise ForwardingTargetError("Forwarding target did not return a valid callback")
    return validate_invoice_payload(await _fetch_json(callback_url, params=params))


async def fetch_forwarding_verify(verify_url: str) -> dict[str, Any]:
    if not is_http_url(verify_url):
        raise ForwardingTargetError("Forwarded invoice did not include a valid verify URL")
    payload = await _fetch_json(verify_url)
    if not isinstance(payload, dict):
        raise ForwardingTargetError("Forwarded verify endpoint did not return a JSON object")
    return dict(payload)
