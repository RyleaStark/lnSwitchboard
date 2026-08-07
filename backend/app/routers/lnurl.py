"""LNURL-pay routes."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, Query, Request

from ..config import Settings, parse_payer_data_config
from ..connection_store import ConnectionStore
from ..deps import (
    enforce_rate_limit,
    get_connection_store_dep,
    get_ln_address_store_dep,
    get_ln_client_dep,
    get_log_storage_dep,
    get_macaroon_store_dep,
    get_nip05_store_dep,
    get_nostr_signer_store_dep,
    get_settings_dep,
)
from ..ln_address_store import LNAddressStore
from ..ln_client import LNClient
from ..lnurl_forwarding import (
    ForwardingTargetError,
    extract_payment_hash_from_verify_url,
    fetch_forwarding_discovery,
    fetch_forwarding_invoice,
    is_usable_verify_url,
)
from ..log_storage import LogEntry, RequestLogStorage
from ..macaroon_store import MacaroonNotConfiguredError, MacaroonStore
from ..nip05_store import NostrIdentityStore
from ..nostr_signer_store import NostrSignerStore
from ..nostr_zaps import ZapRequestError, validate_zap_request
from ..request_utils import build_public_url, get_client_ip, get_proxy_debug_info


router = APIRouter(prefix="/.well-known/lnurlp", tags=["lnurl"])
logger = logging.getLogger(__name__)
LOCAL_PART_PATTERN = re.compile(r"^[a-z0-9._-]+$")


def _lnurl_error(reason: str) -> Dict[str, str]:
    return {"status": "ERROR", "reason": reason}


def _parse_lnurl_local_part(value: str) -> Optional[tuple[str, Optional[str]]]:
    raw = value.strip()
    if raw != value or not raw or raw.count("+") > 1:
        return None
    if "+" not in raw:
        if not LOCAL_PART_PATTERN.fullmatch(raw):
            return None
        return raw, None
    base, tag = raw.split("+", 1)
    if not base or not tag:
        return None
    if not LOCAL_PART_PATTERN.fullmatch(base) or not LOCAL_PART_PATTERN.fullmatch(tag):
        return None
    return base, tag


def _parse_amount_param(value: Optional[str]) -> tuple[Optional[int], Optional[str]]:
    if value is None:
        return None, None
    raw = value.strip()
    if not raw:
        return None, "Amount must be an integer"
    try:
        amount = int(raw, 10)
    except ValueError:
        return None, "Amount must be an integer"
    if amount <= 0:
        return None, "Amount must be positive"
    return amount, None


def _build_metadata(
    description: str,
    ln_address: str,
    domain: str,
    tag: Optional[str],
    long_description: Optional[str],
) -> str:
    metadata = [
        ["text/plain", description],
        ["text/identifier", ln_address],
    ]
    if domain:
        metadata.append(["text/hostname", domain])
    if tag:
        metadata.append(["text/tag", tag])
    if long_description:
        metadata.append(["text/long-desc", long_description])
    return json.dumps(metadata, separators=(",", ":"))


def _split_username_tag(username: str) -> tuple[str, Optional[str]]:
    if "+" not in username:
        return username, None
    base, _, tag = username.partition("+")
    if not base or not tag:
        return username, None
    return base, tag


def _extract_domain(callback_url: str) -> str:
    parsed = urlsplit(callback_url)
    if parsed.hostname:
        return parsed.hostname
    netloc = parsed.netloc
    if netloc and ":" in netloc:
        return netloc.split(":", 1)[0]
    return netloc or "unknown"


def _shorten_payment_request(payment_request: str, prefix: int = 20, suffix: int = 12) -> str:
    if len(payment_request) <= prefix + suffix + 3:
        return payment_request
    return f"{payment_request[:prefix]}…{payment_request[-suffix:]}"


def _build_invoice_details(
    *,
    payment_request: Optional[str],
    memo: str,
    amount_msat: int,
    description_hash_hex: str,
) -> Dict[str, Any]:
    invoice: Dict[str, Any] = {
        "memo": memo,
        "amount_msat": amount_msat,
        "amount_sat": amount_msat // 1000,
        "description_hash": description_hash_hex,
    }
    if payment_request:
        invoice["payment_request"] = payment_request
        invoice["payment_request_preview"] = _shorten_payment_request(payment_request)
        invoice["payment_request_length"] = len(payment_request)
    return invoice


def _make_lnurlp(callback_url: str) -> str:
    parsed = urlsplit(callback_url)
    if parsed.scheme not in {"http", "https"}:
        return callback_url
    return urlunsplit(("lnurlp", parsed.netloc, parsed.path, parsed.query, parsed.fragment))


def _force_https(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        return url
    netloc = parsed.netloc
    scheme = "http" if netloc.endswith(".onion") else "https"
    return urlunsplit((scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _resolve_long_description(settings: Settings) -> Optional[str]:
    if settings.metadata_long_description:
        return settings.metadata_long_description
    env_value = os.environ.get("LNURL_METADATA_LONG_DESC")
    if not env_value:
        return None
    trimmed = env_value.strip()
    return trimmed or None


async def _channel_max_sendable_sat(ln_client: LNClient) -> int:
    try:
        channels = await ln_client.list_channels(public_only=False)
    except Exception as exc:  # pragma: no cover - network errors
        logger.warning("Failed to fetch channel data for LNURL max sendable: %s", exc)
        return 0
    max_receiving = 0
    for channel in channels:
        value = channel.get("receiving_capacity_sat")
        if isinstance(value, int) and value > max_receiving:
            max_receiving = value
    return max_receiving


def _resolve_payer_data_request(settings: Settings) -> Dict[str, Dict[str, bool]]:
    config_data = dict(settings.payer_data)
    if not config_data:
        raw = os.environ.get("LNURL_PAYER_DATA")
        if raw:
            config_data = parse_payer_data_config(raw)
    if not config_data:
        return {}
    return {field: {"mandatory": mandatory} for field, mandatory in config_data.items()}


class _TemplateDict(dict):
    def __missing__(self, key):
        return f"{{{key}}}"


def _format_template(template: str, context: Dict[str, Any]) -> str:
    prepared = {
        key: ("" if value is None else value)
        for key, value in context.items()
    }
    safe_context = _TemplateDict(prepared)
    try:
        return template.format_map(safe_context).strip()
    except Exception:
        return template.strip()


def _build_template_context(
    *,
    raw_username: str,
    domain: str,
    ln_address: str,
    min_sat: int,
    max_sat: int,
    channel_max_sat: int,
    amount_msat: Optional[int] = None,
) -> Dict[str, Any]:
    base, tag = _split_username_tag(raw_username)
    amount_sat = amount_msat // 1000 if amount_msat is not None else None
    return {
        "username": raw_username,
        "local_part": base,
        "tag": tag or "",
        "domain": domain,
        "ln_address": ln_address,
        "amount_sat": amount_sat,
    }


def _resolve_metadata_description(
    *,
    settings: Settings,
    override_template: Optional[str],
    context: Dict[str, Any],
) -> str:
    template = (override_template or settings.metadata_description or "").strip()
    if not template:
        return context["ln_address"]
    rendered = _format_template(template, context) or context["ln_address"]
    if "{ln_address}" not in template and context["ln_address"] not in rendered:
        rendered = f"{rendered} {context['ln_address']}".strip()
    return rendered


def _resolve_success_message(
    *,
    settings: Settings,
    override_template: Optional[str],
    context: Dict[str, Any],
) -> str:
    template = (override_template or settings.success_message or "").strip()
    if not template:
        template = "{ln_address} stacked your sats!"
    rendered = _format_template(template, context) or context["ln_address"]
    if len(rendered) > 144:
        rendered = f"{context['ln_address']} stacked your sats!"
    return rendered


async def _lookup_address_override(
    store: LNAddressStore,
    *,
    username: str,
    domain: str,
) -> Optional[Dict[str, Any]]:
    normalized_domain = domain.strip().lower()
    normalized_username = username.strip().lower()
    exact = await store.get_by_identifier(local_part=normalized_username, domain=normalized_domain)
    if exact:
        return exact
    base, tag = _split_username_tag(normalized_username)
    if tag:
        return await store.get_by_identifier(local_part=base, domain=normalized_domain)
    return None


def _build_address_override_details(override: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": override.get("id"),
        "local_part": override.get("local_part"),
        "domain": override.get("domain"),
        "routing_mode": override.get("routing_mode") or "local",
        "forward_to": override.get("forward_to"),
    }


async def _linked_nostr_pubkey(
    identity_store: NostrIdentityStore,
    *,
    username: str,
    domain: str,
) -> Optional[str]:
    base, _tag = _split_username_tag(username)
    entries = await identity_store.get_by_domain(domain)
    for entry in entries:
        if entry.get("local_part") == base:
            pubkey = entry.get("pubkey_hex")
            if isinstance(pubkey, str) and pubkey:
                return pubkey.lower()
    return None


async def _forward_lnurl_pay(
    *,
    request: Request,
    raw_username: str,
    username: str,
    tag: Optional[str],
    amount: Optional[int],
    ip: str,
    proxy_info: Dict[str, Any],
    callback_http_url: str,
    callback_lnurl: str,
    domain: str,
    ln_address: str,
    override: Dict[str, Any],
    storage: RequestLogStorage,
) -> Dict[str, Any]:
    forward_to = override.get("forward_to")
    forward_phase = "invoice" if amount is not None else "discovery"
    address_override = _build_address_override_details(override)
    try:
        target = await fetch_forwarding_discovery(str(forward_to or ""))
    except ForwardingTargetError as exc:
        await storage.append(
            LogEntry.create(
                username=username,
                ip=ip,
                event="forward",
                domain=domain,
                amount_msat=amount,
                status="error",
                message=str(exc),
                details={
                    "forwarded": True,
                    "forward_to": forward_to,
                    "ln_address": ln_address,
                    "username_raw": raw_username,
                    "domain": domain,
                    "callback": callback_http_url,
                    "callback_lnurl": callback_lnurl,
                    "callback_http": callback_http_url,
                    "proxy": proxy_info,
                    "address_override": address_override,
                    "forward_phase": forward_phase,
                    "error": str(exc),
                },
            )
        )
        return _lnurl_error(str(exc) or "Forwarding target unavailable")

    base_details: Dict[str, Any] = {
        "forwarded": True,
        "forward_to": target.address,
        "settlement_source": "remote_verify",
        "callback": callback_http_url,
        "callback_lnurl": callback_lnurl,
        "callback_http": callback_http_url,
        "proxy": proxy_info,
        "domain": domain,
        "ln_address": ln_address,
        "username_raw": raw_username,
        "address_override": address_override,
        "forward_phase": forward_phase,
        "forwarding_target": {
            "ln_address": target.address,
            "discovery_url": target.discovery_url,
            "callback": target.payload.get("callback"),
            "minSendable": target.payload.get("minSendable"),
            "maxSendable": target.payload.get("maxSendable"),
            "metadata": target.payload.get("metadata"),
        },
    }
    if tag:
        base_details["tag"] = tag

    discovery_response = dict(target.payload)
    discovery_response["callback"] = callback_http_url
    if amount is None:
        details = dict(base_details)
        details["response"] = discovery_response
        await storage.append(
            LogEntry.create(
                username=username,
                ip=ip,
                event="forward",
                domain=domain,
                amount_msat=None,
                details=details,
            )
        )
        return discovery_response

    if amount <= 0:
        return _lnurl_error("Amount must be positive")
    min_sendable = target.payload.get("minSendable")
    max_sendable = target.payload.get("maxSendable")
    if isinstance(min_sendable, int) and isinstance(max_sendable, int):
        if amount < min_sendable or amount > max_sendable:
            return _lnurl_error("Amount outside allowed range")

    try:
        invoice_response = await fetch_forwarding_invoice(
            str(target.payload.get("callback") or ""),
            list(request.query_params.multi_items()),
        )
    except ForwardingTargetError as exc:
        details = dict(base_details)
        details["error"] = str(exc)
        await storage.append(
            LogEntry.create(
                username=username,
                ip=ip,
                event="forward",
                domain=domain,
                amount_msat=amount,
                status="error",
                message=str(exc),
                details=details,
            )
        )
        return _lnurl_error(str(exc))

    verify_url = invoice_response.get("verify")
    payment_hash = extract_payment_hash_from_verify_url(verify_url)
    details = dict(base_details)
    details["response"] = invoice_response
    details["invoice"] = {
        "payment_request": invoice_response.get("pr"),
        "amount_msat": amount,
        "amount_sat": amount // 1000,
        "payment_hash": payment_hash,
        "remote_callback": target.payload.get("callback"),
    }
    if payment_hash:
        details["payment_hash"] = payment_hash
    if is_usable_verify_url(verify_url):
        details["verify_url"] = verify_url
    else:
        details["webhooks_unavailable_reason"] = "Forwarding target did not return a usable verify URL"

    request_log_id = await storage.append(
        LogEntry.create(
            username=username,
            ip=ip,
            event="forward",
            domain=domain,
            amount_msat=amount,
            details=details,
        )
    )
    if is_usable_verify_url(verify_url):
        await storage.log_invoice_event(
            username=username,
            domain=domain,
            amount_msat=amount,
            ip=ip,
            payment_hash=payment_hash,
            payment_request=invoice_response.get("pr"),
            details=details,
            request_log_id=request_log_id,
            expires_at=None,
        )

    return invoice_response


@router.get("/{username}", name="lnurlp")
async def lnurl_pay(
    request: Request,
    username: str,
    amount: Optional[str] = Query(
        None,
        description="Amount in millisatoshis requested by the wallet.",
    ),
    comment: Optional[str] = Query(
        None,
        description="Optional payer comment as defined in LUD-12.",
    ),
    payerdata: Optional[str] = Query(
        None,
        description="Optional payer identity payload as defined in LUD-18.",
    ),
    nostr: Optional[str] = Query(
        None,
        description="Optional NIP-57 zap request event JSON.",
    ),
    _rate_limit: None = Depends(enforce_rate_limit),
    settings: Settings = Depends(get_settings_dep),
    ln_client: LNClient = Depends(get_ln_client_dep),
    storage: RequestLogStorage = Depends(get_log_storage_dep),
    address_store: LNAddressStore = Depends(get_ln_address_store_dep),
    macaroon_store: MacaroonStore = Depends(get_macaroon_store_dep),
    identity_store: NostrIdentityStore = Depends(get_nip05_store_dep),
    nostr_signer_store: NostrSignerStore = Depends(get_nostr_signer_store_dep),
    connection_store: ConnectionStore = Depends(get_connection_store_dep),
) -> Dict[str, Any]:
    raw_username = username.strip()
    parsed_username = _parse_lnurl_local_part(username)
    if parsed_username is None:
        return _lnurl_error("Invalid username")

    username, tag = parsed_username
    amount_msat, amount_error = _parse_amount_param(amount)
    if amount_error:
        return _lnurl_error(amount_error)

    ip = get_client_ip(request)
    proxy_info = get_proxy_debug_info(request)
    callback_http_url = build_public_url(request)
    domain = _extract_domain(callback_http_url)
    if connection_store.has_public_domain(domain):
        # Funnel terminates TLS before proxying to this listener over HTTP.
        # Registered provider domains are therefore always public HTTPS origins.
        callback_http_url = _force_https(callback_http_url)
    ln_address = f"{raw_username}@{domain}"
    override = await _lookup_address_override(
        address_store,
        username=raw_username,
        domain=domain,
    )
    override_min_sat = override.get("min_sendable_sat") if override else None
    override_max_sat = override.get("max_sendable_sat") if override else None
    override_metadata = override.get("metadata_description") if override else None
    override_success = override.get("success_message") if override else None
    override_payer_data = override.get("payer_data") if override else None
    long_description = _resolve_long_description(settings)
    if isinstance(override_payer_data, dict) and override_payer_data:
        payer_data_request = {str(field): {"mandatory": bool(mandatory)} for field, mandatory in override_payer_data.items()}
    else:
        try:
            payer_data_request = _resolve_payer_data_request(settings)
        except ValueError as exc:
            return _lnurl_error(str(exc))
    if payer_data_request:
        base_payer_data = payer_data_request
    else:
        base_payer_data = None

    query_params = dict(request.query_params)
    callback_lnurl = _make_lnurlp(callback_http_url)

    if override and (override.get("routing_mode") == "forward"):
        return await _forward_lnurl_pay(
            request=request,
            raw_username=raw_username,
            username=username,
            tag=tag,
            amount=amount_msat,
            ip=ip,
            proxy_info=proxy_info,
            callback_http_url=callback_http_url,
            callback_lnurl=callback_lnurl,
            domain=domain,
            ln_address=ln_address,
            override=override,
            storage=storage,
        )

    channel_max_sendable_sat = await _channel_max_sendable_sat(ln_client)
    if channel_max_sendable_sat <= 0:
        return _lnurl_error("No inbound liquidity available")
    min_sendable_sat = override_min_sat if override_min_sat is not None else settings.min_sendable_sat
    min_sendable_sat = max(1, min_sendable_sat)
    if channel_max_sendable_sat < min_sendable_sat:
        return _lnurl_error("Inbound liquidity below configured minimum send amount")

    max_sendable_sat = channel_max_sendable_sat
    if override_max_sat is not None:
        max_sendable_sat = min(channel_max_sendable_sat, override_max_sat)
    if max_sendable_sat < min_sendable_sat:
        max_sendable_sat = min_sendable_sat

    memo_context = _build_template_context(
        raw_username=raw_username,
        domain=domain,
        ln_address=ln_address,
        min_sat=min_sendable_sat,
        max_sat=max_sendable_sat,
        channel_max_sat=channel_max_sendable_sat,
    )
    memo = _resolve_metadata_description(
        settings=settings,
        override_template=override_metadata,
        context=memo_context,
    )
    metadata = _build_metadata(
        memo,
        ln_address,
        domain,
        tag,
        long_description,
    )
    metadata_entries = json.loads(metadata)
    base_metadata_hash = hashlib.sha256(metadata.encode("utf-8")).digest()
    base_details: Dict[str, Any] = {
        "callback": callback_http_url,
        "callback_lnurl": callback_lnurl,
        "callback_http": callback_http_url,
        "proxy": proxy_info,
        "domain": domain,
        "metadata": metadata,
        "metadata_hash": base_metadata_hash.hex(),
        "ln_address": ln_address,
        "metadata_entries": metadata_entries,
        "metadata_long_desc": long_description,
        "comment_allowed": settings.comment_max_length,
        "username_raw": raw_username,
    }
    if tag:
        base_details["tag"] = tag
    if query_params:
        base_details["query"] = query_params
    if base_payer_data:
        base_details["payer_data"] = base_payer_data
    if override:
        base_details["address_override"] = _build_address_override_details(override)
    base_details["limits"] = {
        "min_sat": min_sendable_sat,
        "max_sat": max_sendable_sat,
        "channel_max_sat": channel_max_sendable_sat,
    }
    linked_nostr_pubkey: Optional[str] = None
    zap_signer_pubkey: Optional[str] = None
    if not (override and override.get("routing_mode") == "forward"):
        linked_nostr_pubkey = await _linked_nostr_pubkey(
            identity_store,
            username=raw_username,
            domain=domain,
        )
        zap_signer_pubkey = await nostr_signer_store.get_public_key()

    max_sendable_msat = max_sendable_sat * 1000
    min_sendable_msat = min_sendable_sat * 1000
    base_details["channel_max_sendable_sat"] = channel_max_sendable_sat

    if amount_msat is None:
        resp = {
            "tag": "payRequest",
            "callback": callback_http_url,
            "maxSendable": max_sendable_msat,
            "minSendable": min_sendable_msat,
            "metadata": metadata,
            "commentAllowed": settings.comment_max_length,
        }
        if base_payer_data:
            resp["payerData"] = base_payer_data
        details = dict(base_details)
        if linked_nostr_pubkey and zap_signer_pubkey:
            resp["allowsNostr"] = True
            resp["nostrPubkey"] = zap_signer_pubkey
            details["zap"] = {
                "recipient_pubkey": linked_nostr_pubkey,
                "signer_pubkey": zap_signer_pubkey,
            }
        details["response"] = resp
        await storage.append(
            LogEntry.create(
                username=username,
                ip=ip,
                event="discovery",
                domain=domain,
                amount_msat=None,
                details=details,
            )
        )
        return resp

    if amount_msat < min_sendable_msat or amount_msat > max_sendable_msat:
        return _lnurl_error("Amount outside allowed range")

    if comment is not None:
        if settings.comment_max_length <= 0:
            return _lnurl_error("Comments not accepted")
        if len(comment) > settings.comment_max_length:
            return _lnurl_error("Comment exceeds maximum length")

    payerdata_raw = payerdata.strip() if isinstance(payerdata, str) else None
    payerdata_obj: Optional[Dict[str, Any]] = None
    if payerdata_raw:
        if len(payerdata_raw) > 4096:
            return _lnurl_error("payerdata payload too large")
        try:
            parsed = json.loads(payerdata_raw)
        except json.JSONDecodeError:
            return _lnurl_error("Invalid payerdata payload")
        if not isinstance(parsed, dict):
            return _lnurl_error("payerdata must be a JSON object")
        payerdata_obj = parsed

    if payer_data_request:
        missing = [
            field
            for field, config in payer_data_request.items()
            if config.get("mandatory") and (payerdata_obj is None or field not in payerdata_obj)
        ]
        mandatory_fields = [field for field, config in payer_data_request.items() if config.get("mandatory")]
        if mandatory_fields and not payerdata_raw:
            return _lnurl_error("Missing payerdata payload")
        if missing:
            missing_list = ", ".join(sorted(missing))
            return _lnurl_error(f"Missing mandatory payerdata fields: {missing_list}")

    zap_request: Optional[Dict[str, Any]] = None
    nostr_raw = nostr.strip() if isinstance(nostr, str) else None
    if nostr_raw:
        if not linked_nostr_pubkey or not zap_signer_pubkey:
            return _lnurl_error("Nostr zaps are not configured for this address")
        try:
            zap_request = validate_zap_request(
                raw=nostr_raw,
                amount_msat=amount_msat,
                recipient_pubkey=linked_nostr_pubkey,
                callback_lnurl=callback_lnurl,
            )
        except ZapRequestError as exc:
            return _lnurl_error(str(exc))

    metadata_payload = metadata
    if payer_data_request and payerdata_raw:
        metadata_payload = f"{metadata}{payerdata_raw}"
    if zap_request is not None:
        metadata_payload = nostr_raw or ""
    metadata_hash = hashlib.sha256(metadata_payload.encode("utf-8")).digest()

    if not await macaroon_store.is_configured():
        return _lnurl_error("Invoice macaroon not configured")

    payment_hash_hex: Optional[str] = None
    invoice_memo = memo
    if comment:
        invoice_memo = f"{memo} | {comment}"

    def _details_with_invoice(
        payment_request: Optional[str] = None,
        response: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        details = dict(base_details)
        details["metadata_hash"] = metadata_hash.hex()
        details["metadata_for_hash"] = metadata_payload
        if payerdata_raw:
            details["payerdata_raw"] = payerdata_raw
        if payerdata_obj is not None:
            details["payerdata"] = payerdata_obj
        if zap_request is not None:
            details["zap_request"] = zap_request
        details["invoice"] = _build_invoice_details(
            payment_request=payment_request,
            memo=invoice_memo,
            amount_msat=amount_msat,
            description_hash_hex=metadata_hash.hex(),
        )
        if response is not None:
            details["response"] = response
        if extra:
            details.update(extra)
        if comment is not None:
            details["comment"] = comment
            details["comment_length"] = len(comment)
        if payment_hash_hex:
            details["payment_hash"] = payment_hash_hex
            verify_http_url = f"{callback_http_url}/verify/{payment_hash_hex}"
            details["verify_url"] = _force_https(verify_http_url)
            details["verify_url_http"] = verify_http_url
        return details
    try:
        invoice_data = await ln_client.create_invoice(
            amount_msat=amount_msat,
            memo=invoice_memo,
            description_hash=metadata_hash,
        )
    except MacaroonNotConfiguredError:
        await storage.append(
            LogEntry.create(
                username=username,
                ip=ip,
                event="invoice",
                domain=domain,
                amount_msat=amount_msat,
                status="error",
                message="macaroon not configured",
                details=_details_with_invoice(),
            )
        )
        return _lnurl_error("Invoice macaroon not configured")
    except Exception as exc:  # pragma: no cover - network errors are runtime
        await storage.append(
            LogEntry.create(
                username=username,
                ip=ip,
                event="invoice",
                domain=domain,
                amount_msat=amount_msat,
                status="error",
                message=str(exc),
                details=_details_with_invoice(
                    extra={
                        "error": {
                            "type": exc.__class__.__name__,
                            "message": str(exc),
                        }
                    }
                ),
            )
        )
        return _lnurl_error("Failed to generate invoice")

    payment_request = invoice_data.get("payment_request")
    payment_hash_data = invoice_data.get("r_hash") or invoice_data.get("payment_hash")
    if isinstance(payment_hash_data, bytes):
        payment_hash_hex = payment_hash_data.hex()
    elif isinstance(payment_hash_data, str):
        payment_hash_hex = payment_hash_data
    if payment_hash_hex:
        invoice_data["r_hash"] = payment_hash_hex
    if not payment_request:
        await storage.append(
            LogEntry.create(
                username=username,
                ip=ip,
                event="invoice",
                domain=domain,
                amount_msat=amount_msat,
                status="error",
                message="missing payment request",
                details=_details_with_invoice(extra={"ln_client_response": invoice_data}),
            )
        )
        return _lnurl_error("Invoice missing payment request")

    invoice_context = dict(memo_context)
    invoice_context["amount_msat"] = amount_msat
    invoice_context["amount_sat"] = amount_msat // 1000
    resolved_message = _resolve_success_message(
        settings=settings,
        override_template=override_success,
        context=invoice_context,
    )

    response_payload: Dict[str, Any] = {
        "pr": payment_request,
        "routes": [],
        "successAction": {
            "tag": "message",
            "message": resolved_message,
        },
    }
    if payment_hash_hex:
        verify_http_url = f"{callback_http_url}/verify/{payment_hash_hex}"
        verify_public_url = _force_https(verify_http_url)
        response_payload["verify"] = verify_public_url
        base_details["payment_hash"] = payment_hash_hex
        base_details["verify_url"] = verify_public_url
        base_details["verify_url_http"] = verify_http_url

    invoice_details = _details_with_invoice(
        payment_request=payment_request,
        response=response_payload,
        extra={"ln_client_response": invoice_data},
    )
    entry = LogEntry.create(
        username=username,
        ip=ip,
        event="invoice",
        domain=domain,
        amount_msat=amount_msat,
        status="ok",
        details=invoice_details,
    )
    request_log_id = await storage.append(entry)
    invoice_meta = invoice_details.get("invoice") if isinstance(invoice_details, dict) else None
    expires_at = None
    if isinstance(invoice_meta, dict):
        expires_at = invoice_meta.get("expires_at")
    await storage.log_invoice_event(
        username=username,
        domain=domain,
        amount_msat=amount_msat,
        ip=ip,
        payment_hash=payment_hash_hex,
        payment_request=payment_request,
        details=invoice_details,
        request_log_id=request_log_id,
        expires_at=expires_at,
    )

    return response_payload


@router.get("/{username}/verify/{payment_hash}", name="lnurlp-verify")
async def lnurl_verify(
    request: Request,
    username: str,
    payment_hash: str,
    _rate_limit: None = Depends(enforce_rate_limit),
    ln_client: LNClient = Depends(get_ln_client_dep),
    storage: RequestLogStorage = Depends(get_log_storage_dep),
) -> Dict[str, Any]:
    raw_username = username.strip()
    parsed_username = _parse_lnurl_local_part(username)
    if parsed_username is None:
        return {"status": "ERROR", "reason": "Invalid username"}

    username_clean, tag = parsed_username

    try:
        hash_bytes = bytes.fromhex(payment_hash)
    except ValueError:
        return {"status": "ERROR", "reason": "Invalid payment hash"}

    ip = get_client_ip(request)
    proxy_info = get_proxy_debug_info(request)
    verify_http_url = build_public_url(request)
    domain = _extract_domain(verify_http_url)
    ln_address = f"{raw_username}@{domain}"

    details: Dict[str, Any] = {
        "verify_url": _force_https(verify_http_url),
        "proxy": proxy_info,
        "username_raw": raw_username,
        "ln_address": ln_address,
        "payment_hash": payment_hash,
        "domain": domain,
    }
    details["verify_url_http"] = verify_http_url
    if tag:
        details["tag"] = tag

    try:
        invoice_info = await ln_client.lookup_invoice(hash_bytes)
    except MacaroonNotConfiguredError:
        details["error"] = "macaroon not configured"
        await storage.append(
            LogEntry.create(
                username=username_clean,
                ip=ip,
                event="verify",
                domain=domain,
                status="error",
                message="macaroon not configured",
                details=details,
            )
        )
        return {"status": "ERROR", "reason": "Invoice macaroon not configured"}
    except LookupError:
        details["error"] = "not found"
        await storage.append(
            LogEntry.create(
                username=username_clean,
                ip=ip,
                event="verify",
                domain=domain,
                status="error",
                message="invoice not found",
                details=details,
            )
        )
        return {"status": "ERROR", "reason": "Not found"}
    except Exception as exc:  # pragma: no cover - runtime errors
        details["error"] = {"type": exc.__class__.__name__, "message": str(exc)}
        await storage.append(
            LogEntry.create(
                username=username_clean,
                ip=ip,
                event="verify",
                domain=domain,
                status="error",
                message=str(exc),
                details=details,
            )
        )
        reason = "Lookup failed"
        try:
            import grpc  # type: ignore
        except Exception:  # pragma: no cover - optional diagnostics
            grpc = None  # type: ignore
        if grpc and isinstance(exc, grpc.aio.AioRpcError):  # type: ignore[attr-defined]
            # Prefer the gRPC details string when available.
            grpc_reason = exc.details()  # type: ignore[attr-defined]
            if grpc_reason:
                reason = f"Lookup failed: {grpc_reason}"
            else:
                reason = f"Lookup failed: {exc}"
        elif str(exc):
            reason = f"Lookup failed: {exc}"
        return {"status": "ERROR", "reason": reason}

    settled = bool(invoice_info.get("settled"))
    preimage_bytes = invoice_info.get("r_preimage") or b""
    if isinstance(preimage_bytes, str):
        # If backend already returned hex string, normalize.
        try:
            preimage_bytes = bytes.fromhex(preimage_bytes)
        except ValueError:
            preimage_bytes = b""
    preimage_hex = preimage_bytes.hex() if preimage_bytes else None
    payment_request = invoice_info.get("payment_request") or ""

    response_payload = {
        "status": "OK",
        "settled": settled,
        "preimage": preimage_hex,
        "pr": payment_request,
    }

    details["settled"] = settled
    details["preimage"] = preimage_hex
    details["payment_request"] = payment_request
    await storage.append(
        LogEntry.create(
            username=username_clean,
            ip=ip,
            event="verify",
            domain=domain,
            status="ok",
            details={"response": response_payload, **details},
        )
    )

    return response_payload
