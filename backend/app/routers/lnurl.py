"""LNURL-pay routes."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from ..config import Settings, parse_payer_data_config
from ..deps import (
    enforce_rate_limit,
    get_ln_client_dep,
    get_log_storage_dep,
    get_macaroon_store_dep,
    get_settings_dep,
)
from ..ln_client import LNClient
from ..log_storage import LogEntry, RequestLogStorage
from ..macaroon_store import MacaroonNotConfiguredError, MacaroonStore
from ..request_utils import build_public_url, get_client_ip, get_proxy_debug_info


router = APIRouter(prefix="/.well-known/lnurlp", tags=["lnurl"])


def _metadata_description(settings: Settings, username: str, domain: str) -> str:
    prefix = settings.metadata_description.strip()
    ln_address = f"{username}@{domain}"
    if prefix:
        return f"{prefix} {ln_address}"
    return ln_address


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


def _resolve_payer_data_request(settings: Settings) -> Dict[str, Dict[str, bool]]:
    config_data = dict(settings.payer_data)
    if not config_data:
        raw = os.environ.get("LNURL_PAYER_DATA")
        if raw:
            try:
                config_data = parse_payer_data_config(raw)
            except ValueError:
                config_data = {}
    if not config_data:
        return {}
    return {field: {"mandatory": mandatory} for field, mandatory in config_data.items()}


@router.get("/{username}", name="lnurlp")
async def lnurl_pay(
    request: Request,
    username: str,
    amount: Optional[int] = Query(
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
    _rate_limit: None = Depends(enforce_rate_limit),
    settings: Settings = Depends(get_settings_dep),
    ln_client: LNClient = Depends(get_ln_client_dep),
    storage: RequestLogStorage = Depends(get_log_storage_dep),
    macaroon_store: MacaroonStore = Depends(get_macaroon_store_dep),
) -> Dict[str, Any]:
    raw_username = username.strip()
    if not raw_username or " " in raw_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid username")

    username, tag = _split_username_tag(raw_username)
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid username")

    ip = get_client_ip(request)
    proxy_info = get_proxy_debug_info(request)
    callback_http_url = build_public_url(request)
    domain = _extract_domain(callback_http_url)
    ln_address = f"{raw_username}@{domain}"
    memo = _metadata_description(settings, raw_username, domain)
    long_description = _resolve_long_description(settings)
    metadata = _build_metadata(
        memo,
        ln_address,
        domain,
        tag,
        long_description,
    )
    base_metadata_hash = hashlib.sha256(metadata.encode("utf-8")).digest()
    query_params = dict(request.query_params)
    callback_lnurl = _make_lnurlp(callback_http_url)
    base_details: Dict[str, Any] = {
        "callback": callback_http_url,
        "callback_lnurl": callback_lnurl,
        "callback_http": callback_http_url,
        "proxy": proxy_info,
        "domain": domain,
        "metadata": metadata,
        "metadata_hash": base_metadata_hash.hex(),
        "ln_address": ln_address,
        "metadata_entries": json.loads(metadata),
        "metadata_long_desc": long_description,
        "comment_allowed": settings.comment_max_length,
    }
    if tag:
        base_details["tag"] = tag
    base_details["username_raw"] = raw_username
    if query_params:
        base_details["query"] = query_params

    payer_data_request = _resolve_payer_data_request(settings)
    if payer_data_request:
        base_details["payer_data"] = payer_data_request

    if amount is None:
        resp = {
            "tag": "payRequest",
            "callback": callback_http_url,
            "maxSendable": settings.max_sendable_sat * 1000,
            "minSendable": settings.min_sendable_sat * 1000,
            "metadata": metadata,
            "commentAllowed": settings.comment_max_length,
        }
        if payer_data_request:
            resp["payerData"] = payer_data_request
        details = dict(base_details)
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

    if amount <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Amount must be positive")

    if amount < settings.min_sendable_sat * 1000 or amount > settings.max_sendable_sat * 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Amount outside allowed range",
        )

    if comment is not None:
        if settings.comment_max_length <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Comments not accepted",
            )
        if len(comment) > settings.comment_max_length:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Comment exceeds maximum length",
            )

    payerdata_raw = payerdata.strip() if isinstance(payerdata, str) else None
    payerdata_obj: Optional[Dict[str, Any]] = None
    if payerdata_raw:
        if len(payerdata_raw) > 4096:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="payerdata payload too large",
            )
        try:
            parsed = json.loads(payerdata_raw)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid payerdata payload",
            ) from exc
        if not isinstance(parsed, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="payerdata must be a JSON object",
            )
        payerdata_obj = parsed

    if payer_data_request:
        if not payerdata_raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing payerdata payload",
            )
        missing = [
            field
            for field, config in payer_data_request.items()
            if config.get("mandatory") and (payerdata_obj is None or field not in payerdata_obj)
        ]
        if missing:
            missing_list = ", ".join(sorted(missing))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing mandatory payerdata fields: {missing_list}",
            )

    metadata_payload = metadata
    if payer_data_request and payerdata_raw:
        metadata_payload = f"{metadata}{payerdata_raw}"
    metadata_hash = hashlib.sha256(metadata_payload.encode("utf-8")).digest()

    if not await macaroon_store.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Invoice macaroon not configured",
        )

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
        details["invoice"] = _build_invoice_details(
            payment_request=payment_request,
            memo=invoice_memo,
            amount_msat=amount,
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
            amount_msat=amount,
            memo=invoice_memo,
            description_hash=metadata_hash,
        )
    except MacaroonNotConfiguredError as exc:
        await storage.append(
            LogEntry.create(
                username=username,
                ip=ip,
                event="invoice",
                domain=domain,
                amount_msat=amount,
                status="error",
                message="macaroon not configured",
                details=_details_with_invoice(),
            )
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Invoice macaroon not configured",
        ) from exc
    except Exception as exc:  # pragma: no cover - network errors are runtime
        await storage.append(
            LogEntry.create(
                username=username,
                ip=ip,
                event="invoice",
                domain=domain,
                amount_msat=amount,
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
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to generate invoice",
        ) from exc

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
                amount_msat=amount,
                status="error",
                message="missing payment request",
                details=_details_with_invoice(extra={"ln_client_response": invoice_data}),
            )
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Invoice missing payment request",
        )

    full_success_message = (
        f"Your payment hit faster than a Lightning bolt — {ln_address} stacked your sats!"
    )
    if len(full_success_message) > 144:
        full_success_message = f"{ln_address} stacked your sats!"

    response_payload: Dict[str, Any] = {
        "pr": payment_request,
        "routes": [],
        "successAction": {
            "tag": "message",
            "message": full_success_message,
        },
    }
    if payment_hash_hex:
        verify_http_url = f"{callback_http_url}/verify/{payment_hash_hex}"
        verify_public_url = _force_https(verify_http_url)
        response_payload["verify"] = verify_public_url
        base_details["payment_hash"] = payment_hash_hex
        base_details["verify_url"] = verify_public_url
        base_details["verify_url_http"] = verify_http_url

    entry = LogEntry.create(
        username=username,
        ip=ip,
        event="invoice",
        domain=domain,
        amount_msat=amount,
        status="ok",
        details=_details_with_invoice(
            payment_request=payment_request,
            response=response_payload,
            extra={"ln_client_response": invoice_data},
        ),
    )
    await storage.append(entry)

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
    if not raw_username or " " in raw_username:
        return {"status": "ERROR", "reason": "Invalid username"}

    username_clean, tag = _split_username_tag(raw_username)
    if not username_clean:
        return {"status": "ERROR", "reason": "Invalid username"}

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
