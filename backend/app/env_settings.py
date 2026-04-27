"""Helpers for exposing and updating environment-based settings via the UI."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from fastapi import HTTPException, status
from pydantic import ValidationError

from . import config
from . import deps

BASE_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = Path(os.environ.get("LNSWITCHBOARD_ENV_FILE", BASE_DIR / ".env")).resolve()


ENV_FIELDS: List[Dict[str, Any]] = [
    {
        "key": "SERVICE_PORT",
        "attr": "service_port",
        "label": "Service Port",
        "type": "number",
        "category": "LND Node",
        "description": "Port lnSwitchboard listens on for UI/API traffic.",
        "editable": False,
        "visible": False,
    },
    {
        "key": "LND_HOST",
        "attr": "lnd_host",
        "label": "LND Host",
        "type": "text",
        "category": "LND Node",
        "description": "Hostname or IP address for your LND instance.",
        "editable": False,
        "visible": False,
    },
    {
        "key": "LND_GRPC_PORT",
        "attr": "lnd_grpc_port",
        "label": "LND gRPC Port",
        "type": "number",
        "category": "LND Node",
        "description": "Port exposed by LND's gRPC interface (default 10009).",
        "editable": False,
        "visible": False,
    },
    {
        "key": "LND_TLS_PATH",
        "attr": "lnd_tls_path",
        "label": "TLS Certificate Path",
        "type": "text",
        "category": "LND Node",
        "description": "Absolute path to your LND tls.cert file.",
        "editable": False,
        "visible": False,
    },
    {
        "key": "LND_TLS_SERVER_NAME",
        "attr": "lnd_tls_server_name",
        "label": "TLS Server Name",
        "type": "text",
        "category": "LND Node",
        "description": "Optional certificate server name override for LND TLS verification. Leave blank to verify against LND_HOST.",
        "editable": False,
        "visible": False,
    },
    {
        "key": "LND_MACAROON_PATH",
        "attr": "lnd_macaroon_path",
        "label": "Mounted Macaroon Path",
        "type": "text",
        "category": "LND Node",
        "description": "Read-only path to LND's binary invoice.macaroon. When set, manual macaroon replacement is disabled.",
        "editable": False,
        "visible": False,
    },
    {
        "key": "MIN_SENDABLE_SAT",
        "attr": "min_sendable_sat",
        "label": "Minimum Receivable (sats)",
        "type": "number",
        "category": "LNURL",
        "description": "Smallest LNURL invoice amount a payer can send you (receivable).",
        "editable": True,
    },
    {
        "key": "MAX_SENDABLE_SAT",
        "attr": "max_sendable_sat",
        "label": "Maximum Receivable (sats)",
        "type": "number",
        "category": "LNURL",
        "description": "Automatically matches the largest receivable channel.",
        "hint_link": {
            "label": "Review your channel capacity here",
            "href": "/liquidity/",
        },
        "editable": False,
    },
    {
        "key": "LNURL_METADATA_DESCRIPTION",
        "attr": "metadata_description",
        "label": "Metadata Description",
        "type": "text",
        "category": "LNURL",
        "description": "Text used in invoice memos/LNURL metadata. Supports {ln_address}, {local_part}, {domain}, and {tag}.",
        "editable": True,
    },
    {
        "key": "LNURL_SUCCESS_MESSAGE",
        "attr": "success_message",
        "label": "Success Message",
        "type": "textarea",
        "category": "LNURL",
        "description": "Message returned in successAction. Supports the metadata variables plus {amount_sat} once a payment is requested.",
        "editable": True,
    },
    {
        "key": "LNURL_METADATA_LONG_DESC",
        "attr": "metadata_long_description",
        "label": "Metadata Long Description",
        "type": "textarea",
        "category": "LNURL",
        "description": "Optional long description returned in LNURL metadata (LUD-12).",
        "editable": False,
        "visible": False,
    },
    {
        "key": "LNURL_COMMENT_MAX_LENGTH",
        "attr": "comment_max_length",
        "label": "Comment Max Length",
        "type": "number",
        "category": "LNURL",
        "description": "Maximum characters accepted in payer comments (LUD-12).",
        "editable": False,
        "visible": False,
    },
    {
        "key": "LNURL_PAYER_DATA",
        "attr": "payer_data",
        "label": "Payer Data Schema",
        "type": "textarea",
        "category": "LNURL",
        "description": "JSON object describing LUD-18 payerData requirements.",
        "editable": False,
        "visible": False,
    },
    {
        "key": "WEBHOOK_MAX_RETRIES",
        "attr": "webhook_max_retries",
        "label": "Webhook Max Retries",
        "type": "number",
        "category": "Webhooks",
        "description": "Number of times to retry a webhook after the initial attempt.",
        "editable": True,
    },
    {
        "key": "WEBHOOK_RETRY_WINDOW_SECONDS",
        "attr": "webhook_retry_window_seconds",
        "label": "Retry Window (seconds)",
        "type": "number",
        "category": "Webhooks",
        "description": "How long to spread webhook retries before giving up.",
        "editable": True,
    },
    {
        "key": "RATE_LIMIT_PER_MIN",
        "attr": "rate_limit_per_min",
        "label": "Rate Limit (per minute)",
        "type": "number",
        "category": "Security",
        "description": "Maximum LNURL requests allowed per IP each minute.",
        "editable": True,
    },
    {
        "key": "UI_POLL_SECONDS",
        "attr": "ui_poll_seconds",
        "label": "UI Poll Interval (seconds)",
        "type": "number",
        "category": "Security",
        "description": "How frequently the dashboard refreshes metrics/logs.",
        "editable": True,
    },
    {
        "key": "RECENT_LOG_LIMIT",
        "attr": "recent_log_limit",
        "label": "Recent Log Buffer",
        "type": "number",
        "category": "System",
        "description": "Maximum number of log entries retained in memory.",
        "editable": True,
    },
    {
        "key": "LOG_RETENTION_DAYS",
        "attr": "log_retention_days",
        "label": "Log Retention (days)",
        "type": "number",
        "category": "System",
        "description": "Delete on-disk logs older than this many days.",
        "editable": True,
    },
    {
        "key": "DATA_STORE_PATH",
        "attr": "data_store_path",
        "label": "Data Store Path",
        "type": "text",
        "category": "System",
        "description": "SQLite database file used for logs and NIP-05 identities.",
        "editable": False,
        "visible": False,
    },
    {
        "key": "MACAROON_STORE_PATH",
        "attr": "macaroon_store_path",
        "label": "Macaroon Path",
        "type": "text",
        "category": "System",
        "description": "Fallback path where a manually supplied invoice macaroon is stored as hex.",
        "editable": False,
        "visible": False,
    },
]

FIELD_MAP: Dict[str, Dict[str, Any]] = {field["key"]: field for field in ENV_FIELDS}


def _serialize_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        return json.dumps(value, indent=2)
    return str(value)


def list_env_settings() -> List[Dict[str, Any]]:
    settings = config.get_settings()
    env_values = _load_env_values()
    results: List[Dict[str, Any]] = []
    for field in ENV_FIELDS:
        if not field.get("visible", True):
            continue
        attr = field["attr"]
        if field["key"] in env_values:
            raw_value = env_values[field["key"]]
        else:
            raw_value = getattr(settings, attr)
        results.append(
            {
                "key": field["key"],
                "label": field["label"],
                "description": field.get("description", ""),
                "type": field["type"],
                "category": field["category"],
                "editable": field["editable"],
                "value": _serialize_value(raw_value),
                "hint_link": field.get("hint_link"),
            }
        )
    return results


def _load_env_values() -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not ENV_FILE.exists():
        return values
    with ENV_FILE.open("r", encoding="utf-8") as fh:
        for raw in fh.readlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            value = val.strip()
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1].replace('\\"', '"')
            values[key] = value
    return values


def _format_env_value(value: str) -> str:
    if value == "":
        return '""'
    if any(ch in value for ch in (' ', '#', '"')):
        escaped = value.replace('"', '\\"')
        return f'"{escaped}"'
    return value


def _write_env_file(values: Dict[str, str]) -> None:
    lines: List[str] = []
    seen: set[str] = set()
    if ENV_FILE.exists():
        with ENV_FILE.open("r", encoding="utf-8") as fh:
            for raw in fh.readlines():
                stripped = raw.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    key = stripped.split("=", 1)[0].strip()
                    if key in values:
                        lines.append(f"{key}={_format_env_value(values[key])}")
                        seen.add(key)
                    else:
                        lines.append(raw.rstrip("\n"))
                else:
                    lines.append(raw.rstrip("\n"))
    for key, value in values.items():
        if key not in seen:
            lines.append(f"{key}={_format_env_value(value)}")
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    with ENV_FILE.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")


def _coerce_value(field: Dict[str, Any], value: Any) -> Any:
    if value is None:
        return ""
    if field["type"] == "number":
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field['label']} must be a number.",
            ) from exc
    return str(value)


def update_env_settings(updates: Dict[str, Any]) -> Dict[str, Any]:
    if not updates:
        return {}
    env_values = _load_env_values()
    settings = config.get_settings()
    settings_data = settings.model_dump()
    changed: Dict[str, Any] = {}

    for key, raw_value in updates.items():
        field = FIELD_MAP.get(key)
        if not field or not field.get("editable", True):
            continue
        attr = field["attr"]
        coerced = _coerce_value(field, raw_value)
        settings_data[attr] = coerced
        env_values[key] = "" if coerced is None else str(coerced)
        changed[key] = coerced

    if not changed:
        return {}

    try:
        config.Settings(**settings_data)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid configuration: {exc.errors()}",
        ) from exc

    _write_env_file(env_values)
    for key, value in env_values.items():
        os.environ[key] = value

    config.get_settings.cache_clear()
    deps._get_rate_limiter.cache_clear()
    deps._get_ln_client.cache_clear()
    deps._get_log_storage.cache_clear()
    deps._get_macaroon_store.cache_clear()
    deps._get_nip05_store.cache_clear()
    deps._get_webhook_dispatcher.cache_clear()

    return changed
