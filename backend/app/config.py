"""Runtime configuration management."""

from __future__ import annotations

import json
from collections.abc import Sequence
from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import AliasChoices, Field, ValidationInfo, field_validator
from pydantic_core import PydanticUndefined
from pydantic_settings import BaseSettings, SettingsConfigDict


def parse_payer_data_config(value: Any) -> Dict[str, bool]:
    def _validated_config(data: Dict[str, bool]) -> Dict[str, bool]:
        normalized: Dict[str, bool] = {}
        for key, mandatory in data.items():
            field = str(key).strip()
            if not field:
                continue
            if field.lower() == "auth":
                raise ValueError("LNURL_PAYER_DATA auth is not supported until auth.k1 verification is implemented")
            normalized[field] = bool(mandatory)
        return normalized

    if not value:
        return {}
    if isinstance(value, dict):
        return _validated_config({str(key): bool(val) for key, val in value.items()})
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return {}
        try:
            data = json.loads(value)
        except json.JSONDecodeError:
            result: Dict[str, bool] = {}
            for part in value.split(","):
                part = part.strip()
                if not part:
                    continue
                mandatory = part.startswith("!")
                field = part[1:] if mandatory else part
                if not field:
                    continue
                result[field] = mandatory
            return _validated_config(result)
        if not isinstance(data, dict):
            raise ValueError("LNURL_PAYER_DATA must be a JSON object or shorthand list")
        return _validated_config({str(key): bool(val) for key, val in data.items()})
    raise ValueError("Unsupported value for LNURL_PAYER_DATA")


def parse_trusted_proxy_cidrs(value: str | Sequence[str]) -> tuple[IPv4Network | IPv6Network, ...]:
    """Parse trusted reverse-proxy networks from a comma-separated value."""

    values = value.split(",") if isinstance(value, str) else value
    networks: list[IPv4Network | IPv6Network] = []
    for item in values:
        normalized = str(item).strip()
        if normalized:
            networks.append(ip_network(normalized, strict=False))
    return tuple(networks)


def parse_trusted_hosts(value: str | Sequence[str]) -> tuple[str, ...]:
    """Parse allowed HTTP Host values, including optional leading wildcards."""

    values = value.split(",") if isinstance(value, str) else value
    hosts: list[str] = []
    for item in values:
        host = str(item).strip().lower()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if not host:
            continue
        if "://" in host or "/" in host or any(character.isspace() for character in host):
            raise ValueError("TRUSTED_HOSTS entries must be hostnames or IP addresses")
        hosts.append(host)
    if not hosts:
        raise ValueError("TRUSTED_HOSTS must contain at least one host")
    return tuple(hosts)


def _env_field(*, env: str | Sequence[str], default: Any = PydanticUndefined, **kwargs: Any) -> Any:
    """Helper to map settings fields to environment variables in Pydantic v2."""

    if isinstance(env, str):
        alias_choices = [env, env.lower()]
    else:
        alias_choices = []
        for item in env:
            alias_choices.append(item)
            alias_choices.append(item.lower())
    alias = AliasChoices(*alias_choices)
    kwargs.setdefault("validation_alias", alias)
    if "default_factory" in kwargs:
        factory = kwargs.pop("default_factory")
        return Field(default_factory=factory, **kwargs)
    actual_default = default if default is not PydanticUndefined else ...
    return Field(actual_default, **kwargs)


class Settings(BaseSettings):
    """Centralized application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        env_ignore_empty=True,
    )

    service_host: str = _env_field(
        env=("SERVICE_HOST", "LNSWITCHBOARD_BIND_ADDRESS"),
        default="127.0.0.1",
    )
    service_port: int = _env_field(env="SERVICE_PORT", default=22121)
    public_service_host: str = _env_field(
        env=("PUBLIC_SERVICE_HOST", "LNSWITCHBOARD_PUBLIC_BIND_ADDRESS"),
        default="127.0.0.1",
    )
    public_service_port: int = _env_field(env="PUBLIC_SERVICE_PORT", default=21212)
    dep_env: str = _env_field(env="DEP_ENV", default="DOCKER")
    lnd_host: str = _env_field(env="LND_HOST", default=...)
    lnd_grpc_port: int = _env_field(env="LND_GRPC_PORT", default=10009)
    lnd_tls_path: Path = _env_field(env="LND_TLS_PATH", default=Path("secrets/tls.cert"))
    lnd_tls_server_name: Optional[str] = _env_field(env="LND_TLS_SERVER_NAME", default=None)
    max_sendable_sat: int = _env_field(env="MAX_SENDABLE_SAT", default=1_000_000)
    min_sendable_sat: int = _env_field(env="MIN_SENDABLE_SAT", default=1)
    metadata_description: str = _env_field(env="LNURL_METADATA_DESCRIPTION", default="Pay {ln_address}")
    success_message: str = _env_field(
        env="LNURL_SUCCESS_MESSAGE",
        default="Your payment hit faster than a Lightning bolt — {ln_address} stacked your sats!",
    )
    comment_max_length: int = _env_field(env="LNURL_COMMENT_MAX_LENGTH", default=280)
    metadata_long_description: Optional[str] = _env_field(
        env="LNURL_METADATA_LONG_DESC",
        default=None,
    )
    payer_data: Dict[str, bool] = _env_field(
        default_factory=dict,
        description="Mapping of payerData fields to mandatory flag.",
        json_schema_extra={"example": {"name": False, "identifier": True}},
        env="LNURL_PAYER_DATA",
    )
    recent_log_limit: int = _env_field(env="RECENT_LOG_LIMIT", default=50)
    log_retention_days: int = _env_field(env="LOG_RETENTION_DAYS", default=180)
    data_store_path: Path = _env_field(env="DATA_STORE_PATH", default=Path("secrets/lnswitchboard.db"))
    rate_limit_per_min: int = _env_field(env="RATE_LIMIT_PER_MIN", default=30)
    trusted_proxy_cidrs: str = _env_field(env="TRUSTED_PROXY_CIDRS", default="")
    trusted_hosts: str = _env_field(env="TRUSTED_HOSTS", default="localhost,127.0.0.1,[::1]")
    allow_private_nostr_relays: bool = _env_field(env="ALLOW_PRIVATE_NOSTR_RELAYS", default=False)
    allow_private_webhooks: bool = _env_field(env="ALLOW_PRIVATE_WEBHOOKS", default=False)
    ui_poll_seconds: int = _env_field(env="UI_POLL_SECONDS", default=10)
    macaroon_store_path: Path = _env_field(env="MACAROON_STORE_PATH", default=Path("secrets/macaroon.hex"))
    lnd_macaroon_path: Optional[Path] = _env_field(env="LND_MACAROON_PATH", default=None)
    lnd_readonly_macaroon_path: Optional[Path] = _env_field(env="LND_READONLY_MACAROON_PATH", default=None)
    webhook_max_retries: int = _env_field(env="WEBHOOK_MAX_RETRIES", default=5)
    webhook_retry_window_seconds: int = _env_field(env="WEBHOOK_RETRY_WINDOW_SECONDS", default=600)
    nostr_zap_secret_path: Path = _env_field(
        env="NOSTR_ZAP_SECRET_PATH",
        default=Path("secrets/nostr_zap_signer.hex"),
    )

    @field_validator("lnd_tls_path", "data_store_path", "macaroon_store_path", "nostr_zap_secret_path", mode="before")
    @classmethod
    def _expand_path(cls, value: Optional[str | Path]) -> Path:
        if value is None:
            raise ValueError("Path cannot be None")
        return Path(value).expanduser().resolve()

    @field_validator("lnd_macaroon_path", "lnd_readonly_macaroon_path", mode="before")
    @classmethod
    def _expand_optional_path(cls, value: Optional[str | Path]) -> Optional[Path]:
        if value is None or value == "":
            return None
        return Path(value).expanduser().resolve()

    @field_validator("lnd_tls_server_name", mode="before")
    @classmethod
    def _normalize_tls_server_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        trimmed = str(value).strip()
        if trimmed.lower() in {"", "none", "false", "off", "disabled"}:
            return None
        return trimmed

    @field_validator("trusted_proxy_cidrs", mode="before")
    @classmethod
    def _validate_trusted_proxy_cidrs(cls, value: Optional[str]) -> str:
        normalized = str(value or "").strip()
        parse_trusted_proxy_cidrs(normalized)
        return normalized

    @field_validator("trusted_hosts", mode="before")
    @classmethod
    def _validate_trusted_hosts(cls, value: Optional[str]) -> str:
        normalized = str(value or "").strip()
        parse_trusted_hosts(normalized)
        return normalized

    @field_validator("dep_env", mode="before")
    @classmethod
    def _normalize_dep_env(cls, value: Optional[str]) -> str:
        if value is None:
            return "DOCKER"
        normalized = str(value).strip().upper().replace("_", "-")
        if not normalized:
            return "DOCKER"
        if normalized not in {"DOCKER", "UMBREL", "UMBREL-DEV"}:
            raise ValueError("DEP_ENV must be one of DOCKER, UMBREL, or UMBREL-DEV")
        return normalized

    @field_validator("max_sendable_sat")
    @classmethod
    def _validate_max_sendable(cls, value: int, info: ValidationInfo) -> int:
        min_value = info.data.get("min_sendable_sat", 1)
        if value < min_value:
            raise ValueError("MAX_SENDABLE_SAT must be >= MIN_SENDABLE_SAT")
        return value

    @field_validator("comment_max_length")
    @classmethod
    def _validate_comment_max_length(cls, value: int) -> int:
        if value < 0:
            raise ValueError("LNURL_COMMENT_MAX_LENGTH must be >= 0")
        return value

    @field_validator("metadata_long_description")
    @classmethod
    def _normalize_long_desc(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        trimmed = value.strip()
        return trimmed or None

    @field_validator("payer_data", mode="before")
    @classmethod
    def _parse_payer_data(cls, value):
        return parse_payer_data_config(value)

    @field_validator("webhook_max_retries")
    @classmethod
    def _validate_webhook_max_retries(cls, value: int) -> int:
        if value < 0:
            raise ValueError("WEBHOOK_MAX_RETRIES must be >= 0")
        return value

    @field_validator("webhook_retry_window_seconds")
    @classmethod
    def _validate_webhook_retry_window(cls, value: int) -> int:
        if value < 0:
            raise ValueError("WEBHOOK_RETRY_WINDOW_SECONDS must be >= 0")
        return value


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()  # type: ignore[arg-type]
