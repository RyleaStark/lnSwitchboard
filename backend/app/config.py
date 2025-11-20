"""Runtime configuration management."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import AliasChoices, Field, ValidationInfo, field_validator
from pydantic_core import PydanticUndefined
from pydantic_settings import BaseSettings, SettingsConfigDict


def parse_payer_data_config(value: Any) -> Dict[str, bool]:
    if not value:
        return {}
    if isinstance(value, dict):
        return {str(key): bool(val) for key, val in value.items()}
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
            return result
        if not isinstance(data, dict):
            raise ValueError("LNURL_PAYER_DATA must be a JSON object or shorthand list")
        return {str(key): bool(val) for key, val in data.items()}
    raise ValueError("Unsupported value for LNURL_PAYER_DATA")


def _env_field(*, env: str, default: Any = PydanticUndefined, **kwargs: Any) -> Any:
    """Helper to map settings fields to environment variables in Pydantic v2."""

    alias = AliasChoices(env, env.lower())
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

    service_port: int = _env_field(env="SERVICE_PORT", default=22121)
    lnd_host: str = _env_field(env="LND_HOST", default=...)
    lnd_grpc_port: int = _env_field(env="LND_GRPC_PORT", default=10009)
    lnd_tls_path: Path = _env_field(env="LND_TLS_PATH", default=Path("secrets/tls.cert"))
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
    log_path: Path = _env_field(env="REQUEST_LOG_PATH", default=Path("logs/requests.log"))
    rate_limit_per_min: int = _env_field(env="RATE_LIMIT_PER_MIN", default=30)
    ui_poll_seconds: int = _env_field(env="UI_POLL_SECONDS", default=10)
    macaroon_store_path: Path = _env_field(env="MACAROON_STORE_PATH", default=Path("secrets/macaroon.hex"))
    nip05_store_path: Path = _env_field(env="NIP05_STORE_PATH", default=Path("secrets/nip05_identities.json"))

    @field_validator("lnd_tls_path", "log_path", "macaroon_store_path", "nip05_store_path", mode="before")
    @classmethod
    def _expand_path(cls, value: Optional[str | Path]) -> Path:
        if value is None:
            raise ValueError("Path cannot be None")
        return Path(value).expanduser().resolve()

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


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()  # type: ignore[arg-type]
