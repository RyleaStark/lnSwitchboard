"""Runtime configuration management."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import Field, FieldValidationInfo, field_validator
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


class Settings(BaseSettings):
    """Centralized application settings."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    service_port: int = Field(22121, env="SERVICE_PORT")
    lnd_host: str = Field(..., env="LND_HOST")
    lnd_grpc_port: int = Field(10009, env="LND_GRPC_PORT")
    lnd_tls_path: Path = Field(Path("secrets/tls.cert"), env="LND_TLS_PATH")
    max_sendable_sat: int = Field(1_000_000, env="MAX_SENDABLE_SAT")
    min_sendable_sat: int = Field(1, env="MIN_SENDABLE_SAT")
    metadata_description: str = Field("Pay", env="LNURL_METADATA_DESCRIPTION")
    comment_max_length: int = Field(280, env="LNURL_COMMENT_MAX_LENGTH")
    metadata_long_description: Optional[str] = Field(
        None, env="LNURL_METADATA_LONG_DESC"
    )
    payer_data: Dict[str, bool] = Field(
        default_factory=dict,
        description="Mapping of payerData fields to mandatory flag.",
        json_schema_extra={"example": {"name": False, "identifier": True}},
        env="LNURL_PAYER_DATA",
    )
    recent_log_limit: int = Field(50, env="RECENT_LOG_LIMIT")
    log_path: Path = Field(Path("logs/requests.log"), env="REQUEST_LOG_PATH")
    rate_limit_per_min: int = Field(10, env="RATE_LIMIT_PER_MIN")
    ui_poll_seconds: int = Field(10, env="UI_POLL_SECONDS")
    macaroon_store_path: Path = Field(Path("secrets/macaroon.hex"), env="MACAROON_STORE_PATH")

    @field_validator("lnd_tls_path", "log_path", "macaroon_store_path", mode="before")
    @classmethod
    def _expand_path(cls, value: Optional[str | Path]) -> Path:
        if value is None:
            raise ValueError("Path cannot be None")
        return Path(value).expanduser().resolve()

    @field_validator("max_sendable_sat")
    @classmethod
    def _validate_max_sendable(cls, value: int, info: FieldValidationInfo) -> int:
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
