"""Helpers for reporting configured LND TLS certificate health."""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CERT_TIME_FORMAT = "%b %d %H:%M:%S %Y %Z"


@dataclass(frozen=True)
class TlsCertStatus:
    status: str
    message: str
    expires_at: str | None = None


def parse_cert_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.strptime(value.strip(), CERT_TIME_FORMAT)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def inspect_tls_cert(path: Path, *, now: datetime | None = None) -> TlsCertStatus:
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    if not path.exists():
        return TlsCertStatus(status="missing", message="TLS certificate file is missing")

    try:
        decoded = ssl._ssl._test_decode_cert(str(path))  # noqa: SLF001
    except OSError as exc:
        return TlsCertStatus(status="invalid", message=f"TLS certificate could not be decoded: {exc}")

    not_before = parse_cert_time(decoded.get("notBefore"))
    not_after = parse_cert_time(decoded.get("notAfter"))
    expires_at = not_after.isoformat() if not_after else None

    if not_before and now < not_before:
        return TlsCertStatus(
            status="not_yet_valid",
            message=f"TLS certificate is not valid until {not_before.isoformat()}",
            expires_at=expires_at,
        )
    if not_after and now > not_after:
        return TlsCertStatus(
            status="expired",
            message=f"TLS certificate expired at {not_after.isoformat()}",
            expires_at=expires_at,
        )
    if not_after:
        return TlsCertStatus(
            status="valid",
            message=f"TLS certificate is valid until {not_after.isoformat()}",
            expires_at=expires_at,
        )
    return TlsCertStatus(
        status="unknown",
        message="TLS certificate expiry could not be determined",
    )
