from __future__ import annotations

import ssl
from datetime import datetime, timezone

from backend.app.tls_status import inspect_tls_cert


def test_tls_status_reports_expired_certificate(tmp_path, monkeypatch):
    cert = tmp_path / "tls.cert"
    cert.write_text("CERT", encoding="utf-8")

    monkeypatch.setattr(
        ssl._ssl,  # noqa: SLF001
        "_test_decode_cert",
        lambda _: {
            "notBefore": "Mar 23 02:47:34 2025 GMT",
            "notAfter": "Mar 23 02:47:34 2026 GMT",
        },
    )

    result = inspect_tls_cert(
        cert,
        now=datetime(2026, 4, 27, tzinfo=timezone.utc),
    )

    assert result.status == "expired"
    assert result.expires_at == "2026-03-23T02:47:34+00:00"
    assert "expired" in result.message


def test_tls_status_reports_valid_certificate(tmp_path, monkeypatch):
    cert = tmp_path / "tls.cert"
    cert.write_text("CERT", encoding="utf-8")

    monkeypatch.setattr(
        ssl._ssl,  # noqa: SLF001
        "_test_decode_cert",
        lambda _: {
            "notBefore": "Mar 23 02:47:34 2026 GMT",
            "notAfter": "Mar 23 02:47:34 2027 GMT",
        },
    )

    result = inspect_tls_cert(
        cert,
        now=datetime(2026, 4, 27, tzinfo=timezone.utc),
    )

    assert result.status == "valid"
    assert result.expires_at == "2027-03-23T02:47:34+00:00"


def test_tls_status_reports_missing_certificate(tmp_path):
    result = inspect_tls_cert(tmp_path / "missing.cert")

    assert result.status == "missing"
    assert result.expires_at is None
