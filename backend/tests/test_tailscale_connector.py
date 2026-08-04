from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from backend.app.tailscale_connector import (
    TailscaleConnector,
    TailscaleProtocolError,
)


def _connector(tmp_path: Path) -> TailscaleConnector:
    return TailscaleConnector(
        control_dir=tmp_path / "control",
        status_dir=tmp_path / "status",
    )


def test_connector_parses_consecutive_login_records_and_ignores_partial_tail(
    tmp_path: Path,
) -> None:
    connector = _connector(tmp_path)
    login_path = tmp_path / "status" / "login.json"
    login_path.write_text(
        '{"AuthURL":"REDACTED","BackendState":"NeedsLogin"}\n'
        '{"BackendState":"Running"}\n'
        '{"BackendState":',
        encoding="utf-8",
    )

    assert connector.read_login_records() == [
        {"AuthURL": "REDACTED", "BackendState": "NeedsLogin"},
        {"BackendState": "Running"},
    ]


def test_connector_rejects_unbounded_or_non_object_status(tmp_path: Path) -> None:
    connector = _connector(tmp_path)
    node_path = tmp_path / "status" / "node.json"
    node_path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")

    with pytest.raises(TailscaleProtocolError, match="object"):
        connector.read_node_status()

    node_path.write_text("x" * (64 * 1024 + 1), encoding="utf-8")
    with pytest.raises(TailscaleProtocolError, match="too large"):
        connector.read_node_status()


def test_connector_emits_only_fixed_atomic_marker_operations(tmp_path: Path) -> None:
    connector = _connector(tmp_path)

    connector.begin_login("lns")
    assert (tmp_path / "control" / "login.device-name").read_text(
        encoding="utf-8"
    ) == "lns\n"
    assert (tmp_path / "control" / "begin-login").read_bytes() == b""
    assert stat.S_IMODE((tmp_path / "control" / "begin-login").stat().st_mode) == 0o600

    connector.enable_funnel()
    connector.clear_login()
    assert (tmp_path / "control" / "enable").exists()
    assert (tmp_path / "control" / "clear-login").exists()
    assert not list((tmp_path / "control").glob("*.tmp.*"))

    assert set(connector.supported_operations) == {
        "begin-login",
        "cancel-login",
        "clear-login",
        "enable",
        "disable",
        "disconnect",
    }


def test_connector_reads_sanitized_command_ack(tmp_path: Path) -> None:
    connector = _connector(tmp_path)
    command_path = tmp_path / "status" / "command.json"
    command_path.write_text(
        '{"command":"enable","state":"error","error":"funnel_enable_failed"}\n',
        encoding="utf-8",
    )

    assert connector.read_command_status() == {
        "command": "enable",
        "state": "error",
        "error": "funnel_enable_failed",
    }
