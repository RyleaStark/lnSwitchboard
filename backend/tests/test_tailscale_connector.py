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


def test_connector_emits_immutable_operation_id_commands_without_overwrite(
    tmp_path: Path,
) -> None:
    connector = _connector(tmp_path)

    login_operation = connector.begin_login("lns")
    login_command = tmp_path / "control" / "queue" / f"{login_operation}.json"
    assert json.loads(login_command.read_text(encoding="utf-8")) == {
        "command": "begin_login",
        "device_name": "lns",
        "operation_id": login_operation,
    }
    assert stat.S_IMODE(login_command.stat().st_mode) == 0o600

    enable_operation = connector.enable_funnel(
        external_id="node-123", hostname="lns.example.ts.net"
    )
    clear_operation = connector.clear_login()
    assert (tmp_path / "control" / "queue" / f"{enable_operation}.json").exists()
    assert (tmp_path / "control" / "queue" / f"{clear_operation}.json").exists()
    assert login_command.exists()
    assert not list((tmp_path / "control").rglob("*.tmp.*"))

    assert set(connector.supported_operations) == {
        "begin_login",
        "cancel_login",
        "clear_login",
        "enable",
        "disable",
        "disconnect",
    }


def test_connector_rejects_conflicting_reuse_of_operation_id(tmp_path: Path) -> None:
    connector = _connector(tmp_path)
    operation_id = "c" * 32
    connector.disconnect(
        external_id="node-a", hostname="a.example.ts.net", operation_id=operation_id
    )

    with pytest.raises(TailscaleProtocolError, match="different content"):
        connector.disconnect(
            external_id="node-b",
            hostname="b.example.ts.net",
            operation_id=operation_id,
        )

    payload = json.loads(
        (tmp_path / "control" / "queue" / f"{operation_id}.json").read_text()
    )
    assert payload["external_id"] == "node-a"


def test_connector_rejects_conflicting_id_after_supervisor_claim(tmp_path: Path) -> None:
    connector = _connector(tmp_path)
    operation_id = "d" * 32
    connector.disconnect(
        external_id="node-a", hostname="a.example.ts.net", operation_id=operation_id
    )
    processing = tmp_path / "control" / "processing"
    processing.mkdir()
    (tmp_path / "control" / "queue" / f"{operation_id}.json").replace(
        processing / f"{operation_id}.json"
    )

    with pytest.raises(TailscaleProtocolError, match="different content"):
        connector.disconnect(
            external_id="node-b",
            hostname="b.example.ts.net",
            operation_id=operation_id,
        )

    assert not (tmp_path / "control" / "queue" / f"{operation_id}.json").exists()


def test_connector_does_not_requeue_terminal_operation(tmp_path: Path) -> None:
    connector = _connector(tmp_path)
    operation_id = "e" * 32
    connector.disconnect(
        external_id="node-a", hostname="a.example.ts.net", operation_id=operation_id
    )
    queue = tmp_path / "control" / "queue" / f"{operation_id}.json"
    completed = tmp_path / "control" / "completed" / f"{operation_id}.json"
    completed.write_bytes(
        (tmp_path / "control" / "operations" / f"{operation_id}.json").read_bytes()
    )
    queue.unlink()

    assert (
        connector.disconnect(
            external_id="node-a",
            hostname="a.example.ts.net",
            operation_id=operation_id,
        )
        == operation_id
    )
    assert not queue.exists()


def test_connector_rejects_conflict_against_terminal_tombstone(tmp_path: Path) -> None:
    connector = _connector(tmp_path)
    operation_id = "f" * 32
    connector.disconnect(
        external_id="node-a", hostname="a.example.ts.net", operation_id=operation_id
    )
    completed = tmp_path / "control" / "completed" / f"{operation_id}.json"
    completed.write_bytes(
        (tmp_path / "control" / "operations" / f"{operation_id}.json").read_bytes()
    )
    (tmp_path / "control" / "queue" / f"{operation_id}.json").unlink()

    with pytest.raises(TailscaleProtocolError, match="different content"):
        connector.disconnect(
            external_id="node-b",
            hostname="b.example.ts.net",
            operation_id=operation_id,
        )


@pytest.mark.parametrize("terminal_state", ["result", "ack"])
def test_connector_does_not_requeue_operation_while_terminal_state_is_pending(
    tmp_path: Path, terminal_state: str
) -> None:
    connector = _connector(tmp_path)
    operation_id = "1" * 32
    connector.disconnect(
        external_id="node-a", hostname="a.example.ts.net", operation_id=operation_id
    )
    queue = tmp_path / "control" / "queue" / f"{operation_id}.json"
    queue.unlink()
    if terminal_state == "result":
        (tmp_path / "status" / "results" / f"{operation_id}.json").write_text(
            '{"state":"complete"}', encoding="utf-8"
        )
    else:
        (tmp_path / "control" / "acks" / f"{operation_id}.ack").write_text(
            operation_id, encoding="utf-8"
        )

    assert (
        connector.disconnect(
            external_id="node-a",
            hostname="a.example.ts.net",
            operation_id=operation_id,
        )
        == operation_id
    )
    assert not queue.exists()


def test_connector_removes_queue_when_ack_becomes_completed_during_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector = _connector(tmp_path)
    operation_id = "2" * 32
    connector.disconnect(
        external_id="node-a", hostname="a.example.ts.net", operation_id=operation_id
    )
    operation = tmp_path / "control" / "operations" / f"{operation_id}.json"
    queue = tmp_path / "control" / "queue" / f"{operation_id}.json"
    completed = tmp_path / "control" / "completed" / f"{operation_id}.json"
    result = tmp_path / "status" / "results" / f"{operation_id}.json"
    acknowledgement = tmp_path / "control" / "acks" / f"{operation_id}.ack"
    queue.unlink()
    result.write_text('{"state":"complete"}', encoding="utf-8")
    acknowledgement.write_text(operation_id, encoding="utf-8")

    original_read = connector._read_bounded
    original_exists = Path.exists
    completed_reads = 0

    def transition_after_completed_read(path: Path) -> str | None:
        nonlocal completed_reads
        value = original_read(path)
        if path == completed:
            completed_reads += 1
            if completed_reads == 2:
                completed.write_bytes(operation.read_bytes())
                result.unlink()
                acknowledgement.unlink()
        return value

    def terminal_artifact_disappeared(path: Path) -> bool:
        if path in {result, acknowledgement}:
            return False
        return original_exists(path)

    monkeypatch.setattr(connector, "_read_bounded", transition_after_completed_read)
    monkeypatch.setattr(Path, "exists", terminal_artifact_disappeared)

    assert (
        connector.disconnect(
            external_id="node-a",
            hostname="a.example.ts.net",
            operation_id=operation_id,
        )
        == operation_id
    )
    assert completed.exists()
    assert not queue.exists()


def test_connector_reads_sanitized_command_ack(tmp_path: Path) -> None:
    connector = _connector(tmp_path)
    operation_id = "a" * 32
    result_dir = tmp_path / "status" / "results"
    command_path = result_dir / f"{operation_id}.json"
    command_path.write_text(
        '{"command":"enable","state":"error","error":"funnel_enable_failed"}\n',
        encoding="utf-8",
    )

    assert connector.read_command_status(operation_id) == {
        "command": "enable",
        "state": "error",
        "error": "funnel_enable_failed",
    }


def test_connector_consumes_only_the_requested_durable_result(tmp_path: Path) -> None:
    connector = _connector(tmp_path)
    first = "a" * 32
    second = "b" * 32
    result_dir = tmp_path / "status" / "results"
    for operation_id in (first, second):
        (result_dir / f"{operation_id}.json").write_text(
            json.dumps(
                {
                    "command": "disconnect",
                    "state": "complete",
                    "operation_id": operation_id,
                    "external_id": "node-123",
                    "hostname": "lns.example.ts.net",
                }
            ),
            encoding="utf-8",
        )

    connector.consume_command_result(first)

    assert connector.read_command_status(first) is not None
    assert (tmp_path / "control" / "acks" / f"{first}.ack").exists()
    assert connector.read_command_status(second) is not None


def test_connector_requeues_retryable_error_result_under_protocol_lock(
    tmp_path: Path
) -> None:
    connector = _connector(tmp_path)
    operation_id = "b" * 32
    connector.disconnect(
        external_id="node-a",
        hostname="a.example.ts.net",
        operation_id=operation_id,
    )
    queue = tmp_path / "control" / "queue" / f"{operation_id}.json"
    queue.unlink()
    result = tmp_path / "status" / "results" / f"{operation_id}.json"
    result.write_text(
        json.dumps(
            {
                "command": "disconnect",
                "state": "error",
                "error": "funnel_disable_failed",
                "operation_id": operation_id,
            }
        ),
        encoding="utf-8",
    )

    connector.disconnect(
        external_id="node-a",
        hostname="a.example.ts.net",
        operation_id=operation_id,
        retry=True,
    )

    assert not result.exists()
    assert queue.exists()
