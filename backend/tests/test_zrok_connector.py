from pathlib import Path

import json
import pytest

from backend.app.zrok_connector import ZrokConnector, ZrokProtocolError


def test_refresh_preserves_last_known_status_until_correlated_reply(tmp_path: Path) -> None:
    connector = ZrokConnector(
        control_dir=tmp_path / "control",
        status_dir=tmp_path / "status",
    )
    status_path = tmp_path / "status" / "status.json"
    original = b'{"state":"connected","operation_id":"previous","frontend_endpoints":["https://pay.example"]}'
    status_path.write_bytes(original)

    operation_id = connector.refresh()

    assert status_path.read_bytes() == original
    assert (tmp_path / "control" / "refresh").read_text(encoding="ascii") == operation_id


@pytest.mark.parametrize("payload", [b"", b"{", b"[]", b"\xff"])
def test_read_status_rejects_partial_or_malformed_snapshots(
    tmp_path: Path, payload: bytes
) -> None:
    connector = ZrokConnector(
        control_dir=tmp_path / "control",
        status_dir=tmp_path / "status",
    )
    (tmp_path / "status" / "status.json").write_bytes(payload)

    with pytest.raises(ZrokProtocolError):
        connector.read_status()


def test_disconnect_command_is_identity_bound(tmp_path: Path) -> None:
    connector = ZrokConnector(
        control_dir=tmp_path / "control",
        status_dir=tmp_path / "status",
    )
    operation_id = connector.disconnect(namespace="public", name="pay-bones")
    payload = json.loads((tmp_path / "control" / "disconnect.json").read_text())
    assert payload == {
        "operation_id": operation_id,
        "namespace": "public",
        "name": "pay-bones",
    }