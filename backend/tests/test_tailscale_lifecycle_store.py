import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from backend.app.tailscale_lifecycle_store import TailscaleLifecycleStore


def test_disconnect_journal_conserves_identity_and_phase_across_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "tailscale-lifecycle.db"
    store = TailscaleLifecycleStore(path)

    created = store.create_disconnect(
        operation_id="a" * 32,
        connection_id="connection-1",
        external_id="node-123",
        hostname="lns.example.ts.net",
    )
    assert created.phase == "prepared"

    store.update("a" * 32, phase="command_published")
    reopened = TailscaleLifecycleStore(path)

    assert reopened.get("a" * 32).phase == "command_published"
    assert reopened.get("a" * 32).external_id == "node-123"
    assert reopened.list_pending()[0].hostname == "lns.example.ts.net"

    reopened.delete("a" * 32)
    assert reopened.get("a" * 32) is None


def test_disconnect_creation_is_cross_process_idempotent_per_connection(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"

    def create(operation_id: str):
        return TailscaleLifecycleStore(path).create_disconnect(
            operation_id=operation_id,
            connection_id="connection-1",
            external_id="node-1",
            hostname="node.tailnet.ts.net",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(create, ("op-a", "op-b")))

    assert rows[0].operation_id == rows[1].operation_id
    assert len(TailscaleLifecycleStore(path).list_pending()) == 1
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_lifecycle_rejects_hostile_lockfile(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "state.sqlite3"
    lock = Path(f"{path}.lock")
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    if kind == "symlink":
        lock.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, lock)
    else:
        os.mkfifo(lock)

    with pytest.raises(OSError):
        TailscaleLifecycleStore(path)

    assert outside.read_bytes() == b"outside"
