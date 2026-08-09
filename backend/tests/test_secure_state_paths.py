from __future__ import annotations

import asyncio
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from ..app.connection_secret_store import ConnectionSecretStore
from ..app.log_storage import RequestLogStorage
from ..app.macaroon_store import MacaroonNotConfiguredError, MacaroonStore
from ..app.nostr_signer_store import NostrSignerStore
from ..app.secure_files import atomic_write_private
from ..app.sqlite_utils import sqlite_connection


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_primary_database_hardlink_is_rejected_without_mutation(tmp_path: Path) -> None:
    target = tmp_path / "outside.db"
    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE sentinel(value TEXT)")
        connection.execute("INSERT INTO sentinel VALUES ('outside')")
    target.chmod(0o644)
    alias = tmp_path / "state.db"
    os.link(target, alias)

    with pytest.raises(OSError, match="hard link"):
        RequestLogStorage(alias)

    with sqlite3.connect(target) as connection:
        assert connection.execute("SELECT value FROM sentinel").fetchone()[0] == "outside"
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert names == {"sentinel"}
    assert _mode(target) == 0o644


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_sqlite_sidecar_hardlink_is_rejected_without_mutation(
    tmp_path: Path, suffix: str
) -> None:
    database = tmp_path / "state.db"
    sqlite3.connect(database).close()
    outside = tmp_path / f"outside{suffix}"
    outside.write_bytes(b"outside-sidecar")
    outside.chmod(0o644)
    os.link(outside, Path(f"{database}{suffix}"))

    with pytest.raises(OSError, match="hard link"):
        with sqlite_connection(database):
            pass

    assert outside.read_bytes() == b"outside-sidecar"
    assert _mode(outside) == 0o644


def test_existing_secret_hardlinks_are_not_loaded_or_chmodded(tmp_path: Path) -> None:
    key_target = tmp_path / "outside-key"
    key_target.write_bytes(b"known-key")
    key_target.chmod(0o644)
    key_alias = tmp_path / "connection-secrets.key"
    os.link(key_target, key_alias)
    with pytest.raises(OSError, match="hard link"):
        ConnectionSecretStore(tmp_path / "connections.db", key_alias)
    assert _mode(key_target) == 0o644

    macaroon_target = tmp_path / "outside-macaroon"
    macaroon_target.write_text("ab" * 32, encoding="ascii")
    macaroon_target.chmod(0o644)
    macaroon_alias = tmp_path / "manual.hex"
    os.link(macaroon_target, macaroon_alias)
    macaroon = MacaroonStore(macaroon_alias)
    with pytest.raises(MacaroonNotConfiguredError):
        asyncio.run(macaroon.get())
    assert _mode(macaroon_target) == 0o644

    signer_target = tmp_path / "outside-signer"
    signer_target.write_text("11" * 32, encoding="ascii")
    signer_target.chmod(0o644)
    signer_alias = tmp_path / "signer.hex"
    os.link(signer_target, signer_alias)
    with pytest.raises(OSError, match="hard link"):
        asyncio.run(NostrSignerStore(signer_alias).get_private_key())
    assert _mode(signer_target) == 0o644


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs unavailable")
def test_sensitive_fifo_paths_fail_without_blocking(tmp_path: Path) -> None:
    key_fifo = tmp_path / "connection-secrets.key"
    os.mkfifo(key_fifo)
    with pytest.raises(OSError, match="regular file"):
        ConnectionSecretStore(tmp_path / "connections.db", key_fifo)

    database_fifo = tmp_path / "database.fifo"
    os.mkfifo(database_fifo)
    with pytest.raises(OSError, match="regular file"):
        RequestLogStorage(database_fifo)

    macaroon_fifo = tmp_path / "macaroon.fifo"
    os.mkfifo(macaroon_fifo)
    macaroon = MacaroonStore(macaroon_fifo)
    with pytest.raises(MacaroonNotConfiguredError):
        asyncio.run(macaroon.get())

    signer_fifo = tmp_path / "signer.fifo"
    os.mkfifo(signer_fifo)
    with pytest.raises(OSError, match="regular file"):
        asyncio.run(NostrSignerStore(signer_fifo).get_private_key())

    sidecar_database = tmp_path / "sidecar.db"
    sqlite3.connect(sidecar_database).close()
    os.mkfifo(Path(f"{sidecar_database}-journal"))
    with pytest.raises(OSError, match="regular file"):
        with sqlite_connection(sidecar_database):
            pass


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_mounted_macaroon_symlink_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside.macaroon"
    outside.write_bytes(bytes.fromhex("ab" * 32))
    alias = tmp_path / "mounted.macaroon"
    alias.symlink_to(outside)
    store = MacaroonStore(tmp_path / "manual.hex", source_path=alias)

    assert asyncio.run(store.is_configured()) is False
    with pytest.raises(MacaroonNotConfiguredError):
        asyncio.run(store.get())


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_post_configuration_parent_swap_cannot_redirect_private_writes(
    tmp_path: Path,
) -> None:
    configured_parent = tmp_path / "configured"
    configured_parent.mkdir()
    moved_parent = tmp_path / "configured-moved"
    outside_parent = tmp_path / "outside"
    outside_parent.mkdir()
    configured_parent.rename(moved_parent)
    configured_parent.symlink_to(outside_parent, target_is_directory=True)

    with pytest.raises(OSError):
        ConnectionSecretStore(
            configured_parent / "state.db",
            configured_parent / "connection-secrets.key",
        )
    with pytest.raises(OSError):
        asyncio.run(MacaroonStore(configured_parent / "macaroon.hex").set("ab" * 32))
    with pytest.raises(OSError):
        asyncio.run(NostrSignerStore(configured_parent / "signer.hex").generate())
    with pytest.raises(OSError):
        atomic_write_private(configured_parent / "node.env", b"token", mode=0o640)

    assert list(outside_parent.iterdir()) == []
