from __future__ import annotations

import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from backend.app.sqlite_utils import sqlite_connection, sqlite_read_connection


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_sqlite_database_and_sidecars_are_owner_only(tmp_path: Path) -> None:
    database = tmp_path / "lnswitchboard.db"
    with sqlite_connection(database) as connection:
        connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
        connection.execute("INSERT INTO records VALUES ('safe')")
        assert _mode(database) == 0o600
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(f"{database}{suffix}")
            if sidecar.exists():
                assert _mode(sidecar) == 0o600

    os.chmod(database, 0o644)
    with sqlite_connection(database) as connection:
        assert connection.execute("SELECT value FROM records").fetchone()[0] == "safe"
    assert _mode(database) == 0o600


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_sqlite_rejects_runtime_sidecar_mode_changes_without_outside_mutation(
    tmp_path: Path, kind: str, suffix: str
) -> None:
    database = tmp_path / "state.db"
    outside = tmp_path / "outside"
    original = b"OUTSIDE" + b"Q" * 32768
    outside.write_bytes(original)
    sidecar = Path(f"{database}{suffix}")

    with pytest.raises((sqlite3.DatabaseError, OSError)):
        with sqlite_connection(database) as connection:
            if suffix == "-journal":
                sidecar.unlink()
            if kind == "symlink":
                sidecar.symlink_to(outside)
            else:
                os.link(outside, sidecar)
            connection.execute("PRAGMA journal_mode=WAL")

    assert outside.read_bytes() == original
    sidecar.unlink()
    assert outside.stat().st_nlink == 1
    assert not sidecar.exists()


def test_sqlite_rejects_a_persisted_wal_database(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("CREATE TABLE records(value TEXT)")

    with pytest.raises(OSError, match="WAL mode is not permitted"):
        with sqlite_connection(database):
            pass


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_sqlite_database_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.db"
    sqlite3.connect(target).close()
    alias = tmp_path / "alias.db"
    alias.symlink_to(target)

    with pytest.raises(OSError, match="symbolic link"):
        with sqlite_connection(alias):
            pass


def test_sqlite_connection_descriptor_binding_survives_concurrent_lifecycles(
    tmp_path: Path,
) -> None:
    database = tmp_path / "concurrent.db"
    with sqlite_connection(database) as connection:
        connection.execute("CREATE TABLE records (worker INTEGER, iteration INTEGER)")

    def worker(_worker_id: int) -> int:
        completed = 0
        for _iteration in range(30):
            with sqlite_connection(database) as connection:
                connection.execute("SELECT COUNT(*) FROM records").fetchone()
            completed += 1
        return completed

    with ThreadPoolExecutor(max_workers=4) as executor:
        completed = list(executor.map(worker, range(4)))

    assert completed == [30, 30, 30, 30]


def test_sqlite_read_repairs_mode_without_mutating_database_contents(tmp_path: Path) -> None:
    database = tmp_path / "read.db"
    with sqlite_connection(database) as connection:
        connection.execute("CREATE TABLE records(value TEXT)")
        connection.execute("INSERT INTO records VALUES ('safe')")
    before = database.read_bytes()
    before_mtime = database.stat().st_mtime_ns
    os.chmod(database, 0o644)

    with sqlite_read_connection(database) as connection:
        assert connection.execute("SELECT value FROM records").fetchone()[0] == "safe"

    assert _mode(database) == 0o600
    assert database.read_bytes() == before
    assert database.stat().st_mtime_ns == before_mtime


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_sqlite_read_rejects_hostile_sidecars(
    tmp_path: Path, kind: str, suffix: str
) -> None:
    database = tmp_path / "read.db"
    with sqlite_connection(database) as connection:
        connection.execute("CREATE TABLE records(value TEXT)")
    sidecar = Path(f"{database}{suffix}")
    sidecar.unlink(missing_ok=True)
    outside = tmp_path / f"outside-{kind}-{suffix[1:]}"
    outside.write_bytes(b"outside")
    if kind == "symlink":
        sidecar.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, sidecar)
    else:
        os.mkfifo(sidecar)

    with pytest.raises(OSError):
        with sqlite_read_connection(database):
            pass


def test_sqlite_read_rejects_persisted_wal_database(tmp_path: Path) -> None:
    database = tmp_path / "wal.db"
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("CREATE TABLE records(value INTEGER)")

    with pytest.raises(OSError, match="WAL mode is not permitted"):
        with sqlite_read_connection(database):
            pass
