from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from backend.app.sqlite_utils import sqlite_connection


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_sqlite_database_and_sidecars_are_owner_only(tmp_path: Path) -> None:
    database = tmp_path / "lnswitchboard.db"
    with sqlite_connection(database) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
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


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_sqlite_database_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.db"
    sqlite3.connect(target).close()
    alias = tmp_path / "alias.db"
    alias.symlink_to(target)

    with pytest.raises(OSError, match="symbolic link"):
        with sqlite_connection(alias):
            pass
