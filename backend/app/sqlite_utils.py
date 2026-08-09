"""Shared SQLite connection lifecycle helpers."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def _secure_existing_sidecars(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not sidecar.exists():
            continue
        if sidecar.is_symlink():
            raise OSError("SQLite sidecar path must not be a symbolic link")
        os.chmod(sidecar, 0o600)


@contextmanager
def sqlite_connection(path: Path) -> Iterator[sqlite3.Connection]:
    """Yield a transactional SQLite connection and always close it."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise OSError("SQLite database path must not be a symbolic link")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    _secure_existing_sidecars(path)
    connection = sqlite3.connect(
        path,
        detect_types=sqlite3.PARSE_DECLTYPES,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()
        _secure_existing_sidecars(path)
