"""Shared SQLite connection lifecycle helpers."""

from __future__ import annotations

import errno
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .secure_files import private_regular

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def _validate_regular_single_link(info: os.stat_result, *, label: str) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"{label} must be a regular file")
    if info.st_nlink != 1:
        raise OSError(f"{label} must have exactly one hard link")


def _secure_existing_sidecars(parent_fd: int, name: str) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar_name = f"{name}{suffix}"
        flags = os.O_RDWR | _NOFOLLOW | _NONBLOCK | _CLOEXEC
        try:
            descriptor = os.open(sidecar_name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            continue
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise OSError("SQLite sidecar path must not be a symbolic link") from exc
            raise
        try:
            _validate_regular_single_link(
                os.fstat(descriptor), label="SQLite sidecar path"
            )
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)


@contextmanager
def sqlite_connection(path: Path) -> Iterator[sqlite3.Connection]:
    """Yield a transactional SQLite connection bound to a stable parent."""

    with private_regular(path, writable=True, create=True) as (
        descriptor,
        parent_fd,
        name,
    ):
        _secure_existing_sidecars(parent_fd, name)
        stable_path = f"/proc/self/fd/{parent_fd}/{name}"
        connection = sqlite3.connect(
            stable_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,
        )
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            connection.close()
            raise OSError("SQLite database path changed while opening")
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()
            _secure_existing_sidecars(parent_fd, name)
