"""Shared SQLite connection lifecycle helpers."""

from __future__ import annotations

import errno
import os
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .secure_files import private_regular

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_SQLITE_OPEN_LOCK = threading.Lock()


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


def _count_open_inode_descriptors(info: os.stat_result) -> int:
    """Count process descriptors referencing the validated database inode."""

    try:
        names = os.listdir("/proc/self/fd")
    except OSError as exc:
        raise OSError("Cannot verify SQLite database descriptor binding") from exc
    count = 0
    for name in names:
        try:
            current = os.fstat(int(name))
        except (OSError, ValueError):
            continue
        if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
            count += 1
    return count


@contextmanager
def sqlite_connection(path: Path) -> Iterator[sqlite3.Connection]:
    """Yield a transactional SQLite connection bound to a stable parent."""

    with private_regular(path, writable=True, create=True) as (
        descriptor,
        parent_fd,
        name,
    ):
        _secure_existing_sidecars(parent_fd, name)
        # Point SQLite at the already validated database descriptor. Using the
        # parent/name pathname here would let a post-validation symlink swap
        # create or open an outside database before our identity check could
        # reject it. SQLite's Unix VFS resolves this descriptor link to the
        # original inode and derives sidecars beside that file.
        stable_path = f"/proc/self/fd/{descriptor}"
        opened = os.fstat(descriptor)
        expected_filename = os.readlink(stable_path)
        with _SQLITE_OPEN_LOCK:
            descriptor_count = _count_open_inode_descriptors(opened)
            connection = sqlite3.connect(
                stable_path,
                detect_types=sqlite3.PARSE_DECLTYPES,
                check_same_thread=False,
            )
            if _count_open_inode_descriptors(opened) <= descriptor_count:
                connection.close()
                raise OSError("SQLite opened a different inode than the validated database")
            main_row = next(
                (
                    row
                    for row in connection.execute("PRAGMA database_list").fetchall()
                    if row[1] == "main"
                ),
                None,
            )
            if main_row is None or os.path.abspath(str(main_row[2])) != expected_filename:
                connection.close()
                raise OSError("SQLite database path changed while opening")
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
