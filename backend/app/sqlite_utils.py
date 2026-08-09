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


def _deny_sidecar_mode_changes(
    action: int,
    argument_one: str | None,
    _argument_two: str | None,
    _database_name: str | None,
    _trigger_name: str | None,
) -> int:
    """Keep private state on rollback-journal mode after the secure open gate."""

    if action == sqlite3.SQLITE_PRAGMA and (argument_one or "").lower() == "journal_mode":
        return sqlite3.SQLITE_DENY
    if action in {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH}:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


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


def _open_journal(parent_fd: int, name: str) -> int:
    journal_name = f"{name}-journal"
    flags = os.O_RDWR | os.O_CREAT | _NOFOLLOW | _NONBLOCK | _CLOEXEC
    try:
        descriptor = os.open(journal_name, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise OSError("SQLite journal path must not be a symbolic link") from exc
        raise
    try:
        _validate_regular_single_link(os.fstat(descriptor), label="SQLite journal path")
        os.fchmod(descriptor, 0o600)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


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
    """Yield a transaction bound to stable database and journal descriptors."""

    with private_regular(path, writable=True, create=True) as (
        descriptor,
        parent_fd,
        name,
    ):
        _secure_existing_sidecars(parent_fd, name)
        journal_descriptor = _open_journal(parent_fd, name)
        journal_opened = os.fstat(journal_descriptor)
        connection: sqlite3.Connection | None = None
        try:
            # Point SQLite at the validated database descriptor. Its Unix VFS
            # resolves this link to the original inode and derives the journal
            # beside that file.
            stable_path = f"/proc/self/fd/{descriptor}"
            opened = os.fstat(descriptor)
            header = os.pread(descriptor, 20, 0)
            if len(header) >= 20 and header[18:20] == b"\x02\x02":
                raise OSError("SQLite WAL mode is not permitted for private state")
            expected_filename = os.readlink(stable_path)
            with _SQLITE_OPEN_LOCK:
                descriptor_count = _count_open_inode_descriptors(opened)
                journal_count = _count_open_inode_descriptors(journal_opened)
                connection = sqlite3.connect(
                    stable_path,
                    detect_types=sqlite3.PARSE_DECLTYPES,
                    check_same_thread=False,
                )
                if _count_open_inode_descriptors(opened) <= descriptor_count:
                    raise OSError(
                        "SQLite opened a different inode than the validated database"
                    )
                main_row = next(
                    (
                        row
                        for row in connection.execute("PRAGMA database_list").fetchall()
                        if row[1] == "main"
                    ),
                    None,
                )
                if (
                    main_row is None
                    or os.path.abspath(str(main_row[2])) != expected_filename
                ):
                    raise OSError("SQLite database path changed while opening")
                connection.execute("PRAGMA locking_mode=EXCLUSIVE")
                journal_mode = connection.execute("PRAGMA journal_mode=PERSIST").fetchone()[0]
                if str(journal_mode).lower() != "persist":
                    raise OSError("SQLite rollback journal could not be made persistent")
                user_version = int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                )
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(f"PRAGMA user_version={user_version}")
                connection.commit()
                if _count_open_inode_descriptors(journal_opened) <= journal_count:
                    raise OSError(
                        "SQLite opened a different inode than the validated journal"
                    )
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            journal_current = os.stat(
                f"{name}-journal", dir_fd=parent_fd, follow_symlinks=False
            )
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise OSError("SQLite database path changed while opening")
            if (journal_opened.st_dev, journal_opened.st_ino) != (
                journal_current.st_dev,
                journal_current.st_ino,
            ):
                raise OSError("SQLite journal path changed while opening")
            connection.row_factory = sqlite3.Row
            connection.set_authorizer(_deny_sidecar_mode_changes)
            with connection:
                yield connection
        finally:
            if connection is not None:
                connection.close()
            try:
                journal_current = os.stat(
                    f"{name}-journal", dir_fd=parent_fd, follow_symlinks=False
                )
                if (journal_opened.st_dev, journal_opened.st_ino) != (
                    journal_current.st_dev,
                    journal_current.st_ino,
                ):
                    raise OSError("SQLite journal path changed while in use")
            finally:
                os.close(journal_descriptor)
            _secure_existing_sidecars(parent_fd, name)
