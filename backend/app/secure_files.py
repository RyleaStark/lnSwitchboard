"""Descriptor-bound helpers for private application state files."""

from __future__ import annotations

import errno
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _validate_regular(info: os.stat_result, *, label: str) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise OSError(f"{label} must not be a symbolic link")
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"{label} must be a regular file")
    if info.st_nlink != 1:
        raise OSError(f"{label} must have exactly one hard link")


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError(errno.EIO, "write returned no progress")
        remaining = remaining[written:]


@contextmanager
def secure_parent(path: Path, *, create: bool = False) -> Iterator[tuple[int, str]]:
    """Walk to an absolute parent using no-follow directory descriptors."""

    candidate = Path(os.path.abspath(path))
    if candidate.name in {"", ".", ".."}:
        raise OSError("private state path has no safe leaf name")
    parts = candidate.parts
    descriptor = os.open(parts[0], _DIRECTORY_FLAGS | _NOFOLLOW)
    try:
        for component in parts[1:-1]:
            if component in {"", ".", ".."}:
                raise OSError("private state path contains an unsafe component")
            try:
                child = os.open(
                    component,
                    _DIRECTORY_FLAGS | _NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(
                    component,
                    _DIRECTORY_FLAGS | _NOFOLLOW,
                    dir_fd=descriptor,
                )
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise OSError("private state parent must be a directory")
            os.close(descriptor)
            descriptor = child
        yield descriptor, candidate.name
    finally:
        os.close(descriptor)


@contextmanager
def private_regular(
    path: Path,
    *,
    writable: bool,
    create: bool = False,
    mode: int = 0o600,
) -> Iterator[tuple[int, int, str]]:
    """Open a regular single-link leaf with its stable parent descriptor."""

    with secure_parent(path, create=create) as (parent_fd, name):
        flags = (os.O_RDWR if writable else os.O_RDONLY) | _NOFOLLOW | _NONBLOCK
        flags |= getattr(os, "O_CLOEXEC", 0)
        if create:
            flags |= os.O_CREAT
        try:
            descriptor = os.open(name, flags, mode, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise OSError("private state file must not be a symbolic link") from exc
            raise
        try:
            info = os.fstat(descriptor)
            _validate_regular(info, label="private state file")
            if writable and hasattr(os, "fchmod"):
                os.fchmod(descriptor, mode)
            yield descriptor, parent_fd, name
        finally:
            os.close(descriptor)


def read_private_file(
    path: Path, *, chmod: bool = False, maximum_bytes: int = 1024 * 1024
) -> bytes:
    with private_regular(path, writable=chmod) as (descriptor, _, _):
        if chmod and hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum_bytes:
            raise OSError("private state file exceeds the safe size limit")
        return payload


def atomic_write_private(
    path: Path,
    payload: bytes,
    *,
    mode: int = 0o600,
    uid: int = -1,
    gid: int = -1,
    parent_mode: int | None = None,
    parent_gid: int = -1,
) -> None:
    """Atomically replace a safe leaf without following aliases or hard links."""

    with secure_parent(path, create=True) as (parent_fd, name):
        if parent_gid >= 0:
            os.fchown(parent_fd, -1, parent_gid)
        if parent_mode is not None:
            os.fchmod(parent_fd, parent_mode)
        try:
            existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            _validate_regular(existing, label="private state file")
        temporary = f".{name}.{secrets.token_hex(16)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _NONBLOCK
        flags |= getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(temporary, flags, mode, dir_fd=parent_fd)
        try:
            info = os.fstat(descriptor)
            _validate_regular(info, label="temporary private state file")
            if uid >= 0 or gid >= 0:
                os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            raise


def create_private_file(path: Path, payload: bytes, *, mode: int = 0o600) -> bool:
    """Atomically publish a new leaf without replacing an existing name."""

    with secure_parent(path, create=True) as (parent_fd, name):
        temporary = f".{name}.{secrets.token_hex(16)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _NONBLOCK
        flags |= getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(temporary, flags, mode, dir_fd=parent_fd)
        try:
            os.fchmod(descriptor, mode)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            return False
        finally:
            os.unlink(temporary, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return True


def unlink_private(path: Path) -> None:
    """Remove one regular single-link leaf through a stable parent descriptor."""

    with secure_parent(path) as (parent_fd, name):
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_regular(info, label="private state file")
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
