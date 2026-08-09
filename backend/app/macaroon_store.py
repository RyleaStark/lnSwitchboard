"""Macaroon storage management."""

from __future__ import annotations

import asyncio
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class MacaroonNotConfiguredError(RuntimeError):
    """Raised when a macaroon is required but not yet configured."""


@dataclass(frozen=True)
class MacaroonStatus:
    configured: bool
    source: str
    manual_entry_allowed: bool
    path: str | None = None
    error: str | None = None


class MacaroonStore:
    """Loads a mounted LND macaroon or stores a user-provided macaroon."""

    def __init__(self, path: Path, source_path: Path | None = None) -> None:
        self._path = path
        self._source_path = source_path
        self._lock: Optional[asyncio.Lock] = None
        self._macaroon: Optional[str] = None
        if self.manual_entry_allowed:
            self._load_from_disk()

    @property
    def manual_entry_allowed(self) -> bool:
        return self._source_path is None

    @property
    def source(self) -> str:
        return "manual" if self.manual_entry_allowed else "file"

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def _load_from_disk(self) -> None:
        if not self._path.exists():
            return
        try:
            if self._path.is_symlink():
                raise ValueError("Manual macaroon path must not be a symbolic link")
            os.chmod(self._path, 0o600)
            content = self._path.read_text(encoding="utf-8").strip()
            if content:
                # Validate hex data on load.
                bytes.fromhex(content)
                self._macaroon = content
        except (OSError, ValueError):
            # Ignore invalid or unreadable persisted data.
            self._macaroon = None

    @staticmethod
    def _sanitize(value: str) -> str:
        candidate = "".join(value.split()).lower()
        if not candidate:
            raise ValueError("Macaroon cannot be empty")
        if len(candidate) % 2 != 0:
            raise ValueError("Macaroon hex length must be even")
        try:
            bytes.fromhex(candidate)
        except ValueError as exc:
            raise ValueError("Macaroon must be valid hexadecimal") from exc
        return candidate

    @classmethod
    def _coerce_file_bytes(cls, data: bytes) -> str:
        if not data or not data.strip():
            raise ValueError("Macaroon file cannot be empty")

        stripped = b"".join(data.split())
        if stripped:
            try:
                return cls._sanitize(stripped.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                pass

        return data.hex()

    def _load_from_source_path(self) -> str:
        if self._source_path is None:
            raise MacaroonNotConfiguredError("No mounted macaroon path is configured")
        try:
            return self._coerce_file_bytes(self._source_path.read_bytes())
        except FileNotFoundError as exc:
            raise MacaroonNotConfiguredError("Mounted macaroon file was not found") from exc
        except PermissionError as exc:
            raise MacaroonNotConfiguredError("Mounted macaroon file is not readable") from exc
        except OSError as exc:
            raise MacaroonNotConfiguredError("Unable to read mounted macaroon file") from exc
        except ValueError as exc:
            raise MacaroonNotConfiguredError(str(exc)) from exc

    async def set(self, macaroon_hex: str) -> None:
        if not self.manual_entry_allowed:
            raise PermissionError("Manual macaroon updates are disabled when LND_MACAROON_PATH is configured")
        sanitized = self._sanitize(macaroon_hex)
        async with self._get_lock():
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if self._path.is_symlink():
                raise OSError("Manual macaroon path must not be a symbolic link")
            temporary = self._path.parent / (
                f".{self._path.name}.{secrets.token_hex(8)}.tmp"
            )
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600)
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    descriptor = -1
                    handle.write(sanitized)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self._path)
                os.chmod(self._path, 0o600)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                temporary.unlink(missing_ok=True)
            self._macaroon = sanitized

    async def get(self) -> str:
        if not self.manual_entry_allowed:
            return self._load_from_source_path()
        async with self._get_lock():
            if self._macaroon is None:
                raise MacaroonNotConfiguredError("Macaroon has not been configured yet")
            return self._macaroon

    async def is_configured(self) -> bool:
        if not self.manual_entry_allowed:
            try:
                self._load_from_source_path()
            except MacaroonNotConfiguredError:
                return False
            return True
        async with self._get_lock():
            return self._macaroon is not None

    async def status(self) -> MacaroonStatus:
        path = self._path if self.manual_entry_allowed else self._source_path
        if not self.manual_entry_allowed:
            try:
                self._load_from_source_path()
            except MacaroonNotConfiguredError as exc:
                return MacaroonStatus(
                    configured=False,
                    source=self.source,
                    manual_entry_allowed=False,
                    path=str(path) if path else None,
                    error=str(exc),
                )
            return MacaroonStatus(
                configured=True,
                source=self.source,
                manual_entry_allowed=False,
                path=str(path) if path else None,
            )

        async with self._get_lock():
            return MacaroonStatus(
                configured=self._macaroon is not None,
                source=self.source,
                manual_entry_allowed=True,
                path=str(path),
            )
