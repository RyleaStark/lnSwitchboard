"""Macaroon storage management."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .secure_files import atomic_write_private, read_private_file


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
        try:
            content = read_private_file(self._path, chmod=True).decode("utf-8").strip()
            if content:
                # Validate hex data on load.
                bytes.fromhex(content)
                self._macaroon = content
        except (OSError, UnicodeDecodeError, ValueError):
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
            return self._coerce_file_bytes(read_private_file(self._source_path))
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
            atomic_write_private(self._path, sanitized.encode("utf-8"))
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
