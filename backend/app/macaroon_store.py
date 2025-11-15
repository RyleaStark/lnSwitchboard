"""Macaroon storage management."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional


class MacaroonNotConfiguredError(RuntimeError):
    """Raised when a macaroon is required but not yet configured."""


class MacaroonStore:
    """Stores the user-provided macaroon securely on disk and in memory."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._macaroon: Optional[str] = None
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        if not self._path.exists():
            return
        try:
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

    async def set(self, macaroon_hex: str) -> None:
        sanitized = self._sanitize(macaroon_hex)
        async with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(sanitized, encoding="utf-8")
            self._macaroon = sanitized

    async def get(self) -> str:
        async with self._lock:
            if self._macaroon is None:
                raise MacaroonNotConfiguredError("Macaroon has not been configured yet")
            return self._macaroon

    async def is_configured(self) -> bool:
        async with self._lock:
            return self._macaroon is not None
