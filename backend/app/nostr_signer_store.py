"""Filesystem-backed Nostr zap receipt signer store."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .nostr_crypto import (
    NostrCryptoError,
    generate_private_key_hex,
    normalize_private_key_hex,
    public_key_from_private_hex,
)


@dataclass(frozen=True)
class NostrSignerStatus:
    configured: bool
    pubkey: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None


class NostrSignerStore:
    """Stores the local Nostr private key used for NIP-57 zap receipts."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def status(self) -> NostrSignerStatus:
        try:
            private_key = await self.get_private_key()
        except FileNotFoundError:
            return NostrSignerStatus(configured=False, path=str(self._path))
        except (OSError, NostrCryptoError, ValueError) as exc:
            return NostrSignerStatus(configured=False, path=str(self._path), error=str(exc))
        return NostrSignerStatus(
            configured=True,
            pubkey=public_key_from_private_hex(private_key),
            path=str(self._path),
        )

    async def get_private_key(self) -> str:
        async with self._lock:
            content = self._path.read_text(encoding="utf-8")
        return normalize_private_key_hex(content.strip())

    async def get_public_key(self) -> Optional[str]:
        current = await self.status()
        return current.pubkey if current.configured else None

    async def set_private_key(self, private_key_hex: str) -> NostrSignerStatus:
        normalized = normalize_private_key_hex(private_key_hex)
        async with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(f"{normalized}\n", encoding="utf-8")
            try:
                self._path.chmod(0o600)
            except OSError:
                pass
        return await self.status()

    async def generate(self) -> NostrSignerStatus:
        return await self.set_private_key(generate_private_key_hex())
