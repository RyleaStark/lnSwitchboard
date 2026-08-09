"""Filesystem-backed Nostr zap receipt signer store."""

from __future__ import annotations

import asyncio
import os
import secrets
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
            if self._path.is_symlink():
                raise OSError("Nostr signer path must not be a symbolic link")
            os.chmod(self._path, 0o600)
            content = self._path.read_text(encoding="utf-8")
        return normalize_private_key_hex(content.strip())

    async def get_public_key(self) -> Optional[str]:
        current = await self.status()
        return current.pubkey if current.configured else None

    async def set_private_key(self, private_key_hex: str) -> NostrSignerStatus:
        normalized = normalize_private_key_hex(private_key_hex)
        async with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if self._path.is_symlink():
                raise OSError("Nostr signer path must not be a symbolic link")
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
                    handle.write(f"{normalized}\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self._path)
                os.chmod(self._path, 0o600)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                temporary.unlink(missing_ok=True)
        return await self.status()

    async def generate(self) -> NostrSignerStatus:
        return await self.set_private_key(generate_private_key_hex())
