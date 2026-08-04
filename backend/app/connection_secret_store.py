"""Encrypted-at-rest storage for provider authorization material."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from cryptography.fernet import Fernet, InvalidToken

from .sqlite_utils import sqlite_connection


class ConnectionSecretStore:
    """Keep provider credentials separate from serializable connection metadata."""

    def __init__(self, database_path: Path, key_path: Path) -> None:
        self.database_path = Path(database_path)
        self.key_path = Path(key_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._fernet = Fernet(self._load_or_create_key())
        self._init_schema()

    def _load_or_create_key(self) -> bytes:
        try:
            descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            os.chmod(self.key_path, 0o600)
        else:
            try:
                os.write(descriptor, Fernet.generate_key())
            finally:
                os.close(descriptor)
        key = self.key_path.read_bytes().strip()
        Fernet(key)  # Validate before accepting it for credential encryption.
        return key

    def _init_schema(self) -> None:
        with sqlite_connection(self.database_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS connection_secrets (
                    owner_id TEXT PRIMARY KEY,
                    ciphertext BLOB NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def set(self, owner_id: str, payload: Mapping[str, Any]) -> None:
        if not isinstance(payload, Mapping):
            raise ValueError("secret payload must be a JSON object")
        owner_id = owner_id.strip()
        if not owner_id:
            raise ValueError("owner_id is required")
        encoded = json.dumps(dict(payload), separators=(",", ":"), sort_keys=True).encode("utf-8")
        ciphertext = self._fernet.encrypt(encoded)
        with sqlite_connection(self.database_path) as connection:
            connection.execute(
                """
                INSERT INTO connection_secrets (owner_id, ciphertext, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(owner_id) DO UPDATE SET
                    ciphertext = excluded.ciphertext,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (owner_id, ciphertext),
            )

    def get(self, owner_id: str) -> dict[str, Any] | None:
        with sqlite_connection(self.database_path) as connection:
            row = connection.execute(
                "SELECT ciphertext FROM connection_secrets WHERE owner_id = ?", (owner_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            decoded = self._fernet.decrypt(bytes(row["ciphertext"]))
        except InvalidToken as exc:
            raise ValueError("stored connection credential cannot be decrypted") from exc
        payload = json.loads(decoded)
        if not isinstance(payload, dict):
            raise ValueError("stored connection credential must be an object")
        return payload

    def delete(self, owner_id: str) -> bool:
        with sqlite_connection(self.database_path) as connection:
            cursor = connection.execute("DELETE FROM connection_secrets WHERE owner_id = ?", (owner_id,))
            return cursor.rowcount > 0
