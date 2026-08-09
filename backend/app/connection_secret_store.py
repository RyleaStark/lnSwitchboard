"""Encrypted-at-rest storage for provider authorization material."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from cryptography.fernet import Fernet, InvalidToken

from .secure_files import create_private_file, read_private_file
from .sqlite_utils import sqlite_connection


class ConnectionSecretStore:
    """Keep provider credentials separate from serializable connection metadata."""

    def __init__(self, database_path: Path, key_path: Path) -> None:
        self.database_path = Path(database_path)
        self.key_path = Path(key_path)
        self._fernet = Fernet(self._load_or_create_key())
        self._init_schema()

    def _load_or_create_key(self) -> bytes:
        generated = Fernet.generate_key()
        key = (
            generated
            if create_private_file(self.key_path, generated, mode=0o600)
            else read_private_file(self.key_path, chmod=True).strip()
        )
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

    def list_owner_ids(self) -> list[str]:
        with sqlite_connection(self.database_path) as connection:
            rows = connection.execute(
                "SELECT owner_id FROM connection_secrets ORDER BY owner_id"
            ).fetchall()
        return [str(row["owner_id"]) for row in rows]

    def delete(self, owner_id: str) -> bool:
        with sqlite_connection(self.database_path) as connection:
            cursor = connection.execute("DELETE FROM connection_secrets WHERE owner_id = ?", (owner_id,))
            return cursor.rowcount > 0
