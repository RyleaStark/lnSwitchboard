from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from backend.app.connection_secret_store import ConnectionSecretStore
from backend.app.connection_store import ConnectionStore


def test_connection_store_tracks_provider_domains_without_credentials(tmp_path: Path) -> None:
    store = ConnectionStore(tmp_path / "connections.db")

    connection = store.upsert_connection(
        provider="cloudflare",
        external_id="tunnel-123",
        label="Cloudflare Tunnel",
        status="connected",
        account_id="account-123",
        public_metadata={"tunnel_name": "lnswitchboard"},
    )
    store.replace_domains(
        connection.id,
        [
            {
                "hostname": "alice.example.com",
                "status": "active",
                "external_id": "dns-123",
                "zone_id": "zone-123",
            },
            {
                "hostname": "nostr.example.com",
                "status": "pending",
            },
        ],
    )

    stored = store.list_connections()

    assert len(stored) == 1
    assert stored[0].provider == "cloudflare"
    assert stored[0].external_id == "tunnel-123"
    assert stored[0].public_metadata == {"tunnel_name": "lnswitchboard"}
    assert [domain.hostname for domain in stored[0].domains] == [
        "alice.example.com",
        "nostr.example.com",
    ]
    raw_db = (tmp_path / "connections.db").read_bytes()
    assert b"tunnel_name" in raw_db
    assert b"credentials" not in raw_db


def test_connection_store_rejects_invalid_provider_and_status(tmp_path: Path) -> None:
    store = ConnectionStore(tmp_path / "connections.db")

    with pytest.raises(ValueError, match="provider"):
        store.upsert_connection(
            provider="Cloudflare Tunnel!",
            external_id="tunnel-123",
            label="Cloudflare",
            status="connected",
        )

    with pytest.raises(ValueError, match="status"):
        store.upsert_connection(
            provider="cloudflare",
            external_id="tunnel-123",
            label="Cloudflare",
            status="secretly-broken",
        )


def test_connection_store_replaces_domains_and_cascades_delete(tmp_path: Path) -> None:
    store = ConnectionStore(tmp_path / "connections.db")
    connection = store.upsert_connection(
        provider="cloudflare",
        external_id="tunnel-123",
        label="Cloudflare",
        status="provisioning",
    )
    store.replace_domains(connection.id, [{"hostname": "old.example.com", "status": "pending"}])
    store.replace_domains(connection.id, [{"hostname": "new.example.com", "status": "active"}])

    assert [item.hostname for item in store.get_connection(connection.id).domains] == [
        "new.example.com"
    ]

    assert store.delete_connection(connection.id) is True
    assert store.get_connection(connection.id) is None
    assert store.delete_connection(connection.id) is False


def test_secret_store_encrypts_payload_and_uses_restricted_key_permissions(tmp_path: Path) -> None:
    database_path = tmp_path / "connections.db"
    key_path = tmp_path / "connection-secrets.key"
    store = ConnectionSecretStore(database_path, key_path)

    store.set("connection-1", {"access_token": "access-secret", "refresh_token": "refresh-secret"})

    assert store.get("connection-1") == {
        "access_token": "access-secret",
        "refresh_token": "refresh-secret",
    }
    raw_db = database_path.read_bytes()
    assert b"access-secret" not in raw_db
    assert b"refresh-secret" not in raw_db
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_secret_store_rejects_non_object_payload(tmp_path: Path) -> None:
    store = ConnectionSecretStore(tmp_path / "connections.db", tmp_path / "secrets.key")

    with pytest.raises(ValueError, match="object"):
        store.set("connection-1", json.loads('["not", "an", "object"]'))
