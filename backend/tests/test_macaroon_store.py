from __future__ import annotations

import asyncio

import pytest

from backend.app.macaroon_store import MacaroonStore


def test_mounted_binary_macaroon_is_hex_encoded(tmp_path):
    mounted = tmp_path / "invoice.macaroon"
    mounted.write_bytes(b"\x00\x01binary")
    store = MacaroonStore(tmp_path / "manual.hex", mounted)

    async def _exercise():
        return await store.get(), await store.status()

    macaroon, status = asyncio.run(_exercise())

    assert macaroon == b"\x00\x01binary".hex()
    assert status.configured is True
    assert status.source == "file"
    assert status.manual_entry_allowed is False
    assert status.path == str(mounted)


def test_mounted_text_macaroon_is_sanitized(tmp_path):
    mounted = tmp_path / "invoice.macaroon"
    mounted.write_text(" AA bb 00\n", encoding="utf-8")
    store = MacaroonStore(tmp_path / "manual.hex", mounted)

    assert asyncio.run(store.get()) == "aabb00"


def test_mounted_macaroon_disables_manual_updates(tmp_path):
    mounted = tmp_path / "invoice.macaroon"
    mounted.write_bytes(b"\x01")
    store = MacaroonStore(tmp_path / "manual.hex", mounted)

    async def _exercise():
        await store.set("00")

    with pytest.raises(PermissionError):
        asyncio.run(_exercise())
