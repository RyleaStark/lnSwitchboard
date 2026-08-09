from __future__ import annotations

import asyncio
import os
import stat

import pytest

from backend.app.macaroon_store import MacaroonStore


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_manual_macaroon_is_written_owner_only_and_existing_mode_is_repaired(tmp_path):
    path = tmp_path / "manual.hex"
    store = MacaroonStore(path)
    asyncio.run(store.set("aabb00"))
    assert path.read_text(encoding="utf-8") == "aabb00"
    assert _mode(path) == 0o600

    os.chmod(path, 0o644)
    reloaded = MacaroonStore(path)
    assert asyncio.run(reloaded.get()) == "aabb00"
    assert _mode(path) == 0o600


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_manual_macaroon_symlink_fails_closed(tmp_path):
    target = tmp_path / "target.hex"
    target.write_text("aabb00", encoding="utf-8")
    alias = tmp_path / "manual.hex"
    alias.symlink_to(target)
    store = MacaroonStore(alias)

    with pytest.raises(OSError, match="symbolic link"):
        asyncio.run(store.set("ccdd00"))


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
