from __future__ import annotations

import importlib.machinery
import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "lnswitchboard-prepare-state"


def _module():
    loader = importlib.machinery.SourceFileLoader("prepare_state", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    setattr(module, "UID", os.getuid())
    setattr(module, "GID", os.getgid())
    return module


def test_prepare_state_skips_separately_mounted_connector_protocol_hardlinks(
    tmp_path: Path,
) -> None:
    module = _module()
    app_secrets = tmp_path / "secrets"
    operations = app_secrets / "tailscale" / "control" / "operations"
    queue = app_secrets / "tailscale" / "control" / "queue"
    operations.mkdir(parents=True)
    queue.mkdir(parents=True)
    operation = operations / ("a" * 32 + ".json")
    operation.write_text('{"command":"enable"}\n', encoding="utf-8")
    (queue / operation.name).hardlink_to(operation)
    database = app_secrets / "lnswitchboard.db"
    database.write_bytes(b"app-state")

    descriptor = os.open(app_secrets, os.O_RDONLY | os.O_DIRECTORY)
    try:
        module.harden_tree(descriptor, excluded_root_names={"tailscale", "zrok"})
        module.validate_tree(descriptor, excluded_root_names={"tailscale", "zrok"})
    finally:
        os.close(descriptor)

    assert operation.stat().st_nlink == 2
    assert database.stat().st_nlink == 1


def test_prepare_state_still_rejects_application_owned_hardlinks(tmp_path: Path) -> None:
    module = _module()
    root = tmp_path / "secrets"
    root.mkdir()
    database = root / "lnswitchboard.db"
    database.write_bytes(b"app-state")
    (root / "unexpected-alias").hardlink_to(database)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(SystemExit, match="unsafe filesystem state"):
            module.harden_tree(descriptor, excluded_root_names={"tailscale", "zrok"})
    finally:
        os.close(descriptor)
