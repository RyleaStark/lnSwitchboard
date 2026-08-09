from __future__ import annotations

import asyncio
import os
import re
import runpy
import socket
from pathlib import Path

import pytest
import yaml

from backend.app.main import _periodic_log_cleanup

ROOT = Path(__file__).resolve().parents[2]


def test_initializer_preserves_the_rollback_compatible_database_authority() -> None:
    initializer = (ROOT / "scripts" / "lnswitchboard-prepare-state").read_text(
        encoding="utf-8"
    )

    assert '"/public-socket"' in initializer
    assert "public-state" not in initializer
    assert "migrate_public_state" not in initializer


def test_initializer_removes_only_its_owned_stale_public_socket(tmp_path) -> None:
    root = tmp_path / "socket-root"
    root.mkdir()
    socket_path = root / "public.sock"
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(str(socket_path))
    stale.close()
    namespace = runpy.run_path(
        str(ROOT / "scripts" / "lnswitchboard-prepare-state")
    )
    globals_dict = namespace["prepare_public_socket_root"].__globals__
    globals_dict["open_directory"] = lambda _path: os.open(
        root, os.O_RDONLY | os.O_DIRECTORY
    )
    globals_dict["UID"] = os.getuid()
    globals_dict["GID"] = os.getgid()

    namespace["prepare_public_socket_root"]()

    assert list(root.iterdir()) == []


def test_initializer_rejects_a_public_socket_symlink_without_mutation(tmp_path) -> None:
    root = tmp_path / "socket-root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"sentinel")
    socket_path = root / "public.sock"
    socket_path.symlink_to(outside)
    namespace = runpy.run_path(
        str(ROOT / "scripts" / "lnswitchboard-prepare-state")
    )
    namespace["prepare_public_socket_root"].__globals__["open_directory"] = (
        lambda _path: os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    )

    with pytest.raises(SystemExit, match="refused unsafe"):
        namespace["prepare_public_socket_root"]()

    assert socket_path.is_symlink()
    assert outside.read_bytes() == b"sentinel"


def test_idle_service_runs_periodic_retention_cleanup() -> None:
    async def exercise() -> None:
        cleaned = asyncio.Event()

        class Storage:
            async def cleanup(self) -> None:
                cleaned.set()

        task = asyncio.create_task(_periodic_log_cleanup(Storage(), interval_seconds=0.01))
        try:
            await asyncio.wait_for(cleaned.wait(), timeout=0.2)
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    asyncio.run(exercise())


def _workflow() -> dict:
    return yaml.load(
        (ROOT / ".github" / "workflows" / "publish-rc.yml").read_text(
            encoding="utf-8"
        ),
        Loader=yaml.BaseLoader,
    )


def test_rc_publication_is_manual_only_and_serialized_by_version() -> None:
    workflow = _workflow()

    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["concurrency"]["group"] == (
        "publish-rc-${{ inputs.version }}"
    )
    assert workflow["concurrency"]["cancel-in-progress"] == "false"


def test_rc_publication_requires_successful_exact_sha_ci_before_write_access() -> None:
    workflow = _workflow()
    gate = workflow["jobs"]["verify-ci"]
    publish = workflow["jobs"]["publish"]
    gate_script = "\n".join(
        step.get("run", "") for step in gate["steps"]
    )

    assert gate["permissions"] == {"actions": "read", "contents": "read"}
    assert "packages" not in gate["permissions"]
    assert "head_sha=$GITHUB_SHA" in gate_script
    assert 'conclusion == "success"' in gate_script
    assert "refs/heads/main" in gate_script
    assert publish["needs"] == "verify-ci"
    assert publish["permissions"]["packages"] == "write"


def test_rc_registry_vacancy_probe_authenticates_with_the_fetched_token() -> None:
    workflow = _workflow()
    publish_script = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["publish"]["steps"]
    )

    assert re.search(
        r'-H "Authorization: Bearer \$\{?TOKEN\}?"', publish_script
    )


def test_primary_application_container_is_least_privilege() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    app = compose["services"]["lnswitchboard"]
    public = compose["services"]["lnswitchboard-public"]
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert re.search(r"(?m)^USER 1000:1000$", dockerfile)
    assert app["user"] == "1000:1000"
    assert app["read_only"] is True
    assert app["cap_drop"] == ["ALL"]
    assert app["security_opt"] == ["no-new-privileges:true"]
    assert "/tmp:size=64m,mode=1777" in app["tmpfs"]
    assert app["depends_on"]["permissions-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert app.get("privileged") is not True
    assert app["environment"]["LISTENER_MODE"] == "admin"
    assert app["environment"]["DATA_STORE_PATH"] == "/app/secrets/lnswitchboard.db"
    assert app["environment"]["PUBLIC_BACKEND_SOCKET_PATH"] == (
        "/run/lnswitchboard-public/public.sock"
    )
    assert app["ports"] == [
        "${LNSWITCHBOARD_BIND_ADDRESS:-127.0.0.1}:22121:22121"
    ]
    assert app["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-c",
        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:22121/api/health', timeout=2).read()",
    ]

    assert public["user"] == "1000:1000"
    assert public["read_only"] is True
    assert public["cap_drop"] == ["ALL"]
    assert public["security_opt"] == ["no-new-privileges:true"]
    assert public["environment"]["LISTENER_MODE"] == "public"
    assert set(public["environment"]) == {
        "LISTENER_MODE",
        "PUBLIC_BACKEND_SOCKET_PATH",
        "PUBLIC_SERVICE_PORT",
    }
    assert public["depends_on"]["permissions-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert public["depends_on"]["lnswitchboard"]["condition"] == "service_healthy"
    assert "./secrets:/app/secrets:rw" in app["volumes"]
    assert "public-backend:/run/lnswitchboard-public:rw" in app["volumes"]
    assert public["volumes"] == [
        "public-backend:/run/lnswitchboard-public:ro"
    ]
    assert all("/app/secrets" not in volume for volume in public["volumes"])
    assert all("/lnd" not in volume for volume in public["volumes"])
    assert set(public["networks"]) == {"cloudflare-egress"}
    assert public["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-c",
        "import socket; socket.create_connection(('127.0.0.1', 21212), 2).close()",
    ]

    initializer = compose["services"]["permissions-init"]
    assert initializer["network_mode"] == "none"
    assert initializer["read_only"] is True
    assert initializer["cap_drop"] == ["ALL"]
    assert set(initializer["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER"}
    assert initializer["security_opt"] == ["no-new-privileges:true"]
    assert initializer["image"] == app["image"]
    assert initializer["entrypoint"] == [
        "/usr/local/bin/lnswitchboard-prepare-state"
    ]
    assert "public-backend:/public-socket" in initializer["volumes"]


def test_compose_application_image_matches_version_file() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    expected = f"ghcr.io/ryleastark/lnswitchboard:${{LNSWITCHBOARD_VERSION:-{version}}}"
    for service in ("permissions-init", "lnswitchboard", "lnswitchboard-public"):
        assert compose["services"][service]["image"] == expected
