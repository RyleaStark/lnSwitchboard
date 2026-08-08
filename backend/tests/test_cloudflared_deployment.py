from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_compose_mesh_sidecar_contract_is_isolated_and_digest_pinned() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    app = services["lnswitchboard"]
    mesh = services["cloudflare-mesh"]

    image = mesh["image"]
    assert image == (
        "cloudflare/mesh:2026.7.0@"
        "sha256:18fad6d500e8ca48b7e4d5ae1905d65e8a50c1f5f5e21eba020d54d5cbf82571"
    )
    assert ":latest" not in image
    assert mesh["entrypoint"] == ["sh", "/opt/lnswitchboard/mesh-entrypoint.sh"]
    assert "ports" not in mesh
    assert mesh.get("privileged") is not True
    assert mesh.get("network_mode") != "host"
    # The mesh node requires TUN + forwarding by design (Cloudflare docs);
    # exactly these capabilities and nothing more.
    assert mesh["cap_drop"] == ["ALL"]
    assert mesh["cap_add"] == ["NET_ADMIN", "NET_RAW"]
    assert mesh["devices"] == ["/dev/net/tun:/dev/net/tun"]
    assert mesh["sysctls"] == {
        "net.ipv4.ip_forward": "1",
        "net.ipv6.conf.all.forwarding": "1",
        "net.ipv6.conf.default.forwarding": "1",
    }

    assert mesh["environment"]["MESH_NODE_TOKEN_FILE"] == "/run/lnswitchboard/node.env"
    assert "./secrets/cloudflare-mesh:/run/lnswitchboard:ro" in mesh["volumes"]
    assert app["environment"]["CLOUDFLARED_CONNECTOR_ENABLED"] == "true"
    assert app["environment"]["CLOUDFLARED_TOKEN_PATH"] == (
        "/app/secrets/cloudflare-mesh/node.env"
    )
    assert app["environment"]["CLOUDFLARED_ORIGIN_URL"] == "http://lnswitchboard:21212"
    assert app["environment"]["CLOUDFLARED_TOKEN_GID"] == "${CLOUDFLARED_TOKEN_GID:-0}"
    assert app["networks"]["default"]["aliases"] == ["lns.internal"]


def test_compose_never_exposes_docker_socket_or_admin_origin_to_mesh() -> None:
    raw = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    mesh_section = raw.split("  cloudflare-mesh:\n", 1)[1]

    assert "/var/run/docker.sock" not in raw
    assert "22121" not in mesh_section
    assert "21212" in raw


def test_cloudflare_onboarding_uses_oauth_configuration() -> None:
    """Cloudflare onboarding is OAuth-only; the API-token path is retired."""
    config = (ROOT / "backend" / "app" / "config.py").read_text(encoding="utf-8")

    assert "cloudflare_oauth_client_id" in config
    assert "cloudflare_oauth_authorize_url" in config
    assert "cloudflare_oauth_token_url" in config


def test_mesh_entrypoint_stops_connector_and_clears_stale_identity() -> None:
    script = (ROOT / "scripts" / "mesh-entrypoint.sh").read_text(encoding="utf-8")

    assert '/entrypoint "$@" &' in script
    assert "MESH_NODE_ID" in script
    assert 'STATE_DIR="/var/lib/cloudflare-warp"' in script
    assert 'CURRENT_TOKEN="$(read_token_field MESH_NODE_TOKEN)"' in script
    assert 'CURRENT_NODE_ID="$(read_token_field MESH_NODE_ID)"' in script
    assert 'if [ "$CURRENT_NODE_ID" != "$NODE_ID" ] ||' in script
    assert "clear_mesh_state" in script
    assert 'rm -rf -- "$entry"' in script
    assert 'kill -TERM "$CHILD_PID"' in script
    assert 'exec /entrypoint "$@"' not in script


def test_mesh_entrypoint_replaces_persisted_identity_on_new_node(
    tmp_path: Path,
) -> None:
    source = (ROOT / "scripts" / "mesh-entrypoint.sh").read_text(
        encoding="utf-8"
    )
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    token_file = tmp_path / "node.env"
    fake_entrypoint = tmp_path / "entrypoint"
    wrapper = tmp_path / "mesh-entrypoint.sh"
    started = tmp_path / "started"
    stopped = tmp_path / "stopped"

    fake_entrypoint.write_text(
        "#!/bin/sh\n"
        "trap 'touch \"$STOP_FILE\"; exit 0' TERM INT HUP\n"
        "touch \"$START_FILE\"\n"
        "while :; do sleep 1; done\n",
        encoding="utf-8",
    )
    fake_entrypoint.chmod(0o755)

    state_path = str(state_dir)
    rewritten = source.replace(
        'STATE_DIR="/var/lib/cloudflare-warp"', f'STATE_DIR="{state_path}"'
    ).replace(
        '[ "$STATE_DIR" = "/var/lib/cloudflare-warp" ]',
        f'[ "$STATE_DIR" = "{state_path}" ]',
    )
    rewritten = rewritten.replace('/entrypoint "$@" &', '"$FAKE_ENTRYPOINT" "$@" &')
    wrapper.write_text(rewritten, encoding="utf-8")
    wrapper.chmod(0o755)

    (state_dir / ".lnswitchboard-node-id").write_text("old-node\n")
    (state_dir / "persisted-registration").write_text("stale\n")
    token_file.write_text("MESH_NODE_ID=node-one\nMESH_NODE_TOKEN=token-one\n")

    environment = {
        **os.environ,
        "MESH_NODE_TOKEN_FILE": str(token_file),
        "FAKE_ENTRYPOINT": str(fake_entrypoint),
        "START_FILE": str(started),
        "STOP_FILE": str(stopped),
    }

    process = subprocess.Popen(
        ["sh", str(wrapper)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 5
    identity = state_dir / ".lnswitchboard-node-id"
    while time.monotonic() < deadline:
        if (
            started.exists()
            and identity.exists()
            and identity.read_text().strip() == "node-one"
        ):
            break
        time.sleep(0.05)
    else:
        process.kill()
        raise AssertionError("mesh wrapper did not start the first identity")
    assert not (state_dir / "persisted-registration").exists()

    replacement = tmp_path / "node.env.next"
    replacement.write_text("MESH_NODE_ID=node-two\nMESH_NODE_TOKEN=token-two\n")
    replacement.replace(token_file)
    _stdout, stderr = process.communicate(timeout=8)
    assert process.returncode == 1
    assert "withdrawn" in stderr
    assert list(state_dir.iterdir()) == []
    assert stopped.exists()

    started.unlink()
    stopped.unlink()
    process = subprocess.Popen(
        ["sh", str(wrapper)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if (
            started.exists()
            and identity.exists()
            and identity.read_text().strip() == "node-two"
        ):
            break
        time.sleep(0.05)
    else:
        process.kill()
        raise AssertionError("mesh wrapper did not enroll the replacement identity")

    process.send_signal(signal.SIGTERM)
    process.communicate(timeout=5)
    assert process.returncode == 143
    assert identity.read_text().strip() == "node-two"
