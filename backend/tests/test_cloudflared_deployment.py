from __future__ import annotations

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
