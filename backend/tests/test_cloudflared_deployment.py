from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_compose_cloudflared_contract_is_isolated_and_digest_pinned() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    app = services["lnswitchboard"]
    cloudflared = services["cloudflared"]

    image = cloudflared["image"]
    assert image == (
        "cloudflare/cloudflared:2026.7.3@"
        "sha256:e39ee8da81ad5e05d77f38d2f51c60ca51bf2a8450ac3abab50c17fdb91d91bf"
    )
    assert ":latest" not in image
    assert cloudflared["entrypoint"] == ["cloudflared"]
    assert cloudflared["user"] == "65532:${CLOUDFLARED_TOKEN_GID:-0}"
    assert "ports" not in cloudflared
    assert cloudflared.get("privileged") is not True
    assert cloudflared.get("network_mode") != "host"
    assert "cap_add" not in cloudflared

    command = cloudflared["command"]
    assert command == [
        "tunnel",
        "--autoupdate-freq",
        "24h",
        "--metrics",
        "0.0.0.0:2000",
        "run",
        "--token-file",
        "/run/lnswitchboard/tunnel.token",
    ]
    assert cloudflared["volumes"] == ["./secrets/cloudflared:/run/lnswitchboard:ro"]
    assert app["environment"]["CLOUDFLARED_CONNECTOR_ENABLED"] == "true"
    assert app["environment"]["CLOUDFLARED_TOKEN_PATH"] == (
        "/app/secrets/cloudflared/tunnel.token"
    )
    assert app["environment"]["CLOUDFLARED_METRICS_URL"] == "http://cloudflared:2000"
    assert app["environment"]["CLOUDFLARED_ORIGIN_URL"] == "http://lnswitchboard:21212"
    assert app["environment"]["CLOUDFLARED_TOKEN_GID"] == "${CLOUDFLARED_TOKEN_GID:-0}"


def test_compose_never_exposes_docker_socket_or_admin_origin_to_cloudflared() -> None:
    raw = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    cloudflared_section = raw.split("  cloudflared:\n", 1)[1]

    assert "/var/run/docker.sock" not in raw
    assert "22121" not in cloudflared_section
    assert "21212" in raw


def test_cloudflare_onboarding_requires_no_oauth_configuration() -> None:
    deployment_files = [
        ROOT / ".env.example",
        ROOT / "docker-compose.yml",
        ROOT / "backend" / "app" / "config.py",
    ]

    for path in deployment_files:
        assert "CLOUDFLARE_OAUTH" not in path.read_text(encoding="utf-8")
