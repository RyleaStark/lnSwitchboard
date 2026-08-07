from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TAILSCALE_IMAGE = (
    "tailscale/tailscale:v1.98.10@"
    "sha256:cdf5612ded5be1344f1a704b8c5e53496db97376bb533e5e15f141e48bf60cc0"
)


def test_compose_tailscale_runtime_is_isolated_userspace_and_digest_pinned() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    app = services["lnswitchboard"]
    tailscale = services["tailscale"]

    assert tailscale["image"] == TAILSCALE_IMAGE
    assert ":latest" not in tailscale["image"]
    assert ":stable" not in tailscale["image"]
    assert tailscale["network_mode"] == "service:lnswitchboard"
    assert tailscale["entrypoint"] == [
        "/usr/local/bin/lnswitchboard-tailscale-supervisor"
    ]
    assert tailscale["read_only"] is True
    assert tailscale["restart"] == "unless-stopped"
    assert tailscale["stop_grace_period"] == "30s"
    assert tailscale["depends_on"]["lnswitchboard"]["condition"] == "service_healthy"
    assert tailscale["tmpfs"] == ["/var/run/tailscale:mode=0750"]
    assert tailscale["healthcheck"]["test"] == [
        "CMD-SHELL",
        "test -S /var/run/tailscale/tailscaled.sock",
    ]
    assert tailscale["cap_drop"] == ["ALL"]
    assert tailscale["security_opt"] == ["no-new-privileges:true"]
    assert "ports" not in tailscale
    assert tailscale.get("privileged") is not True
    assert "cap_add" not in tailscale
    assert "devices" not in tailscale

    volumes = tailscale["volumes"]
    assert "tailscale-state:/var/lib/tailscale" in volumes
    assert "tailscale-control:/run/lnswitchboard" in volumes
    assert (
        "./deploy/tailscale/supervisor.sh:"
        "/usr/local/bin/lnswitchboard-tailscale-supervisor:ro"
    ) in volumes
    assert compose["volumes"]["tailscale-state"] is None
    assert compose["volumes"]["tailscale-control"] is None
    assert "tailscale-control:/app/secrets/tailscale" in app["volumes"]

    environment = tailscale["environment"]
    assert environment["TS_STATE_DIR"] == "/var/lib/tailscale"
    assert environment["TS_SOCKET"] == "/var/run/tailscale/tailscaled.sock"
    assert environment["TS_USERSPACE"] == "true"
    assert environment["TS_CONTROL_DIR"] == "/run/lnswitchboard/control"
    assert environment["TS_STATUS_DIR"] == "/run/lnswitchboard/status"
    assert environment["TS_LOGIN_RETENTION_SECONDS"] == "300"
    assert not any(
        "AUTH" in key or "CLIENT_SECRET" in key or "OAUTH" in key for key in environment
    )

    app_environment = app["environment"]
    assert app_environment["TAILSCALE_CONNECTOR_ENABLED"] == "true"
    assert app_environment["TAILSCALE_CONTROL_DIR"] == (
        "/app/secrets/tailscale/control"
    )
    assert app_environment["TAILSCALE_STATUS_DIR"] == ("/app/secrets/tailscale/status")


def test_tailscale_runtime_never_exposes_host_or_admin_boundaries() -> None:
    raw = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    tailscale_section = raw.split("  tailscale:\n", 1)[1].split("\nvolumes:", 1)[0]

    assert "/var/run/docker.sock" not in raw
    assert "/dev/net/tun" not in tailscale_section
    assert "NET_ADMIN" not in tailscale_section
    assert "network_mode: host" not in tailscale_section
    assert "22121" not in tailscale_section
    assert "127.0.0.1:21212" in (ROOT / "deploy/tailscale/supervisor.sh").read_text(
        encoding="utf-8"
    )


def test_readme_documents_tailscale_runtime_security_boundary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "tailscale/tailscale:v1.98.10" in readme
    assert "http://127.0.0.1:21212" in readme
    assert "never exposes the administration listener on `22121`" in readme
    assert "five-minute fallback" in readme
    assert "no OAuth client, API token, or reusable auth key" in readme
    assert "MagicDNS" in readme
    assert "`funnel` node attribute" in readme
