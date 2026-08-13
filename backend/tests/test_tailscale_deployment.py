from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TAILSCALE_IMAGE = (
    "tailscale/tailscale:v1.102.2@"
    "sha256:321ce041508c19079b57a28b6666c8d81ab0b08accc0a2585b3ab663d557ac24"
)


def test_compose_tailscale_runtime_is_isolated_userspace_and_digest_pinned() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    app = services["lnswitchboard"]
    tailscale = services["tailscale"]

    assert tailscale["image"] == TAILSCALE_IMAGE
    assert ":latest" not in tailscale["image"]
    assert ":stable" not in tailscale["image"]
    assert tailscale["network_mode"] == "service:lnswitchboard-public"
    assert tailscale["environment"]["TS_FUNNEL_TARGET"] == "http://127.0.0.1:21212"
    assert tailscale["entrypoint"] == [
        "/usr/local/bin/lnswitchboard-tailscale-supervisor"
    ]
    assert tailscale["read_only"] is True
    assert tailscale["user"] == "1000:1000"
    assert tailscale["restart"] == "unless-stopped"
    assert tailscale["stop_grace_period"] == "30s"
    assert tailscale["depends_on"]["lnswitchboard-public"]["condition"] == (
        "service_healthy"
    )
    assert tailscale["tmpfs"] == [
        "/var/run/tailscale:size=16m,mode=0750,uid=1000,gid=1000"
    ]
    assert tailscale["depends_on"]["permissions-init"]["condition"] == (
        "service_completed_successfully"
    )
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
    assert tailscale["environment"]["TS_USERSPACE"] == "true"
    assert tailscale["environment"]["TS_NO_LOGS_NO_SUPPORT"] == "true"
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
    assert "TS_FUNNEL_TARGET:?" in (
        ROOT / "deploy/tailscale/supervisor.sh"
    ).read_text(encoding="utf-8")
    compose = yaml.safe_load(raw)
    assert compose["services"]["tailscale"]["environment"]["TS_FUNNEL_TARGET"] == (
        "http://127.0.0.1:21212"
    )


def test_readme_documents_tailscale_runtime_security_boundary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "tailscale/tailscale:v1.102.2" in readme
    assert "http://127.0.0.1:21212" in readme
    assert "never exposes the administration listener on `22121`" in readme
    assert "five-minute fallback" in readme
    assert "no OAuth client, API token, or reusable auth key" in readme
    assert "MagicDNS" in readme
    assert "`funnel` node attribute" in readme
