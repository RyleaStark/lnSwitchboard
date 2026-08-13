from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ZROK_IMAGE = (
    "openziti/zrok2:2.0.4@"
    "sha256:310ab634172ce03dd23ff1ee8515195e1a564197dbc4e6cdfd57dad2fb822400"
)


def test_zrok_runtime_is_isolated_digest_pinned_and_public_only() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    zrok = services["zrok"]
    admin = services["lnswitchboard"]
    public = services["lnswitchboard-public"]

    assert zrok["image"] == ZROK_IMAGE
    assert zrok["user"] == "1000:1000"
    assert zrok["read_only"] is True
    assert zrok["cap_drop"] == ["ALL"]
    assert zrok["security_opt"] == ["no-new-privileges:true"]
    assert zrok["networks"] == ["zrok-public"]
    assert "zrok-public" not in admin.get("networks", {})
    assert public["networks"]["zrok-public"]["aliases"] == ["public"]
    assert zrok["environment"]["DEP_ENV"] == "DOCKER"
    assert "zrok-state:/var/lib/zrok" in zrok["volumes"]
    assert "zrok-control:/run/lnswitchboard" in zrok["volumes"]
    assert "zrok-control:/app/secrets/zrok" in admin["volumes"]

    raw = str(zrok)
    for forbidden in ("22121", "lnswitchboard.db", "connection-secrets.key", "/lnd/", "cloudflare", "tailscale"):
        assert forbidden not in raw


def test_zrok_supervisor_has_fixed_target_and_never_logs_subordinate_access() -> None:
    supervisor = (ROOT / "deploy/zrok/supervisor.sh").read_text(encoding="utf-8")
    assert "DEP_ENV" in supervisor
    assert ":22121" not in supervisor
    assert "--backend-mode proxy --open --subordinate --force-local" in supervisor
    assert "--headless --subordinate" not in supervisor
    assert '2>/dev/null' in supervisor
    assert 'account_token' in supervisor
    assert 'operation_id' in supervisor
    assert 'share_token' in supervisor
    assert 'chmod 600 "$tmp"' in supervisor
    assert 'rm -f "$cfg"' in supervisor
    assert '"https://" + ascii_downcase' in supervisor
