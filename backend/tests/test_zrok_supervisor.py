from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUPERVISOR = ROOT / "deploy/zrok/supervisor.sh"


def _wait_for(predicate, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("condition did not become true")


def _read_status(path: Path) -> dict[str, object] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


@pytest.fixture
def runtime(tmp_path: Path):
    control = tmp_path / "control"
    status = tmp_path / "status"
    home = tmp_path / "home"
    bin_dir = tmp_path / "bin"
    for directory in (control, status, home, bin_dir):
        directory.mkdir()
    log = tmp_path / "commands.log"
    mock = bin_dir / "zrok2"
    mock.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$ZROK_TEST_LOG"
case "${1:-}" in
  status) [ -f "$HOME/enabled" ] && printf 'EnvZId <<SET>>\\n' || exit 1 ;;
  enable) touch "$HOME/enabled" ;;
  disable) [ -f "$ZROK_TEST_FAIL_DISABLE" ] && exit 1; rm -f "$HOME/enabled" ;;
  create) touch "$HOME/name" ;;
  list)
    if [ -f "$ZROK_TEST_LIST_ERROR" ]; then exit 1; fi
    if [ "${2:-}" = shares ]; then printf '{"shares":[]}\\n'
    elif [ -f "$HOME/name" ]; then printf '[{"namespaceToken":"public","name":"pay"}]\\n'
    else printf '[]\\n'; fi ;;
  delete)
    [ -f "$ZROK_TEST_FAIL_DELETE" ] && exit 1
    [ "${2:-}" = name ] && rm -f "$HOME/name" ;;
  share)
    printf '{"msg":"boot","token":"do-not-persist","frontend_endpoints":["Pay.Example"]}\\n'
    if [ -f "$ZROK_TEST_SHARE_DIES" ]; then sleep 2; exit 7; fi
    trap 'exit 0' TERM INT
    while true; do sleep 1; done ;;
esac
""",
        encoding="utf-8",
    )
    mock.chmod(0o755)
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bin_dir}:{env['PATH']}",
            "HOME": str(home),
            "ZROK_CONTROL_DIR": str(control),
            "ZROK_STATUS_DIR": str(status),
            "ZROK_TARGET": "http://test-public:21212",
            "ZROK_TEST_LOG": str(log),
            "ZROK_TEST_FAIL_DISABLE": str(tmp_path / "fail-disable"),
            "ZROK_TEST_FAIL_DELETE": str(tmp_path / "fail-delete"),
            "ZROK_TEST_LIST_ERROR": str(tmp_path / "list-error"),
            "ZROK_TEST_SHARE_DIES": str(tmp_path / "share-dies"),
        }
    )
    return control, status, home, log, env


def _configure(control: Path, operation_id: str = "a" * 32) -> None:
    (control / "configure.json").write_text(
        json.dumps(
            {
                "operation_id": operation_id,
                "mode": "cloud",
                "account_token": "sensitive-enrollment-token",
                "api_endpoint": "https://api-v2.zrok.io",
                "namespace": "public",
                "name": "pay",
            }
        ),
        encoding="utf-8",
    )


def test_supervisor_consumes_token_publishes_sanitized_status_and_exits_on_term(runtime) -> None:
    control, status, _home, _log, env = runtime
    _configure(control)
    process = subprocess.Popen([str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_for(
            lambda: (
                (_read_status(status / "status.json") or {}).get("state")
                == "connected"
                and (_home / ".lnswitchboard-active.json").exists()
            )
        )
        payload = (status / "status.json").read_text(encoding="utf-8")
        assert '"state":"connected"' in payload
        assert "sensitive-enrollment-token" not in payload
        assert "do-not-persist" not in payload
        assert '"https://pay.example"' in payload
        assert not (control / "configure.json").exists()
        active = (_home / ".lnswitchboard-active.json").read_text(encoding="utf-8")
        assert "do-not-persist" in active
        assert "sensitive-enrollment-token" not in active
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()


def test_supervisor_exits_nonzero_when_share_child_dies(runtime) -> None:
    control, status, _home, _log, env = runtime
    Path(env["ZROK_TEST_SHARE_DIES"]).touch()
    _configure(control)
    process = subprocess.Popen([str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert process.wait(timeout=8) != 0
    assert json.loads((status / "status.json").read_text(encoding="utf-8"))["state"] == "error"
    assert (_home / ".lnswitchboard-active.json").exists()


def test_disconnect_failure_retains_cleanup_authority(runtime) -> None:
    control, status, home, _log, env = runtime
    home.joinpath("enabled").touch()
    home.joinpath("name").touch()
    home.joinpath(".lnswitchboard-active.json").write_text(
        '{"phase":"active","namespace":"public","name":"pay","share_token":"share-token","operation_id":"recovery"}',
        encoding="utf-8",
    )
    Path(env["ZROK_TEST_FAIL_DELETE"]).touch()
    process = subprocess.Popen([str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        control.joinpath("disconnect").write_text("b" * 32, encoding="ascii")
        _wait_for(
            lambda: (_read_status(status / "status.json") or {}).get("state")
            == "error"
        )
        assert json.loads((status / "status.json").read_text(encoding="utf-8"))["state"] == "error"
        assert home.joinpath(".lnswitchboard-active.json").exists()
        assert home.joinpath("enabled").exists()
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)
