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
  enable)
    touch "$HOME/enabled"
    mkdir -p "$HOME/.zrok2"
    printf '{"zrok_token":"secret","ziti_identity":"local-env","api_endpoint":"https://api-v2.zrok.io"}\\n' >"$HOME/.zrok2/environment.json" ;;
  disable) [ -f "$ZROK_TEST_FAIL_DISABLE" ] && exit 1; rm -f "$HOME/enabled" ;;
  create) touch "$HOME/name" ;;
  list)
    if [ -f "$ZROK_TEST_LIST_ERROR" ]; then exit 1; fi
    if [ "${2:-}" = shares ]; then
      if [ -f "$HOME/share-live" ]; then
        printf '{"shares":[{"shareToken":"runtime-token","envZId":"local-env","frontendEndpoints":["Pay.Example"],"shareMode":"public","backendMode":"proxy","target":"http://extended-umbrella-lnswitchboard-public:21212"},{"shareToken":"foreign-token","envZId":"foreign-env","frontendEndpoints":["Pay.Example"],"shareMode":"public","backendMode":"proxy","target":"http://extended-umbrella-lnswitchboard-public:21212"}]}\\n'
      else printf '{"shares":[]}\\n'; fi
    elif [ -f "$HOME/name" ]; then printf '[{"namespaceToken":"public","name":"pay"}]\\n'
    else printf '[]\\n'; fi ;;
  delete)
    [ -f "$ZROK_TEST_FAIL_DELETE" ] && exit 1
    if [ "${2:-}" = name ]; then rm -f "$HOME/name"; fi
    if [ "${2:-}" = share ]; then rm -f "$HOME/share-live"; fi
    exit 0 ;;
  share)
    [ -f "$ZROK_TEST_FAIL_SHARE_BOOT" ] && exit 7
    touch "$HOME/share-live"
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
            "DEP_ENV": "UMBREL_DEV",
            "ZROK_TEST_LOG": str(log),
            "ZROK_TEST_FAIL_DISABLE": str(tmp_path / "fail-disable"),
            "ZROK_TEST_FAIL_DELETE": str(tmp_path / "fail-delete"),
            "ZROK_TEST_LIST_ERROR": str(tmp_path / "list-error"),
            "ZROK_TEST_SHARE_DIES": str(tmp_path / "share-dies"),
            "ZROK_TEST_FAIL_SHARE_BOOT": str(tmp_path / "fail-share-boot"),
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


def _enable_existing(home: Path) -> None:
    home.joinpath("enabled").touch()
    home.joinpath(".zrok2").mkdir(exist_ok=True)
    home.joinpath(".zrok2/environment.json").write_text(
        '{"zrok_token":"secret","ziti_identity":"local-env","api_endpoint":"https://api-v2.zrok.io"}',
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
        assert "do-not-persist" not in active
        assert "sensitive-enrollment-token" not in active
        assert '"namespace":"public"' in active
        assert '"name":"pay"' in active
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()


def test_refresh_republishes_correlated_status_after_requester_clears_snapshot(runtime) -> None:
    control, status, _home, _log, env = runtime
    _configure(control)
    process = subprocess.Popen([str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_for(lambda: (_read_status(status / "status.json") or {}).get("state") == "connected")
        # Let start_share finish its own acknowledgement check before simulating
        # the application-side snapshot removal that triggered the live race.
        time.sleep(1.1)
        (status / "status.json").unlink()
        operation_id = "c" * 32
        (control / "refresh").write_text(operation_id, encoding="ascii")

        _wait_for(
            lambda: (
                (_read_status(status / "status.json") or {}).get("operation_id") == operation_id
            )
        )
        refreshed = _read_status(status / "status.json")
        assert refreshed is not None
        assert refreshed["state"] == "refresh_complete"
        assert refreshed["frontend_endpoints"] == ["https://pay.example"]
        assert refreshed["namespace"] == "public"
        assert refreshed["name"] == "pay"
        assert process.poll() is None
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)


def test_recovery_migrates_legacy_active_state_without_persisting_share_token(runtime) -> None:
    _control, status, home, _log, env = runtime
    _enable_existing(home)
    home.joinpath("name").touch()
    home.joinpath(".lnswitchboard-active.json").write_text(
        '{"phase":"active","namespace":"public","name":"pay","share_token":"legacy-secret","operation_id":"recovery"}',
        encoding="utf-8",
    )
    process = subprocess.Popen([str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_for(lambda: (_read_status(status / "status.json") or {}).get("state") == "connected")
        active = home.joinpath(".lnswitchboard-active.json").read_text(encoding="utf-8")
        assert "legacy-secret" not in active
        assert "share_token" not in active
        assert '\"frontend_endpoints\":[\"https://pay.example\"]' in active
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)


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
    _enable_existing(home)
    home.joinpath("name").touch()
    home.joinpath(".lnswitchboard-active.json").write_text(
        '{"phase":"active","namespace":"public","name":"pay","share_token":"share-token","operation_id":"recovery"}',
        encoding="utf-8",
    )
    Path(env["ZROK_TEST_FAIL_DELETE"]).touch()
    process = subprocess.Popen([str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        control.joinpath("disconnect.json").write_text(
            json.dumps({"operation_id": "b" * 32, "namespace": "public", "name": "pay"}),
            encoding="utf-8",
        )
        _wait_for(
            lambda: (_read_status(status / "status.json") or {}).get("state")
            == "error"
        )
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)


def test_failed_first_boot_clears_fully_compensated_starting_state(runtime) -> None:
    control, status, home, _log, env = runtime
    Path(env["ZROK_TEST_FAIL_SHARE_BOOT"]).touch()
    _configure(control)
    process = subprocess.Popen(
        [str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        _wait_for(
            lambda: (
                (_read_status(status / "status.json") or {}).get("state") == "error"
                and not home.joinpath(".lnswitchboard-active.json").exists()
                and not home.joinpath("enabled").exists()
                and not home.joinpath("name").exists()
            )
        )
        assert not home.joinpath(".lnswitchboard-active.json").exists()
        assert not home.joinpath("enabled").exists()
        assert not home.joinpath("name").exists()
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)


def test_recovery_reconciles_starting_state_instead_of_restart_looping(runtime) -> None:
    _control, status, home, _log, env = runtime
    _enable_existing(home)
    home.joinpath("name").touch()
    home.joinpath(".lnswitchboard-active.json").write_text(
        '{"phase":"starting","namespace":"public","name":"pay","operation_id":"recovery","frontend_endpoints":[]}',
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        _wait_for(lambda: (_read_status(status / "status.json") or {}).get("state") == "connected")
        assert json.loads(home.joinpath(".lnswitchboard-active.json").read_text())["phase"] == "active"
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)


def test_disconnect_rejects_identity_mismatch_without_remote_cleanup(runtime) -> None:
    control, status, home, log, env = runtime
    _enable_existing(home)
    home.joinpath("name").touch()
    home.joinpath(".lnswitchboard-active.json").write_text(
        '{"phase":"active","namespace":"public","name":"pay","operation_id":"recovery","frontend_endpoints":["https://pay.example"]}',
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        _wait_for(lambda: (_read_status(status / "status.json") or {}).get("state") == "connected")
        before = log.read_text(encoding="utf-8")
        control.joinpath("disconnect.json").write_text(
            json.dumps({"operation_id": "d" * 32, "namespace": "public", "name": "someone-else"}),
            encoding="utf-8",
        )
        _wait_for(
            lambda: (_read_status(status / "status.json") or {}).get("operation_id") == "d" * 32
        )
        assert (_read_status(status / "status.json") or {})["state"] == "error"
        after = log.read_text(encoding="utf-8")
        assert "delete name" not in after[len(before):]
        assert home.joinpath(".lnswitchboard-active.json").exists()
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)


def test_disconnect_deletes_only_current_environment_share(runtime) -> None:
    control, status, home, log, env = runtime
    _enable_existing(home)
    home.joinpath("name").touch()
    home.joinpath("share-live").touch()
    home.joinpath(".lnswitchboard-active.json").write_text(
        '{"phase":"active","namespace":"public","name":"pay","operation_id":"recovery","frontend_endpoints":["https://pay.example"]}',
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        _wait_for(lambda: (_read_status(status / "status.json") or {}).get("state") == "connected")
        control.joinpath("disconnect.json").write_text(
            json.dumps({"operation_id": "e" * 32, "namespace": "public", "name": "pay"}),
            encoding="utf-8",
        )
        _wait_for(lambda: (_read_status(status / "status.json") or {}).get("state") == "disconnected")
        commands = log.read_text(encoding="utf-8")
        assert "list shares --env-zid local-env" in commands
        assert "delete share runtime-token" in commands
        assert "delete share foreign-token" not in commands
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)
