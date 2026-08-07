from __future__ import annotations

import os
import stat
import subprocess
import time
from pathlib import Path
from typing import Iterator

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUPERVISOR = ROOT / "deploy" / "tailscale" / "supervisor.sh"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _wait_for(predicate, *, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timed out waiting for supervisor state")


@pytest.fixture
def supervisor_runtime(
    tmp_path: Path,
) -> Iterator[tuple[Path, Path, Path, Path, dict[str, str]]]:
    bin_dir = tmp_path / "bin"
    control_dir = tmp_path / "control"
    status_dir = tmp_path / "status"
    state_dir = tmp_path / "state"
    socket_path = tmp_path / "tailscaled.sock"
    command_log = tmp_path / "commands.log"
    for path in (bin_dir, control_dir, status_dir, state_dir):
        path.mkdir()

    _write_executable(
        bin_dir / "tailscaled",
        """#!/bin/sh
printf 'tailscaled %s\\n' "$*" >> "$TS_TEST_COMMAND_LOG"
trap 'exit 0' TERM INT
while :; do sleep 1; done
""",
    )
    _write_executable(
        bin_dir / "tailscale",
        """#!/bin/sh
printf 'tailscale %s\\n' "$*" >> "$TS_TEST_COMMAND_LOG"
case "${1:-}" in --socket=*) shift ;; esac
if [ "${1:-}" = "status" ]; then
  printf '%s\\n' '{"BackendState":"NeedsLogin","AuthURL":"REDACTED","Self":{"DNSName":""}}'
elif [ "${1:-}" = "up" ]; then
  printf '%s\\n' '{"AuthURL":"REDACTED","BackendState":"NeedsLogin"}'
  if [ -f "$TS_TEST_COMPLETE_LOGIN_FILE" ]; then
    printf '%s\\n' '{"BackendState":"Running"}'
    exit 0
  fi
  trap 'exit 0' TERM INT
  while :; do sleep 1; done
elif [ "${1:-}" = "funnel" ] && [ "${2:-}" = "reset" ]; then
  if [ -f "$TS_TEST_FAIL_FUNNEL_RESET_FILE" ]; then exit 1; fi
  exit 0
elif [ "${1:-}" = "funnel" ] && [ "${2:-}" = "status" ]; then
  if [ -f "$TS_TEST_FAIL_FUNNEL_STATUS_FILE" ]; then exit 1; fi
  printf '%s\\n' '{}'
fi
""",
    )

    env = os.environ.copy()
    env.update(
        {
            "TS_TAILSCALED_BIN": str(bin_dir / "tailscaled"),
            "TS_TAILSCALE_BIN": str(bin_dir / "tailscale"),
            "TS_CONTROL_DIR": str(control_dir),
            "TS_STATUS_DIR": str(status_dir),
            "TS_STATE_DIR": str(state_dir),
            "TS_SOCKET": str(socket_path),
            "TS_POLL_INTERVAL": "0.05",
            "TS_TEST_COMMAND_LOG": str(command_log),
            "TS_TEST_FAIL_FUNNEL_STATUS_FILE": str(tmp_path / "fail-funnel-status"),
            "TS_TEST_FAIL_FUNNEL_RESET_FILE": str(tmp_path / "fail-funnel-reset"),
            "TS_TEST_COMPLETE_LOGIN_FILE": str(tmp_path / "complete-login"),
            "TS_LOGIN_RETENTION_SECONDS": "2",
        }
    )
    yield control_dir, status_dir, state_dir, command_log, env


def test_supervisor_starts_userspace_daemon_and_publishes_self_only_status(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, state_dir, command_log, env = supervisor_runtime

    process = subprocess.Popen(
        [str(SUPERVISOR)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for(lambda: (status_dir / "node.json").exists())

        commands = command_log.read_text(encoding="utf-8")
        assert "tailscaled --tun=userspace-networking" in commands
        assert f"--state={state_dir / 'tailscaled.state'}" in commands
        assert f"--statedir={state_dir}" in commands
        assert (
            f"tailscale --socket={env['TS_SOCKET']} status --json --peers=false"
            in commands
        )
        assert "tailscale up " not in commands
        assert (status_dir / "node.json").read_text(encoding="utf-8") == (
            '{"BackendState":"NeedsLogin","Self":{"DNSName":""}}\n'
        )
        assert stat.S_IMODE((status_dir / "node.json").stat().st_mode) == 0o600
        assert not (status_dir / "tailscaled.stderr").exists()
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_starts_and_cancels_login_with_validated_device_name(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, _state_dir, command_log, env = supervisor_runtime
    process = subprocess.Popen(
        [str(SUPERVISOR)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for(lambda: (status_dir / "node.json").exists())
        (control_dir / "login.device-name").write_text("LNS\n", encoding="utf-8")
        (control_dir / "begin-login").touch()

        _wait_for(lambda: (status_dir / "login.json").exists())
        _wait_for(
            lambda: "AuthURL" in (status_dir / "login.json").read_text(encoding="utf-8")
        )

        commands = command_log.read_text(encoding="utf-8")
        assert (
            f"tailscale --socket={env['TS_SOCKET']} up --json --reset "
            "--hostname=lns --accept-dns=false"
        ) in commands
        assert "--advertise-tags=" not in commands
        assert stat.S_IMODE((status_dir / "login.json").stat().st_mode) == 0o600
        assert not (status_dir / "login.stderr").exists()
        assert process.stdout is not None
        assert process.stderr is not None

        (control_dir / "cancel-login").touch()
        _wait_for(lambda: not (status_dir / "login.json").exists())
        _wait_for(
            lambda: (
                '"command":"cancel_login"'
                in (status_dir / "command.json").read_text(encoding="utf-8")
            )
        )
        assert process.stdout.read(0) == ""
        assert process.stderr.read(0) == ""
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_rejects_multiline_device_name_without_running_login(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, _state_dir, command_log, env = supervisor_runtime
    process = subprocess.Popen(
        [str(SUPERVISOR)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        _wait_for(lambda: (status_dir / "node.json").exists())
        (control_dir / "login.device-name").write_text(
            "lns\n--hostname=attacker", encoding="utf-8"
        )
        (control_dir / "begin-login").touch()

        _wait_for(
            lambda: (
                (status_dir / "command.json").exists()
                and '"error":"invalid_device_name"'
                in (status_dir / "command.json").read_text(encoding="utf-8")
            )
        )
        commands = command_log.read_text(encoding="utf-8")
        assert "--hostname=" not in commands
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_uses_fixed_funnel_commands_and_disconnects_fail_closed(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, state_dir, command_log, env = supervisor_runtime
    process = subprocess.Popen(
        [str(SUPERVISOR)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        _wait_for(lambda: (status_dir / "node.json").exists())
        (state_dir / "owned-node-state").write_text("private", encoding="utf-8")

        (control_dir / "enable").touch()
        _wait_for(
            lambda: (
                (status_dir / "command.json").exists()
                and '"command":"enable"'
                in (status_dir / "command.json").read_text(encoding="utf-8")
            )
        )
        _wait_for(lambda: (status_dir / "funnel.json").exists())
        commands = command_log.read_text(encoding="utf-8")
        assert (
            f"tailscale --socket={env['TS_SOCKET']} funnel --bg --yes "
            "http://127.0.0.1:21212"
        ) in commands

        (control_dir / "disable").touch()
        _wait_for(
            lambda: (
                '"command":"disable"'
                in (status_dir / "command.json").read_text(encoding="utf-8")
            )
        )

        (control_dir / "disconnect").touch()
        _wait_for(
            lambda: (
                '"command":"disconnect"'
                in (status_dir / "command.json").read_text(encoding="utf-8")
            )
        )
        _wait_for(lambda: not (state_dir / "owned-node-state").exists())

        lines = command_log.read_text(encoding="utf-8").splitlines()
        reset_index = max(i for i, line in enumerate(lines) if "funnel reset" in line)
        logout_index = max(
            i for i, line in enumerate(lines) if line.endswith(" logout")
        )
        assert reset_index < logout_index
        assert sum(line.startswith("tailscaled ") for line in lines) >= 2
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_removes_stale_funnel_snapshot_when_probe_fails(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    _control_dir, status_dir, _state_dir, _command_log, env = supervisor_runtime
    process = subprocess.Popen(
        [str(SUPERVISOR)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        _wait_for(lambda: (status_dir / "funnel.json").exists())
        Path(env["TS_TEST_FAIL_FUNNEL_STATUS_FILE"]).touch()
        _wait_for(lambda: not (status_dir / "funnel.json").exists())
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_expires_completed_login_artifact_without_backend_cleanup(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, _state_dir, _command_log, env = supervisor_runtime
    Path(env["TS_TEST_COMPLETE_LOGIN_FILE"]).touch()
    process = subprocess.Popen(
        [str(SUPERVISOR)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        (control_dir / "login.device-name").write_text("lns\n", encoding="utf-8")
        (control_dir / "begin-login").touch()

        login_status = status_dir / "login.json"
        _wait_for(
            lambda: (
                login_status.exists()
                and '"BackendState":"Running"'
                in login_status.read_text(encoding="utf-8")
            )
        )
        _wait_for(lambda: not login_status.exists(), timeout=5)
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_expires_login_artifact_left_by_previous_process(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    _control_dir, status_dir, _state_dir, _command_log, env = supervisor_runtime
    env["TS_LOGIN_RETENTION_SECONDS"] = "2"
    login_status = status_dir / "login.json"
    login_status.write_text('{"AuthURL":"REDACTED"}\n', encoding="utf-8")
    old = time.time() - 10
    os.utime(login_status, (old, old))

    process = subprocess.Popen(
        [str(SUPERVISOR)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        _wait_for(lambda: not login_status.exists())
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_disconnect_preserves_state_when_funnel_reset_fails(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, state_dir, command_log, env = supervisor_runtime
    Path(env["TS_TEST_FAIL_FUNNEL_RESET_FILE"]).touch()
    owned_state = state_dir / "owned-node-state"
    owned_state.write_text("private", encoding="utf-8")

    process = subprocess.Popen(
        [str(SUPERVISOR)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        _wait_for(lambda: (status_dir / "node.json").exists())
        (control_dir / "disconnect").touch()
        command_status = status_dir / "command.json"
        _wait_for(
            lambda: (
                command_status.exists()
                and '"error":"funnel_disable_failed"'
                in command_status.read_text(encoding="utf-8")
            )
        )

        assert owned_state.exists()
        assert not any(
            line.endswith(" logout")
            for line in command_log.read_text(encoding="utf-8").splitlines()
        )
    finally:
        process.terminate()
        process.wait(timeout=3)
