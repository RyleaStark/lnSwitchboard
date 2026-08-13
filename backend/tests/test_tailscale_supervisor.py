from __future__ import annotations

import os
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterator

import pytest

from backend.app.tailscale_connector import TailscaleConnector

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


def _write_command(
    control_dir: Path,
    name: str,
    operation_id: str,
    *,
    external_id: str | None = None,
    hostname: str | None = None,
    device_name: str | None = None,
) -> None:
    import json

    payload = {"command": name.replace("-", "_"), "operation_id": operation_id}
    if external_id is not None:
        payload["external_id"] = external_id
    if hostname is not None:
        payload["hostname"] = hostname
    if device_name is not None:
        payload["device_name"] = device_name
    queue_dir = control_dir / "queue"
    queue_dir.mkdir(exist_ok=True)
    (queue_dir / f"{operation_id}.json").write_text(
        json.dumps(payload, separators=(",", ":")), encoding="utf-8"
    )


def _write_operation_record(
    control_dir: Path, name: str, operation_id: str
) -> Path:
    import json

    operations = control_dir / "operations"
    operations.mkdir(exist_ok=True)
    path = operations / f"{operation_id}.json"
    path.write_text(
        json.dumps(
            {"command": name.replace("-", "_"), "operation_id": operation_id},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return path


def _command_result(status_dir: Path, operation_id: str) -> Path:
    return status_dir / "results" / f"{operation_id}.json"


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
if [ -f "$TS_TEST_IGNORE_DAEMON_TERM_FILE" ]; then
  trap '' TERM INT
else
  trap 'exit 0' TERM INT
fi
while :; do sleep 1; done
""",
    )
    _write_executable(
        bin_dir / "tailscale",
        """#!/bin/sh
printf 'tailscale %s\\n' "$*" >> "$TS_TEST_COMMAND_LOG"
case "${1:-}" in --socket=*) shift ;; esac
if [ "${1:-}" = "status" ]; then
  if [ -f "$TS_TEST_RUNNING_FILE" ]; then
    printf '%s\n' '{"BackendState":"Running","Self":{"ID":"node-123","DNSName":"lns.tailnet.example.ts.net."}}'
  else
    printf '%s\n' '{"BackendState":"NeedsLogin","AuthURL":"REDACTED","Self":{"DNSName":""}}'
  fi
elif [ "${1:-}" = "up" ]; then
  printf '%s\\n' '{"AuthURL":"REDACTED","BackendState":"NeedsLogin"}'
  if [ -f "$TS_TEST_COMPLETE_LOGIN_FILE" ]; then
    printf '%s\\n' '{"BackendState":"Running"}'
    exit 0
  fi
  if [ -f "$TS_TEST_IGNORE_LOGIN_TERM_FILE" ]; then
    trap '' TERM INT
  else
    trap 'exit 0' TERM INT
  fi
  if [ -f "$TS_TEST_LOGIN_DESCENDANT_PID_FILE" ]; then
    sh -c 'trap "" TERM INT; while :; do sleep 1; done' &
    printf '%s\n' "$!" > "$TS_TEST_LOGIN_DESCENDANT_PID_FILE"
  fi
  while :; do sleep 1; done
elif [ "${1:-}" = "funnel" ] && [ "${2:-}" = "reset" ]; then
  if [ -f "$TS_TEST_FAIL_FUNNEL_RESET_FILE" ]; then exit 1; fi
  exit 0
elif [ "${1:-}" = "funnel" ] && [ "${2:-}" = "status" ]; then
  if [ -f "$TS_TEST_FAIL_FUNNEL_STATUS_FILE" ]; then exit 1; fi
  printf '%s\\n' '{}'
elif [ "${1:-}" = "funnel" ] && [ "${2:-}" = "--bg" ]; then
  while [ -f "$TS_TEST_BLOCK_FUNNEL_FILE" ]; do sleep 0.02; done
  exit 0
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
            "TS_TEST_RUNNING_FILE": str(tmp_path / "node-running"),
            "TS_TEST_COMPLETE_LOGIN_FILE": str(tmp_path / "complete-login"),
            "TS_TEST_IGNORE_LOGIN_TERM_FILE": str(tmp_path / "ignore-login-term"),
            "TS_TEST_IGNORE_DAEMON_TERM_FILE": str(tmp_path / "ignore-daemon-term"),
            "TS_TEST_LOGIN_DESCENDANT_PID_FILE": str(tmp_path / "login-descendant-pid"),
            "TS_TEST_BLOCK_FUNNEL_FILE": str(tmp_path / "block-funnel"),
            "TS_LOGIN_RETENTION_SECONDS": "2",
            "TS_LOGIN_STOP_TIMEOUT": "1",
            "DEP_ENV": "UMBREL_DEV",
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


def test_supervisor_recovers_operation_published_before_queue_link(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, _state_dir, _command_log, env = supervisor_runtime
    operation_id = "e" * 32
    _write_operation_record(control_dir, "cancel-login", operation_id)
    process = subprocess.Popen([str(SUPERVISOR)], env=env)
    try:
        _wait_for(lambda: _command_result(status_dir, operation_id).exists())
        assert '"command":"cancel_login"' in _command_result(
            status_dir, operation_id
        ).read_text(encoding="utf-8")
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_ack_creates_terminal_tombstone_before_cleanup(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, _state_dir, _command_log, env = supervisor_runtime
    operation_id = "f" * 32
    _write_operation_record(control_dir, "cancel-login", operation_id)
    process = subprocess.Popen([str(SUPERVISOR)], env=env)
    try:
        result = _command_result(status_dir, operation_id)
        _wait_for(result.exists)
        ack_dir = control_dir / "acks"
        ack_dir.mkdir(exist_ok=True)
        (ack_dir / f"{operation_id}.ack").write_text(operation_id, encoding="utf-8")
        completed = control_dir / "completed" / f"{operation_id}.json"
        _wait_for(completed.exists)
        _wait_for(lambda: not result.exists())
        assert '"operation_id":"' + operation_id + '"' in completed.read_text(
            encoding="utf-8"
        )
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_discards_queue_link_for_completed_operation(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, _state_dir, command_log, env = supervisor_runtime
    operation_id = "a" * 32
    operation = _write_operation_record(control_dir, "cancel-login", operation_id)
    completed_dir = control_dir / "completed"
    completed_dir.mkdir(exist_ok=True)
    (completed_dir / f"{operation_id}.json").write_bytes(operation.read_bytes())
    _write_command(control_dir, "cancel-login", operation_id)

    process = subprocess.Popen([str(SUPERVISOR)], env=env)
    try:
        queue = control_dir / "queue" / f"{operation_id}.json"
        _wait_for(lambda: not queue.exists())
        time.sleep(0.15)
        assert not _command_result(status_dir, operation_id).exists()
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_protocol_lock_prevents_ack_transition_during_claim_execution(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, _state_dir, command_log, env = supervisor_runtime
    operation_id = "c" * 32
    blocker = Path(env["TS_TEST_BLOCK_FUNNEL_FILE"])
    blocker.touch()
    Path(env["TS_TEST_RUNNING_FILE"]).touch()
    _write_operation_record(control_dir, "enable", operation_id)
    _write_command(
        control_dir,
        "enable",
        operation_id,
        external_id="node-123",
        hostname="lns.tailnet.example.ts.net",
    )
    connector = TailscaleConnector(control_dir=control_dir, status_dir=status_dir)

    process = subprocess.Popen([str(SUPERVISOR)], env=env)
    acknowledgement = threading.Thread(
        target=connector.consume_command_result, args=(operation_id,), daemon=True
    )
    try:
        _wait_for(
            lambda: command_log.exists()
            and "funnel --bg" in command_log.read_text(encoding="utf-8")
        )
        acknowledgement.start()
        time.sleep(0.15)
        assert acknowledgement.is_alive()

        blocker.unlink()
        acknowledgement.join(timeout=3)
        assert not acknowledgement.is_alive()
    finally:
        blocker.unlink(missing_ok=True)
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
        _write_command(control_dir, "begin-login", "1" * 32, device_name="lns")

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

        _write_command(control_dir, "cancel-login", "7" * 32)
        _wait_for(lambda: not (status_dir / "login.json").exists())
        _wait_for(
            lambda: (
                _command_result(status_dir, "7" * 32).exists()
                and '"command":"cancel_login"'
                in _command_result(status_dir, "7" * 32).read_text(encoding="utf-8")
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
        _write_command(
            control_dir,
            "begin-login",
            "2" * 32,
            device_name="lns\n--hostname=attacker",
        )

        _wait_for(
            lambda: (
                _command_result(status_dir, "2" * 32).exists()
                and '"error":"invalid_command"'
                in _command_result(status_dir, "2" * 32).read_text(encoding="utf-8")
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
    Path(env["TS_TEST_RUNNING_FILE"]).touch()
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

        _write_command(
            control_dir, "enable", "3" * 32,
            external_id="node-123", hostname="lns.tailnet.example.ts.net",
        )
        _wait_for(
            lambda: (
                _command_result(status_dir, "3" * 32).exists()
                and '"command":"enable"'
                in _command_result(status_dir, "3" * 32).read_text(encoding="utf-8")
            )
        )
        _wait_for(lambda: (status_dir / "funnel.json").exists())
        commands = command_log.read_text(encoding="utf-8")
        assert (
            f"tailscale --socket={env['TS_SOCKET']} funnel --bg --yes "
            "http://extended-umbrella-lnswitchboard_public:21212"
        ) in commands

        _write_command(
            control_dir, "disable", "4" * 32,
            external_id="node-123", hostname="lns.tailnet.example.ts.net",
        )
        _wait_for(
            lambda: (
                _command_result(status_dir, "4" * 32).exists()
                and '"command":"disable"'
                in _command_result(status_dir, "4" * 32).read_text(encoding="utf-8")
            )
        )

        _write_command(
            control_dir, "disconnect", "5" * 32,
            external_id="node-123", hostname="lns.tailnet.example.ts.net",
        )
        _wait_for(
            lambda: (
                _command_result(status_dir, "5" * 32).exists()
                and '"command":"disconnect"'
                in _command_result(status_dir, "5" * 32).read_text(encoding="utf-8")
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


def test_supervisor_disconnect_needs_live_identity_when_key_is_expired(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    """Historical identity metadata cannot authorize deletion of ambiguous state."""
    control_dir, status_dir, state_dir, command_log, env = supervisor_runtime
    Path(env["TS_TEST_FAIL_FUNNEL_RESET_FILE"]).touch()
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
        (state_dir / ".lnswitchboard-active.json").write_text(
            '{"external_id":"node-123","hostname":"lns.tailnet.example.ts.net"}\n',
            encoding="utf-8",
        )

        _write_command(
            control_dir, "disconnect", "5" * 32,
            external_id="node-123", hostname="lns.tailnet.example.ts.net",
        )
        _wait_for(
            lambda: (
                _command_result(status_dir, "5" * 32).exists()
                and '"command":"disconnect"' in _command_result(status_dir, "5" * 32).read_text(encoding="utf-8")
            )
        )
        command_status = _command_result(status_dir, "5" * 32).read_text(encoding="utf-8")
        assert '"state":"error"' in command_status
        assert '"error":"identity_mismatch"' in command_status
        assert (state_dir / "owned-node-state").exists()
        # No provider mutation or daemon restart is authorized without live identity.
        lines = command_log.read_text(encoding="utf-8").splitlines()
        assert not any("funnel reset" in line for line in lines)
        assert not any(line.endswith(" logout") for line in lines)
        assert sum(line.startswith("tailscaled ") for line in lines) == 1
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
        _write_command(control_dir, "begin-login", "6" * 32, device_name="lns")

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


def test_cancel_login_force_kills_term_resistant_provider_and_releases_protocol_lock(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, _state_dir, command_log, env = supervisor_runtime
    Path(env["TS_TEST_IGNORE_LOGIN_TERM_FILE"]).touch()
    process = subprocess.Popen(
        [str(SUPERVISOR)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        begin_id = "7" * 32
        cancel_id = "8" * 32
        _write_command(control_dir, "begin-login", begin_id, device_name="lns")
        _wait_for(lambda: _command_result(status_dir, begin_id).exists())
        _wait_for(
            lambda: any(
                " up --json --reset " in f" {line} "
                for line in command_log.read_text(encoding="utf-8").splitlines()
            )
        )

        started = time.monotonic()
        _write_command(control_dir, "cancel-login", cancel_id)
        _wait_for(lambda: _command_result(status_dir, cancel_id).exists(), timeout=3)
        assert time.monotonic() - started < 3
        assert '"state":"complete"' in _command_result(
            status_dir, cancel_id
        ).read_text(encoding="utf-8")

        connector = TailscaleConnector(control_dir=control_dir, status_dir=status_dir)
        operation_id = connector.cancel_login()
        assert (control_dir / "queue" / f"{operation_id}.json").exists()
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_cancel_login_terminates_term_resistant_descendants(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, _state_dir, _command_log, env = supervisor_runtime
    Path(env["TS_TEST_IGNORE_LOGIN_TERM_FILE"]).touch()
    descendant_pid_file = Path(env["TS_TEST_LOGIN_DESCENDANT_PID_FILE"])
    descendant_pid_file.touch()
    process = subprocess.Popen([str(SUPERVISOR)], env=env)
    try:
        begin_id = "9" * 32
        cancel_id = "a" * 32
        _write_command(control_dir, "begin-login", begin_id, device_name="lns")
        _wait_for(lambda: descendant_pid_file.read_text(encoding="utf-8").strip() != "")
        descendant_pid = int(descendant_pid_file.read_text(encoding="utf-8"))
        _write_command(control_dir, "cancel-login", cancel_id)
        _wait_for(lambda: _command_result(status_dir, cancel_id).exists(), timeout=3)

        def descendant_stopped() -> bool:
            try:
                os.kill(descendant_pid, 0)
            except ProcessLookupError:
                return True
            return False

        _wait_for(descendant_stopped, timeout=3)
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_disconnect_force_kills_term_resistant_daemon_and_releases_protocol_lock(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, state_dir, _command_log, env = supervisor_runtime
    Path(env["TS_TEST_RUNNING_FILE"]).touch()
    Path(env["TS_TEST_IGNORE_DAEMON_TERM_FILE"]).touch()
    (state_dir / "owned-node-state").write_text("private", encoding="utf-8")
    process = subprocess.Popen([str(SUPERVISOR)], env=env)
    try:
        operation_id = "b" * 32
        _write_command(
            control_dir,
            "disconnect",
            operation_id,
            external_id="node-123",
            hostname="lns.tailnet.example.ts.net",
        )
        _wait_for(lambda: _command_result(status_dir, operation_id).exists(), timeout=4)
        assert '"state":"complete"' in _command_result(
            status_dir, operation_id
        ).read_text(encoding="utf-8")

        connector = TailscaleConnector(control_dir=control_dir, status_dir=status_dir)
        next_operation = connector.cancel_login()
        assert (control_dir / "queue" / f"{next_operation}.json").exists()
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


def test_supervisor_disconnect_stays_fail_closed_when_running_and_reset_fails(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    """A live node may still be funneling: failed reset must block disconnect."""
    control_dir, status_dir, state_dir, command_log, env = supervisor_runtime
    Path(env["TS_TEST_RUNNING_FILE"]).touch()
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
        operation_id = "5" * 32
        connector = TailscaleConnector(control_dir=control_dir, status_dir=status_dir)
        assert connector.disconnect(
            external_id="node-123",
            hostname="lns.tailnet.example.ts.net",
            operation_id=operation_id,
        ) == operation_id
        command_status = _command_result(status_dir, operation_id)
        _wait_for(
            lambda: (
                command_status.exists()
                and '"error":"funnel_disable_failed"'
                in command_status.read_text(encoding="utf-8")
            )
        )

        assert not (control_dir / "completed" / f"{operation_id}.json").exists()
        assert (control_dir / "operations" / f"{operation_id}.json").exists()
        assert (state_dir / f".lnswitchboard-disconnect-{operation_id}.json").exists()
        assert command_status.exists()

        Path(env["TS_TEST_FAIL_FUNNEL_RESET_FILE"]).unlink()
        connector.disconnect(
            external_id="node-123",
            hostname="lns.tailnet.example.ts.net",
            operation_id=operation_id,
            retry=True,
        )
        _wait_for(
            lambda: command_status.exists()
            and '"state":"complete"' in command_status.read_text(encoding="utf-8")
        )
        assert not owned_state.exists()
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_uses_fresh_identity_bound_status_not_cached_node_snapshot(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, state_dir, command_log, env = supervisor_runtime
    process = subprocess.Popen(
        [str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, text=True,
    )
    try:
        _wait_for(lambda: (status_dir / "node.json").exists())
        assert '"NeedsLogin"' in (status_dir / "node.json").read_text(encoding="utf-8")
        Path(env["TS_TEST_RUNNING_FILE"]).touch()
        owned_state = state_dir / "owned-node-state"
        owned_state.write_text("private", encoding="utf-8")
        operation_id = "9" * 32
        _write_command(
            control_dir, "disconnect", operation_id,
            external_id="node-123", hostname="lns.tailnet.example.ts.net",
        )
        result = _command_result(status_dir, operation_id)
        _wait_for(lambda: result.exists() and '"state":"complete"' in result.read_text(encoding="utf-8"))
        lines = command_log.read_text(encoding="utf-8").splitlines()
        assert any("funnel reset" in line for line in lines)
        assert any(line.endswith(" logout") for line in lines)
        assert not owned_state.exists()
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_replays_claimed_disconnect_after_restart(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, state_dir, command_log, env = supervisor_runtime
    Path(env["TS_TEST_RUNNING_FILE"]).touch()
    operation_id = "a" * 32
    processing = control_dir / "processing"
    processing.mkdir(exist_ok=True)
    (processing / f"{operation_id}.json").write_text(
        '{"command":"disconnect","operation_id":"' + operation_id
        + '","external_id":"node-123","hostname":"lns.tailnet.example.ts.net"}',
        encoding="utf-8",
    )
    (state_dir / "owned-node-state").write_text("private", encoding="utf-8")
    process = subprocess.Popen(
        [str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, text=True,
    )
    try:
        result = _command_result(status_dir, operation_id)
        _wait_for(lambda: result.exists() and '"state":"complete"' in result.read_text(encoding="utf-8"))
        _wait_for(lambda: not (processing / f"{operation_id}.json").exists())
        assert not (state_dir / "owned-node-state").exists()
        lines = command_log.read_text(encoding="utf-8").splitlines()
        assert any("funnel reset" in line for line in lines)
        assert any(line.endswith(" logout") for line in lines)
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_supervisor_rejects_disconnect_identity_mismatch_without_deleting_state(
    supervisor_runtime: tuple[Path, Path, Path, Path, dict[str, str]],
) -> None:
    control_dir, status_dir, state_dir, command_log, env = supervisor_runtime
    Path(env["TS_TEST_RUNNING_FILE"]).touch()
    owned_state = state_dir / "owned-node-state"
    owned_state.write_text("private", encoding="utf-8")
    process = subprocess.Popen(
        [str(SUPERVISOR)], env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, text=True,
    )
    try:
        _wait_for(lambda: (status_dir / "node.json").exists())
        _write_command(
            control_dir, "disconnect", "8" * 32,
            external_id="different-node",
            hostname="other.tailnet.example.ts.net",
        )
        command_status = _command_result(status_dir, "8" * 32)
        _wait_for(
            lambda: command_status.exists()
            and '"error":"identity_mismatch"'
            in command_status.read_text(encoding="utf-8")
        )
        assert owned_state.exists()
        assert not any(
            line.endswith(" logout")
            for line in command_log.read_text(encoding="utf-8").splitlines()
        )
    finally:
        process.terminate()
        process.wait(timeout=3)