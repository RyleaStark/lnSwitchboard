"""Protected filesystem adapter for the Tailscale sidecar supervisor."""

from __future__ import annotations

import json
import os
import uuid
from json import JSONDecodeError
from pathlib import Path
from typing import Any

MAX_STATUS_BYTES = 64 * 1024


class TailscaleProtocolError(RuntimeError):
    """The private sidecar protocol returned malformed or unbounded data."""


class TailscaleConnector:
    """Issue fixed supervisor operations and read bounded status snapshots."""

    supported_operations = (
        "begin-login",
        "cancel-login",
        "clear-login",
        "enable",
        "disable",
        "disconnect",
    )

    def __init__(self, *, control_dir: Path, status_dir: Path) -> None:
        self.control_dir = Path(control_dir)
        self.status_dir = Path(status_dir)
        self.control_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.status_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.control_dir, 0o700)
        os.chmod(self.status_dir, 0o700)

    def _atomic_write(self, path: Path, content: bytes) -> None:
        temporary = path.with_name(f".{path.name}.tmp.{uuid.uuid4().hex}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _mark(self, operation: str) -> None:
        if operation not in self.supported_operations:
            raise ValueError("unsupported Tailscale operation")
        (self.status_dir / "command.json").unlink(missing_ok=True)
        self._atomic_write(self.control_dir / operation, b"")

    def _read_bounded(self, path: Path) -> str | None:
        try:
            with path.open("rb") as handle:
                payload = handle.read(MAX_STATUS_BYTES + 1)
        except FileNotFoundError:
            return None
        if len(payload) > MAX_STATUS_BYTES:
            raise TailscaleProtocolError("Tailscale status is too large")
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TailscaleProtocolError("Tailscale status is not UTF-8") from exc

    def _read_object(self, filename: str) -> dict[str, Any] | None:
        raw = self._read_bounded(self.status_dir / filename)
        if raw is None:
            return None
        try:
            payload = json.loads(raw)
        except JSONDecodeError as exc:
            raise TailscaleProtocolError("Tailscale status is invalid JSON") from exc
        if not isinstance(payload, dict):
            raise TailscaleProtocolError("Tailscale status must be an object")
        return payload

    def begin_login(self, device_name: str) -> None:
        (self.status_dir / "login.json").unlink(missing_ok=True)
        self._atomic_write(
            self.control_dir / "login.device-name", f"{device_name}\n".encode("ascii")
        )
        self._mark("begin-login")

    def cancel_login(self) -> None:
        self._mark("cancel-login")

    def clear_login(self) -> None:
        self._mark("clear-login")

    def enable_funnel(self) -> None:
        self._mark("enable")

    def disable_funnel(self) -> None:
        self._mark("disable")

    def disconnect(self) -> None:
        self._mark("disconnect")

    def read_login_records(self) -> list[dict[str, Any]]:
        raw = self._read_bounded(self.status_dir / "login.json")
        if raw is None:
            return []
        decoder = json.JSONDecoder()
        position = 0
        records: list[dict[str, Any]] = []
        while position < len(raw):
            while position < len(raw) and raw[position].isspace():
                position += 1
            if position >= len(raw):
                break
            try:
                payload, position = decoder.raw_decode(raw, position)
            except JSONDecodeError:
                break  # The CLI may still be writing the trailing record.
            if not isinstance(payload, dict):
                raise TailscaleProtocolError("Tailscale login record must be an object")
            records.append(payload)
        return records

    def read_node_status(self) -> dict[str, Any] | None:
        return self._read_object("node.json")

    def read_funnel_status(self) -> dict[str, Any] | None:
        return self._read_object("funnel.json")

    def read_command_status(self) -> dict[str, Any] | None:
        return self._read_object("command.json")

    def has_login_artifact(self) -> bool:
        return (self.status_dir / "login.json").exists()
