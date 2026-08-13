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
        "begin_login",
        "cancel_login",
        "clear_login",
        "enable",
        "disable",
        "disconnect",
    )

    def __init__(self, *, control_dir: Path, status_dir: Path) -> None:
        self.control_dir = Path(control_dir)
        self.status_dir = Path(status_dir)
        self.control_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.status_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.command_dir = self.control_dir / "queue"
        self.operation_dir = self.control_dir / "operations"
        self.processing_dir = self.control_dir / "processing"
        self.ack_dir = self.control_dir / "acks"
        self.result_dir = self.status_dir / "results"
        self.command_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.operation_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.ack_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.result_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.control_dir, 0o700)
        os.chmod(self.status_dir, 0o700)
        os.chmod(self.command_dir, 0o700)
        os.chmod(self.operation_dir, 0o700)
        os.chmod(self.ack_dir, 0o700)
        os.chmod(self.result_dir, 0o700)

    @staticmethod
    def _sync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _atomic_write(
        self, path: Path, content: bytes, *, immutable: bool = False
    ) -> None:
        temporary = path.with_name(f".{path.name}.tmp.{uuid.uuid4().hex}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            if immutable:
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    if self._read_bounded(path) != content.decode("utf-8"):
                        raise TailscaleProtocolError(
                            "Tailscale operation ID already has different content"
                        ) from None
                self._sync_directory(path.parent)
            else:
                os.replace(temporary, path)
                self._sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _mark(
        self, operation: str, *, operation_id: str | None = None, **parameters: str
    ) -> str:
        if operation not in self.supported_operations:
            raise ValueError("unsupported Tailscale operation")
        operation_id = operation_id or uuid.uuid4().hex
        if len(operation_id) != 32 or any(
            character not in "0123456789abcdef" for character in operation_id
        ):
            raise ValueError("invalid Tailscale operation ID")
        payload = {
            "command": operation,
            "operation_id": operation_id,
            **parameters,
        }
        content = (
            json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode("utf-8")
        operation_path = self.operation_dir / f"{operation_id}.json"
        self._atomic_write(operation_path, content, immutable=True)
        processing_path = self.processing_dir / f"{operation_id}.json"
        queue_path = self.command_dir / f"{operation_id}.json"
        if not processing_path.exists() and not queue_path.exists():
            try:
                os.link(operation_path, queue_path)
                self._sync_directory(self.command_dir)
            except FileExistsError:
                pass
        return operation_id

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

    def begin_login(self, device_name: str) -> str:
        (self.status_dir / "login.json").unlink(missing_ok=True)
        return self._mark("begin_login", device_name=device_name)

    def cancel_login(self) -> str:
        return self._mark("cancel_login")

    def clear_login(self) -> str:
        return self._mark("clear_login")

    def enable_funnel(self, *, external_id: str, hostname: str) -> str:
        return self._mark("enable", external_id=external_id, hostname=hostname)

    def disable_funnel(self, *, external_id: str, hostname: str) -> str:
        return self._mark("disable", external_id=external_id, hostname=hostname)

    def disconnect(
        self, *, external_id: str, hostname: str, operation_id: str | None = None
    ) -> str:
        return self._mark(
            "disconnect",
            operation_id=operation_id,
            external_id=external_id,
            hostname=hostname,
        )

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

    def read_command_status(self, operation_id: str) -> dict[str, Any] | None:
        return self._read_object(f"results/{operation_id}.json")

    def consume_command_result(self, operation_id: str) -> None:
        self._atomic_write(
            self.ack_dir / f"{operation_id}.ack",
            (operation_id + "\n").encode("ascii"),
        )

    def has_login_artifact(self) -> bool:
        return (self.status_dir / "login.json").exists()
