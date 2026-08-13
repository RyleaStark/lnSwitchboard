"""Bounded filesystem protocol for the isolated zrok connector."""

from __future__ import annotations

import json
import os
import uuid
from json import JSONDecodeError
from pathlib import Path
from typing import Any

SHARED_DIRECTORY_MODE = 0o750
SHARED_FILE_MODE = 0o640
MAX_STATUS_BYTES = 64 * 1024


class ZrokProtocolError(RuntimeError):
    """The private connector protocol returned malformed or unbounded data."""


class ZrokConnector:
    supported_operations = ("configure", "refresh", "disconnect")

    def __init__(self, *, control_dir: Path, status_dir: Path) -> None:
        self.control_dir = Path(control_dir)
        self.status_dir = Path(status_dir)
        self.control_dir.mkdir(parents=True, exist_ok=True, mode=SHARED_DIRECTORY_MODE)
        self.status_dir.mkdir(parents=True, exist_ok=True, mode=SHARED_DIRECTORY_MODE)
        os.chmod(self.control_dir, SHARED_DIRECTORY_MODE)
        os.chmod(self.status_dir, SHARED_DIRECTORY_MODE)

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        temporary = path.with_name(f".{path.name}.tmp.{uuid.uuid4().hex}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, SHARED_FILE_MODE)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def configure(self, payload: dict[str, str]) -> str:
        operation_id = uuid.uuid4().hex
        payload = {**payload, "operation_id": operation_id}
        (self.status_dir / "status.json").unlink(missing_ok=True)
        self._atomic_write(
            self.control_dir / "configure.json",
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        )
        return operation_id

    def refresh(self) -> str:
        operation_id = uuid.uuid4().hex
        self._atomic_write(self.control_dir / "refresh", operation_id.encode("ascii"))
        return operation_id

    def clear_refresh(self) -> None:
        (self.control_dir / "refresh").unlink(missing_ok=True)

    def disconnect(self) -> str:
        operation_id = uuid.uuid4().hex
        (self.status_dir / "status.json").unlink(missing_ok=True)
        self._atomic_write(self.control_dir / "disconnect", operation_id.encode("ascii"))
        return operation_id

    def read_status(self) -> dict[str, Any] | None:
        path = self.status_dir / "status.json"
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_STATUS_BYTES + 1)
        except FileNotFoundError:
            return None
        if len(raw) > MAX_STATUS_BYTES:
            raise ZrokProtocolError("zrok status is too large")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (JSONDecodeError, UnicodeDecodeError) as exc:
            raise ZrokProtocolError("zrok status is invalid") from exc
        if not isinstance(payload, dict):
            raise ZrokProtocolError("zrok status must be an object")
        return payload
