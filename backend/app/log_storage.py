"""Request log persistence and retrieval."""

from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List


def _normalize_details(details: Dict[str, Any] | None) -> Dict[str, Any] | None:
    if not details:
        return None
    try:
        return json.loads(json.dumps(details))
    except (TypeError, ValueError):
        return {"_raw": repr(details)}


@dataclass(slots=True)
class LogEntry:
    """Structured log entry for LNURL interactions."""

    timestamp: str
    username: str
    ip: str
    event: str
    domain: str | None = None
    amount_msat: int | None = None
    status: str = "ok"
    message: str | None = None
    details: Dict[str, Any] | None = None

    @classmethod
    def create(
        cls,
        *,
        username: str,
        ip: str,
        event: str,
        domain: str | None = None,
        amount_msat: int | None = None,
        status: str = "ok",
        message: str | None = None,
        details: Dict[str, Any] | None = None,
    ) -> "LogEntry":
        return cls(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            username=username,
            ip=ip,
            event=event,
            domain=domain,
            amount_msat=amount_msat,
            status=status,
            message=message,
            details=_normalize_details(details),
        )


class RequestLogStorage:
    """Handles append-only storage and retrieval of request logs."""

    def __init__(self, path: Path, max_recent: int = 50) -> None:
        self._path = path
        self._max_recent = max_recent
        self._recent: Deque[Dict[str, object]] = deque(maxlen=max_recent)
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._load_existing()

    def _load_existing(self) -> None:
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    payload.setdefault("domain", None)
                    self._recent.append(payload)
        except OSError:
            # Nothing we can do; continue without preloading.
            return

    async def append(self, entry: LogEntry) -> None:
        payload = asdict(entry)
        async with self._lock:
            try:
                with self._path.open("a", encoding="utf-8") as fp:
                    fp.write(json.dumps(payload) + "\n")
            except OSError:
                # If writing fails, we still keep the recent buffer up-to-date.
                pass
            payload.setdefault("domain", None)
            self._recent.append(payload)

    async def get_recent(self, limit: int | None = None) -> List[Dict[str, object]]:
        async with self._lock:
            recent_items = list(self._recent)
        if limit is not None:
            return recent_items[-limit:]
        return recent_items

    async def clear(self) -> None:
        async with self._lock:
            self._recent.clear()
            try:
                with self._path.open("w", encoding="utf-8"):
                    pass
            except OSError:
                # Ignore failures; in-memory buffer remains cleared.
                return
