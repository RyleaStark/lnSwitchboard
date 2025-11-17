"""Helpers for loading macaroons from disk."""

from __future__ import annotations

from pathlib import Path


class MacaroonStore:
    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    async def get(self) -> str:
        data = self._path.read_text(encoding="utf-8").strip()
        return data

    async def set(self, value: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(value.strip(), encoding="utf-8")
