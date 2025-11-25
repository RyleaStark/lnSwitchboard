"""Version helpers."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]


@lru_cache()
def get_version() -> str:
    version_file = BASE_DIR / "VERSION"
    try:
        content = version_file.read_text(encoding="utf-8")
    except OSError:
        return "0.0.0"
    return content.strip() or "0.0.0"
