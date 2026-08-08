"""Logging configuration utilities."""

from __future__ import annotations

import logging
from pathlib import Path


def configure_logging(log_directory: Path) -> None:
    log_directory.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # httpx logs complete request URLs at INFO. Cloudflare administration URLs
    # contain account IDs, zone IDs, route IDs, and sometimes hostnames, none of
    # which belong in application logs.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
