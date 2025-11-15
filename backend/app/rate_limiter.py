"""Simple in-memory IP-based rate limiter."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple


class RateLimiter:
    """Token bucket style rate limiter stored in-memory."""

    def __init__(self, limit: int, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> Tuple[bool, int]:
        """Return whether the key is allowed and remaining quota."""
        now = time.monotonic()
        async with self._lock:
            bucket = self._events[key]
            while bucket and now - bucket[0] > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.limit:
                remaining = 0
                return False, remaining
            bucket.append(now)
            remaining = self.limit - len(bucket)
            return True, remaining
