"""In-memory rate limiting for local package-firewall daemon actions."""

from __future__ import annotations

import threading
import time


class PackageFirewallActionRateLimiter:
    def __init__(self, *, limit: int = 30, window_seconds: float = 60.0) -> None:
        self._limit = max(1, limit)
        self._window_seconds = max(1.0, window_seconds)
        self._lock = threading.Lock()
        self._events: dict[str, list[float]] = {}

    def allow(self, key: str, *, now: float | None = None) -> tuple[bool, int]:
        current = now if now is not None else time.monotonic()
        cutoff = current - self._window_seconds
        with self._lock:
            bucket = [timestamp for timestamp in self._events.get(key, []) if timestamp > cutoff]
            if len(bucket) >= self._limit:
                self._events[key] = bucket
                retry_after = max(1, int(self._window_seconds - (current - bucket[0])))
                return False, retry_after
            bucket.append(current)
            self._events[key] = bucket
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
