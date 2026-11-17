"""In-memory hook metrics recorder for the daemon hot path.

Records only bounded decision-route counts and failure counters — never raw
output, prompt text, decrypted payloads, or secret samples.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import final

_MAX_COUNTER_KEYS = 256
_ROUTES = {"native_resident", "native_oneshot", "native_fail_safe", "native_degraded", "python_semantic"}


@final
class HookMetricsRecorder:
    """Thread-safe in-memory metrics recorder.

    Never stores raw output, prompts, decrypted payloads, or secret samples.
    Only stores bounded route counts and failure counters.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._routes: dict[str, int] = defaultdict(int)

    def _increment(self, key: str) -> None:
        if key in self._counters:
            self._counters[key] += 1
        elif len(self._counters) < _MAX_COUNTER_KEYS - 1:
            self._counters[key] = 1
        else:
            self._counters["metrics:overflow"] += 1

    def snapshot(self) -> dict[str, object]:
        """Return a snapshot of current metrics."""
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict[str, object]:
        return {
            "counters": dict(self._counters),
            "routes": dict(self._routes),
        }

    def record_route(self, route: str) -> None:
        """Record bounded decision-route provenance without request data."""
        safe_route = route if route in _ROUTES else "native_fail_safe"
        with self._lock:
            self._routes[safe_route] += 1

    def record_failure(self, *, stage: str, exception_type: str) -> None:
        """Record only a bounded failure stage and exception class."""
        safe_stage = stage if stage in {"engine", "metrics", "server"} else "unknown"
        safe_exception = exception_type if exception_type.isidentifier() else "UnknownError"
        with self._lock:
            self._increment(f"failure:{safe_stage}:{safe_exception[:80]}")


__all__ = ["HookMetricsRecorder"]
