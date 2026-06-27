"""In-memory hook metrics recorder for the daemon hot path.

Records only buckets, reason codes, and counters — never raw output,
prompt text, decrypted payloads, or secret samples. Counters are
flushed to SQLite asynchronously via ``maybe_flush_to_store()``.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..store import GuardStore

LATENCY_BUCKETS_MS = (5, 10, 25, 50, 75, 100, 200, 350, 500, 750, 1000, 2500, 5000, 10000)
SIZE_BUCKETS = (
    (12_000, "0-12k"),
    (64 * 1024, "12k-64k"),
    (256 * 1024, "64k-256k"),
    (1024 * 1024, "256k-1m"),
    (5 * 1024 * 1024, "1m-5m"),
)


def _latency_bucket(latency_ms: float) -> str:
    for threshold in LATENCY_BUCKETS_MS:
        if latency_ms <= threshold:
            return f"<= {threshold}ms"
    return f"> {LATENCY_BUCKETS_MS[-1]}ms"


def _size_bucket(output_size: int) -> str:
    for threshold, label in SIZE_BUCKETS:
        if output_size <= threshold:
            return label
    return "over"


class HookMetricsRecorder:
    """Thread-safe in-memory metrics recorder.

    Never stores raw output, prompts, decrypted payloads, or secret samples.
    Only stores buckets, counters, and reason codes.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._latencies: list[float] = []
        self._max_items = 10_000

    def record(
        self,
        *,
        harness: str,
        event_name: str,
        route: str,
        payload_kind: str,
        output_size: int,
        latency_ms: float,
        decision: str,
        policy_action: str | None,
        model_output_action: str,
        reason_code: str,
        cache_status: str,
        fallback_kind: str,
        scanner_bytes: int,
    ) -> None:
        """Record one hook decision metric without raw content."""
        with self._lock:
            if len(self._latencies) < self._max_items:
                self._latencies.append(latency_ms)
            key = f"{harness}:{event_name}:{route}:{payload_kind}:{decision}:{reason_code}:{cache_status}:{fallback_kind}"
            self._counters[key] += 1
            self._counters[f"latency:{_latency_bucket(latency_ms)}"] += 1
            self._counters[f"size:{_size_bucket(output_size)}"] += 1
            self._counters[f"model_output_action:{model_output_action}"] += 1
            if policy_action:
                self._counters[f"policy_action:{policy_action}"] += 1

    def snapshot(self) -> dict[str, object]:
        """Return a snapshot of current metrics."""
        with self._lock:
            latencies = sorted(self._latencies)
            p50 = latencies[len(latencies) // 2] if latencies else 0.0
            p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
            p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0.0
            return {
                "counters": dict(self._counters),
                "latency_p50_ms": round(p50, 2),
                "latency_p95_ms": round(p95, 2),
                "latency_p99_ms": round(p99, 2),
                "total_decisions": len(self._latencies),
            }

    def maybe_flush_to_store(self, store: GuardStore, *, force: bool = False) -> None:
        """Flush metrics to store as a rollup event.

        Only writes if there are enough decisions or force is True.
        The event payload contains no raw content.
        """
        with self._lock:
            if not force and len(self._latencies) < 100:
                return
            snapshot = {
                "counters": dict(self._counters),
                "latency_p50_ms": round(
                    sorted(self._latencies)[len(self._latencies) // 2] if self._latencies else 0.0, 2
                ),
                "latency_p95_ms": round(
                    sorted(self._latencies)[int(len(self._latencies) * 0.95)] if self._latencies else 0.0, 2
                ),
                "total_decisions": len(self._latencies),
            }
            self._counters.clear()
            self._latencies.clear()

        from datetime import datetime, timezone

        store.add_event(
            "hook.metrics.rollup",
            snapshot,
            datetime.now(timezone.utc).isoformat(),
        )


__all__ = ["HookMetricsRecorder", "LATENCY_BUCKETS_MS", "SIZE_BUCKETS"]
