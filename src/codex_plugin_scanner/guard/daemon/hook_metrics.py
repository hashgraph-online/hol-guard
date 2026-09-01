"""In-memory hook metrics recorder for the daemon hot path.

Records only buckets, reason codes, and counters — never raw output,
prompt text, decrypted payloads, or secret samples. Counters are
flushed to SQLite asynchronously via ``maybe_flush_to_store()``.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import TYPE_CHECKING, final

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
_MAX_COUNTER_KEYS = 256
_HARNESSES = {"pi", "omp", "codex", "claude-code", "cursor", "opencode"}
_DECISIONS = {"allow", "deny", "ask", "block", "warn", "error"}
_CACHE_STATUSES = {"hit", "miss", "bypass", "disabled", "error"}
_FALLBACK_KINDS = {"none", "fail_closed", "local", "cache", "error"}
_EVENTS = {"pretooluse", "posttooluse", "permissionrequest", "userpromptsubmit"}
_ROUTES = {"native_resident", "native_oneshot", "native_fail_safe", "python_semantic"}


def _bounded_dimension(value: str, allowed: set[str]) -> str:
    normalized = value.strip().lower()
    return normalized if normalized in allowed else "other"


def _reason_category(reason_code: str) -> str:
    normalized = reason_code.strip().lower()
    for category in ("secret", "policy", "deadline", "capacity", "worker", "store", "auth"):
        if category in normalized:
            return category
    return "other"


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


@final
class HookMetricsRecorder:
    """Thread-safe in-memory metrics recorder.

    Never stores raw output, prompts, decrypted payloads, or secret samples.
    Only stores buckets, counters, and reason codes.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._latencies: list[float] = []
        self._routes: dict[str, int] = defaultdict(int)
        self._max_items = 10_000

    def _increment(self, key: str) -> None:
        if key in self._counters:
            self._counters[key] += 1
        elif len(self._counters) < _MAX_COUNTER_KEYS - 1:
            self._counters[key] = 1
        else:
            self._counters["metrics:overflow"] += 1

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
            safe_harness = _bounded_dimension(harness, _HARNESSES)
            safe_event = _bounded_dimension(event_name.replace("_", "").replace("-", ""), _EVENTS)
            safe_decision = _bounded_dimension(decision, _DECISIONS)
            safe_cache = _bounded_dimension(cache_status, _CACHE_STATUSES)
            safe_fallback = _bounded_dimension(fallback_kind, _FALLBACK_KINDS)
            safe_reason = _reason_category(reason_code)
            self._increment(
                f"decision:{safe_harness}:{safe_event}:{safe_decision}:{safe_reason}:{safe_cache}:{safe_fallback}"
            )
            self._increment(f"latency:{_latency_bucket(latency_ms)}")
            self._increment(f"size:{_size_bucket(output_size)}")
            self._increment(f"scanner_size:{_size_bucket(scanner_bytes)}")
            self._increment(f"model_output_action:{_bounded_dimension(model_output_action, _DECISIONS)}")
            _ = route, payload_kind
            if policy_action:
                self._increment(f"policy_action:{_bounded_dimension(policy_action, _DECISIONS)}")

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

    def maybe_flush_to_store(self, store: GuardStore, *, force: bool = False) -> None:
        """Flush metrics to store as a rollup event.

        Only writes if there are enough decisions or force is True.
        The event payload contains no raw content.
        """
        with self._lock:
            if not force and len(self._latencies) < 100:
                return
            snapshot: dict[str, object] = {
                "counters": dict(self._counters),
                "latency_p50_ms": round(
                    sorted(self._latencies)[len(self._latencies) // 2] if self._latencies else 0.0, 2
                ),
                "latency_p95_ms": round(
                    sorted(self._latencies)[int(len(self._latencies) * 0.95)] if self._latencies else 0.0, 2
                ),
                "total_decisions": len(self._latencies),
                "routes": dict(self._routes),
            }
            self._counters.clear()
            self._latencies.clear()
            self._routes.clear()

        from datetime import datetime, timezone

        store.add_event(
            "hook.metrics.rollup",
            snapshot,
            datetime.now(timezone.utc).isoformat(),
        )


__all__ = ["LATENCY_BUCKETS_MS", "SIZE_BUCKETS", "HookMetricsRecorder"]
