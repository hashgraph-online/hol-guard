"""Bounded observation of a capacity wave; never evidence of accepted routing.

Native observations run in the real worker context. Delivered observations run
after the existing response timer and are aggregated independently: concurrent
request order cannot join the two streams. No request is repeated and no health,
readiness, policy or deadline is refreshed. Native-wrapper overhead remains in
the measured request latency. These records never change the conservation gate.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any
from unittest.mock import patch

from scripts.native_slo_adapter import Observation
from scripts.native_slo_edge_diagnostic import capture_native_edge_stages
from scripts.native_slo_native_diagnostic import observe_native_call

_MAX_WAVE = 64
_MAX_NATIVE_DETAILS = 8
_MAX_LABEL = 128
_ACTIONS = frozenset({"allow", "deny", "block", "review", "ask", "warn", "allow_original", "replace"})
_REASONS = frozenset(
    {
        "daemon_capacity",
        "daemon_overloaded",
        "daemon_hook_queue_capacity",
        "daemon_hook_queue_bytes",
        "daemon_hook_deadline_exhausted",
        "native_overloaded",
        "native_post_tool_unavailable",
        "native_pre_tool_unavailable",
        "native_hook_event_unavailable",
        "native_command_control_fence_unavailable",
        "native_policy_not_ready",
    }
)
_DELIVERY: ContextVar[dict[str, object] | None] = ContextVar("capacity_delivery", default=None)


def _semantics(value: object) -> dict[str, object]:
    """Copy only fixed fields, closed labels and bounded unknown-value digests."""
    if not isinstance(value, Mapping):
        return {"available": False}
    result: dict[str, object] = {"available": True}
    for field, alias in (
        ("decision", "decision"),
        ("minimum_action", "minimum_action"),
        ("policy_action", "policy_action"),
        ("model_output_action", "model_action"),
        ("reason_code", "reason_code"),
        ("error", "error"),
    ):
        if field not in value:
            continue
        item = value[field]
        if type(item) is not str:
            result[alias + "_state"] = "invalid_type"
            continue
        allowed = _REASONS if field in {"reason_code", "error"} else _ACTIONS
        if item in allowed:
            result[alias] = item
        else:
            result[alias + "_digest"] = hashlib.sha256(item[:_MAX_LABEL].encode("utf-8", errors="replace")).hexdigest()
            result[alias + "_digest_complete"] = len(item) <= _MAX_LABEL
    return result


def retain_capacity_delivery(response: Mapping[str, object]) -> None:
    """Observe only an explicitly selected load thread, after its latency timer."""
    active = _DELIVERY.get()
    if active is not None:
        active.update(_semantics(response))


class CapacityDiagnostics:
    """Capped per-wave evidence with no association inferred from arrival order."""

    def __init__(self, worker: Any, limit: int) -> None:
        if type(limit) is not int or not 0 < limit <= _MAX_WAVE:
            raise ValueError("capacity diagnostic limit is invalid")
        self.worker = worker
        self.limit = limit
        self.native_status = "unavailable"
        self.native_count = 0
        self.native_count_saturated = False
        self.native_missing = 0
        self.native_details: list[dict[str, object]] = []
        self.delivery_count = 0
        self.delivery_count_saturated = False
        self.deliveries: Counter[str] = Counter()
        self._lock = threading.Lock()

    def observe(self, operation: Callable[[], Observation]) -> Observation:
        detail: dict[str, object] = {"available": False}
        token = _DELIVERY.set(detail)
        try:
            observation = operation()
        finally:
            _DELIVERY.reset(token)
        # A returned response and a raised transport error remain disjoint.
        detail.update(allowed=observation.allowed, overloaded=observation.overloaded)
        encoded = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        with self._lock:
            if self.delivery_count >= self.limit:
                self.delivery_count_saturated = True
            else:
                self.delivery_count += 1
                self.deliveries[encoded] += 1
        return observation

    @contextmanager
    def capture_native(self) -> Iterator[None]:
        original = getattr(self.worker, "_review_raw_hook_native", None)
        if not callable(original):
            yield
            return
        self.native_status = "active"

        def observe(**kwargs: object) -> object:
            with self._lock:
                if self.native_count >= self.limit:
                    self.native_count_saturated = True
                    selected = False
                else:
                    self.native_count += 1
                    selected = True
            if not selected:
                return original(**kwargs)
            edge, diagnostic = observe_native_call(
                lambda: original(**kwargs),
                worker=self.worker,
                deadline=kwargs.get("deadline"),
                policy_snapshot=kwargs.get("policy_snapshot"),
            )
            if edge is None:
                with self._lock:
                    self.native_missing += 1
                    if len(self.native_details) < _MAX_NATIVE_DETAILS:
                        self.native_details.append(diagnostic)
            return edge

        try:
            with capture_native_edge_stages(), patch.object(self.worker, "_review_raw_hook_native", observe):
                yield
        finally:
            self.native_status = "capture_window_closed"

    def report(self) -> dict[str, object]:
        with self._lock:
            return {
                "schema": "hol-guard.capacity-wave-diagnostic.v1",
                "scope": "same_wave_independent_aggregate_observations",
                "individual_route_attribution": False,
                "native_wrapper_overhead_in_latency": True,
                "delivery_capture_after_latency": True,
                "request_repeated": False,
                "deadline_changed": False,
                "maximum_observations": self.limit,
                "native_wrapper": self.native_status,
                "native_call_count": self.native_count,
                "native_count_is_lower_bound": self.native_count_saturated,
                "native_missing_count": self.native_missing,
                "native_missing_details": list(self.native_details),
                "native_details_truncated": self.native_missing > len(self.native_details),
                "delivery_count": self.delivery_count,
                "delivery_count_is_lower_bound": self.delivery_count_saturated,
                "delivered_semantics": [
                    {"count": count, "verdict": json.loads(encoded)}
                    for encoded, count in sorted(self.deliveries.items())
                ],
            }
