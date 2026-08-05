"""Bounded, deadline-aware admission for local runtime hook reviews."""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from typing import Final, final

from .runtime_hook_deadline import RuntimeHookDeadline
from .runtime_hook_scheduler_contracts import (
    QueuedRuntimeHook,
    RuntimeHookAdmission,
    RuntimeHookByteReservation,
    RuntimeHookPermit,
    RuntimeHookSchedulerStats,
)
from .runtime_hook_scheduler_types import RuntimeHookAdmissionReason, RuntimeHookLane

_LANE_WEIGHTS: Final[dict[RuntimeHookLane, int]] = {
    "decision": 4,
    "content-security": 3,
    "evidence": 1,
}
_LANES: Final[tuple[RuntimeHookLane, ...]] = tuple(_LANE_WEIGHTS)
_AGE_BOOST_SECONDS: Final = 0.5
_DEFAULT_SERVICE_SECONDS: Final = 0.75
_MIN_SERVICE_SECONDS: Final = 0.1
_MAX_SERVICE_SECONDS: Final = 2.8
_MIN_PREDICTION_SAMPLES: Final = 20
_HISTOGRAM_WINDOW_SECONDS: Final = 60.0
_STABLE_HARNESSES: Final = frozenset({"pi", "omp", "codex", "claude-code", "cursor", "opencode"})


@final
class RuntimeHookScheduler:
    """Queues short hook bursts while bounding count, bytes, and wait time."""

    def __init__(
        self,
        *,
        active_limit: int = 32,
        per_harness_active_limit: int = 24,
        queued_limit: int = 128,
        per_harness_queued_limit: int = 64,
        per_client_queued_limit: int = 32,
        retained_bytes_limit: int = 32 * 1024 * 1024,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        limits = (
            active_limit,
            per_harness_active_limit,
            queued_limit,
            per_harness_queued_limit,
            per_client_queued_limit,
            retained_bytes_limit,
        )
        if active_limit < 0 or any(limit < 1 for limit in limits[1:]):
            raise ValueError("runtime hook scheduler limits must be positive")
        self._active_limit = active_limit
        self._per_harness_active_limit = per_harness_active_limit
        self._queued_limit = queued_limit
        self._per_harness_queued_limit = per_harness_queued_limit
        self._per_client_queued_limit = per_client_queued_limit
        self._retained_bytes_limit = retained_bytes_limit
        self._monotonic = monotonic
        self._condition = threading.Condition()
        self._queues: dict[
            RuntimeHookLane,
            OrderedDict[tuple[str, str], deque[QueuedRuntimeHook]],
        ] = {lane: OrderedDict() for lane in _LANE_WEIGHTS}
        self._sequence = 0
        self._lane_cursor = 0
        self._lane_deficits: dict[RuntimeHookLane, int] = dict.fromkeys(_LANES, 0)
        self._active = 0
        self._active_by_harness: dict[str, int] = {}
        self._active_by_client: dict[str, int] = {}
        self._queued = 0
        self._queued_by_harness: dict[str, int] = {}
        self._queued_by_client: dict[str, int] = {}
        self._retained_bytes = 0
        self._admitted = 0
        self._completed = 0
        self._expired = 0
        self._cancelled = 0
        self._retries = 0
        self._rejected: dict[str, int] = {}
        self._queue_wait_samples: deque[float] = deque(maxlen=2048)
        self._service_time_samples: deque[float] = deque(maxlen=2048)
        self._queue_wait_by_lane: dict[RuntimeHookLane, deque[tuple[float, float]]] = {
            lane: deque(maxlen=2048) for lane in _LANES
        }
        self._service_time_by_lane: dict[RuntimeHookLane, deque[tuple[float, float]]] = {
            lane: deque(maxlen=2048) for lane in _LANES
        }

    def acquire(
        self,
        *,
        harness: str,
        client_key: str,
        lane: RuntimeHookLane,
        payload_bytes: int,
        deadline: float | RuntimeHookDeadline,
        byte_reservation: RuntimeHookByteReservation | None = None,
        cancellation: threading.Event | None = None,
        normalized_payload: bytes | None = None,
    ) -> RuntimeHookAdmission:
        if payload_bytes < 0:
            raise ValueError("payload_bytes must not be negative")
        if normalized_payload is not None and len(normalized_payload) != payload_bytes:
            raise ValueError("normalized_payload length must match payload_bytes")
        with self._condition:
            now = self._monotonic()
            resolved_deadline = (
                deadline
                if isinstance(deadline, RuntimeHookDeadline)
                else RuntimeHookDeadline(
                    expires_at=deadline,
                    transport_reserve_seconds=0.0,
                    serialization_reserve_seconds=0.0,
                )
            )
            if resolved_deadline.expires_at <= now:
                return self._reject("daemon_hook_deadline_exhausted")
            if self._queued >= self._queued_limit:
                return self._reject("daemon_hook_queue_capacity")
            if self._queued_by_harness.get(harness, 0) >= self._per_harness_queued_limit:
                return self._reject("daemon_hook_queue_capacity")
            if self._queued_by_client.get(client_key, 0) >= self._per_client_queued_limit:
                return self._reject("daemon_hook_queue_capacity")
            if byte_reservation is None and self._retained_bytes + payload_bytes > self._retained_bytes_limit:
                return self._reject("daemon_hook_queue_bytes")
            if byte_reservation is not None and byte_reservation.payload_bytes != payload_bytes:
                raise ValueError("runtime hook byte reservation does not match payload size")
            if byte_reservation is not None and not byte_reservation.is_owned_by(self):
                raise ValueError("runtime hook byte reservation belongs to another scheduler")

            self._sequence += 1
            item = QueuedRuntimeHook(
                sequence=self._sequence,
                harness=harness,
                client_key=client_key,
                lane=lane,
                payload_bytes=payload_bytes,
                deadline=resolved_deadline,
                queued_at=now,
                cancellation=cancellation,
                normalized_payload=normalized_payload or b"",
            )
            self._enqueue(item)
            if byte_reservation is not None:
                byte_reservation.transfer()
            else:
                self._retained_bytes += payload_bytes
            self._dispatch()
            while not item.admitted and item.rejection_reason is None:
                remaining = resolved_deadline.expires_at - self._monotonic()
                if remaining <= 0:
                    if self._remove_queued(item):
                        self._expired += 1
                        self._condition.notify_all()
                    return RuntimeHookAdmission(None, "daemon_hook_deadline_exhausted")
                if cancellation is not None and cancellation.is_set():
                    if self._remove_queued(item):
                        self._cancelled += 1
                        self._condition.notify_all()
                    return RuntimeHookAdmission(None, "daemon_hook_deadline_exhausted")
                _ = self._condition.wait(timeout=min(remaining, 0.05) if cancellation is not None else remaining)
                self._dispatch()
            if item.rejection_reason is not None:
                return RuntimeHookAdmission(None, item.rejection_reason)
            return RuntimeHookAdmission(RuntimeHookPermit(self, item), None)

    def reserve_bytes(
        self,
        *,
        payload_bytes: int,
        deadline: float,
    ) -> tuple[RuntimeHookByteReservation | None, RuntimeHookAdmissionReason | None]:
        if payload_bytes < 0:
            raise ValueError("payload_bytes must not be negative")
        with self._condition:
            if deadline <= self._monotonic():
                admission = self._reject("daemon_hook_deadline_exhausted")
                return None, admission.reason_code
            if payload_bytes > self._retained_bytes_limit:
                admission = self._reject("daemon_hook_queue_bytes")
                return None, admission.reason_code
            while self._retained_bytes + payload_bytes > self._retained_bytes_limit:
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    admission = self._reject("daemon_hook_deadline_exhausted")
                    return None, admission.reason_code
                _ = self._condition.wait(timeout=remaining)
            self._retained_bytes += payload_bytes
            return RuntimeHookByteReservation(self, payload_bytes), None

    def release_reserved_bytes(self, payload_bytes: int) -> None:
        with self._condition:
            self._retained_bytes -= payload_bytes
            self._condition.notify_all()

    def grow_reserved_bytes(
        self,
        *,
        current_bytes: int,
        payload_bytes: int,
        deadline: float,
    ) -> RuntimeHookAdmissionReason | None:
        with self._condition:
            if payload_bytes > self._retained_bytes_limit:
                return self._reject("daemon_hook_queue_bytes").reason_code
            additional_bytes = payload_bytes - current_bytes
            if additional_bytes < 0:
                raise ValueError("runtime hook byte growth cannot be negative")
            while self._retained_bytes + additional_bytes > self._retained_bytes_limit:
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    return self._reject("daemon_hook_deadline_exhausted").reason_code
                _ = self._condition.wait(timeout=remaining)
            self._retained_bytes += additional_bytes
            return None

    def stats(self) -> RuntimeHookSchedulerStats:
        with self._condition:
            now = self._monotonic()
            return {
                "active": self._active,
                "active_limit": self._active_limit,
                "queued": self._queued,
                "queued_limit": self._queued_limit,
                "retained_bytes": self._retained_bytes,
                "retained_bytes_limit": self._retained_bytes_limit,
                "admitted": self._admitted,
                "completed": self._completed,
                "expired": self._expired,
                "cancelled": self._cancelled,
                "retries": self._retries,
                "rejected": dict(self._rejected),
                "per_harness_active": self._bounded_harness_counts(self._active_by_harness),
                "per_harness_queued": self._bounded_harness_counts(self._queued_by_harness),
                "queue_wait_p95_ms": self._percentile_ms(self._queue_wait_samples, 0.95),
                "service_time_p95_ms": self._percentile_ms(self._service_time_samples, 0.95),
                "queue_wait_p99_ms": self._percentile_ms(self._queue_wait_samples, 0.99),
                "service_time_p99_ms": self._percentile_ms(self._service_time_samples, 0.99),
                "oldest_queued_ms": self._oldest_queued_ms(now),
                "queue_wait_by_lane_p95_ms": {
                    lane: self._timed_percentile_ms(samples, now) for lane, samples in self._queue_wait_by_lane.items()
                },
                "service_time_by_lane_p95_ms": {
                    lane: self._timed_percentile_ms(samples, now)
                    for lane, samples in self._service_time_by_lane.items()
                },
                "queue_wait_by_lane_p99_ms": {
                    lane: self._timed_percentile_ms(samples, now, percentile=0.99)
                    for lane, samples in self._queue_wait_by_lane.items()
                },
                "service_time_by_lane_p99_ms": {
                    lane: self._timed_percentile_ms(samples, now, percentile=0.99)
                    for lane, samples in self._service_time_by_lane.items()
                },
            }

    def record_retry(self) -> None:
        with self._condition:
            self._retries += 1

    def set_active_limit(self, active_limit: int) -> None:
        if active_limit < 0:
            raise ValueError("runtime hook scheduler active limit must not be negative")
        with self._condition:
            self._active_limit = active_limit
            self._dispatch()

    def _reject(self, reason_code: RuntimeHookAdmissionReason) -> RuntimeHookAdmission:
        self._rejected[reason_code] = self._rejected.get(reason_code, 0) + 1
        return RuntimeHookAdmission(None, reason_code)

    def _enqueue(self, item: QueuedRuntimeHook) -> None:
        clients = self._queues[item.lane]
        clients.setdefault((item.client_key, item.harness), deque()).append(item)
        self._queued += 1
        self._queued_by_harness[item.harness] = self._queued_by_harness.get(item.harness, 0) + 1
        self._queued_by_client[item.client_key] = self._queued_by_client.get(item.client_key, 0) + 1

    def _dispatch(self) -> None:
        self._expire_waiters()
        while self._active < self._active_limit and self._queued > 0:
            item = self._next_item()
            if item is None:
                break
            self._decrement_queued(item)
            item.admitted = True
            item.admitted_at = self._monotonic()
            self._queue_wait_samples.append(max(0.0, item.admitted_at - item.queued_at))
            self._queue_wait_by_lane[item.lane].append((item.admitted_at, max(0.0, item.admitted_at - item.queued_at)))
            self._active += 1
            self._active_by_harness[item.harness] = self._active_by_harness.get(item.harness, 0) + 1
            self._active_by_client[item.client_key] = self._active_by_client.get(item.client_key, 0) + 1
            self._admitted += 1
        self._condition.notify_all()

    def _next_item(self) -> QueuedRuntimeHook | None:
        boosted = self._oldest_aged_eligible()
        if boosted is not None:
            return boosted
        active_share_limit = max(1, math.ceil(self._active_limit / 2))
        for _ in range(sum(_LANE_WEIGHTS.values()) + len(_LANES)):
            lane = _LANES[self._lane_cursor]
            if self._lane_deficits[lane] == 0:
                self._lane_deficits[lane] = _LANE_WEIGHTS[lane]
            clients = self._queues[lane]
            if not clients:
                self._lane_deficits[lane] = 0
                self._lane_cursor = (self._lane_cursor + 1) % len(_LANES)
                continue
            if self._lane_deficits[lane] < 1:
                continue
            for _ in range(len(clients)):
                group_key, items = clients.popitem(last=False)
                client_key, _harness = group_key
                if self._active_by_harness.get(items[0].harness, 0) >= self._per_harness_active_limit:
                    clients[group_key] = items
                    continue
                competing_client = self._has_competing_client(client_key)
                if competing_client and self._active_by_client.get(client_key, 0) >= active_share_limit:
                    clients[group_key] = items
                    continue
                if not self._can_finish(items[0]):
                    item = items.popleft()
                    if items:
                        clients[group_key] = items
                    self._reject_queued(item, "daemon_hook_deadline_exhausted")
                    continue
                item = items.popleft()
                if items:
                    clients[group_key] = items
                self._lane_deficits[lane] -= 1
                if self._lane_deficits[lane] == 0:
                    self._lane_cursor = (self._lane_cursor + 1) % len(_LANES)
                return item
            self._lane_deficits[lane] = 0
            self._lane_cursor = (self._lane_cursor + 1) % len(_LANES)
        return None

    def _oldest_aged_eligible(self) -> QueuedRuntimeHook | None:
        now = self._monotonic()
        candidates = [
            items[0]
            for clients in self._queues.values()
            for items in clients.values()
            if items and now - items[0].queued_at >= _AGE_BOOST_SECONDS
        ]
        for item in sorted(candidates, key=lambda candidate: candidate.sequence):
            if self._active_by_harness.get(item.harness, 0) >= self._per_harness_active_limit:
                continue
            competing_client = self._has_competing_client(item.client_key)
            active_share_limit = max(1, math.ceil(self._active_limit / 2))
            if competing_client and self._active_by_client.get(item.client_key, 0) >= active_share_limit:
                continue
            if not self._can_finish(item):
                _ = self._remove_queued(item)
                item.rejection_reason = "daemon_hook_deadline_exhausted"
                self._expired += 1
                continue
            self._remove_from_lane(item)
            return item
        return None

    def _can_finish(self, item: QueuedRuntimeHook) -> bool:
        return item.deadline.can_dispatch(
            self._service_estimate(item.lane),
            monotonic=self._monotonic,
        )

    def _service_estimate(self, lane: RuntimeHookLane) -> float:
        now = self._monotonic()
        recent = [value for timestamp, value in self._service_time_by_lane[lane] if now - timestamp <= 60.0]
        if len(recent) < _MIN_PREDICTION_SAMPLES:
            return _DEFAULT_SERVICE_SECONDS
        estimate = self._percentile(deque(recent), 0.95)
        return min(_MAX_SERVICE_SECONDS, max(_MIN_SERVICE_SECONDS, estimate))

    def _has_competing_client(self, client_key: str) -> bool:
        return any(
            queued_client != client_key for clients in self._queues.values() for queued_client, _harness in clients
        )

    def _expire_waiters(self) -> None:
        now = self._monotonic()
        for clients in self._queues.values():
            for group_key in tuple(clients):
                items = clients[group_key]
                retained = deque(
                    item
                    for item in items
                    if item.deadline.expires_at > now and (item.cancellation is None or not item.cancellation.is_set())
                )
                for item in items:
                    if item.deadline.expires_at <= now:
                        self._drop_queued(item)
                        self._expired += 1
                        item.rejection_reason = "daemon_hook_deadline_exhausted"
                    elif item.cancellation is not None and item.cancellation.is_set():
                        self._drop_queued(item)
                        self._cancelled += 1
                        item.rejection_reason = "daemon_hook_deadline_exhausted"
                if retained:
                    clients[group_key] = retained
                else:
                    _ = clients.pop(group_key, None)

    def _remove_queued(self, target: QueuedRuntimeHook) -> bool:
        clients = self._queues[target.lane]
        group_key = (target.client_key, target.harness)
        items = clients.get(group_key)
        if items is None:
            return False
        try:
            items.remove(target)
        except ValueError:
            return False
        if not items:
            _ = clients.pop(group_key, None)
        self._drop_queued(target)
        return True

    def _remove_from_lane(self, target: QueuedRuntimeHook) -> None:
        clients = self._queues[target.lane]
        group_key = (target.client_key, target.harness)
        items = clients[group_key]
        items.remove(target)
        if not items:
            _ = clients.pop(group_key)

    def _reject_queued(self, item: QueuedRuntimeHook, reason: RuntimeHookAdmissionReason) -> None:
        self._drop_queued(item)
        item.rejection_reason = reason
        self._expired += 1

    def _decrement_queued(self, item: QueuedRuntimeHook) -> None:
        self._queued -= 1
        self._decrement_counter(self._queued_by_harness, item.harness)
        self._decrement_counter(self._queued_by_client, item.client_key)

    def _drop_queued(self, item: QueuedRuntimeHook) -> None:
        self._decrement_queued(item)
        self._retained_bytes -= item.payload_bytes

    def release_permit(self, item: QueuedRuntimeHook) -> None:
        """Release one admitted work item and dispatch the next waiter."""

        with self._condition:
            self._active -= 1
            self._decrement_counter(self._active_by_harness, item.harness)
            self._decrement_counter(self._active_by_client, item.client_key)
            self._retained_bytes -= item.payload_bytes
            self._completed += 1
            if item.admitted_at is not None:
                finished_at = self._monotonic()
                service_time = max(0.0, finished_at - item.admitted_at)
                self._service_time_samples.append(service_time)
                self._service_time_by_lane[item.lane].append((finished_at, service_time))
            self._dispatch()

    def _oldest_queued_ms(self, now: float) -> float:
        oldest = min(
            (item.queued_at for clients in self._queues.values() for items in clients.values() for item in items),
            default=None,
        )
        return 0.0 if oldest is None else max(0.0, now - oldest) * 1000.0

    @staticmethod
    def _percentile_ms(samples: deque[float], percentile: float) -> float:
        if not samples:
            return 0.0
        ordered = sorted(samples)
        index = max(0, math.ceil(len(ordered) * percentile) - 1)
        return ordered[index] * 1000.0

    @staticmethod
    def _percentile(samples: deque[float], percentile: float) -> float:
        if not samples:
            return 0.0
        ordered = sorted(samples)
        return ordered[max(0, math.ceil(len(ordered) * percentile) - 1)]

    @classmethod
    def _timed_percentile_ms(
        cls,
        samples: deque[tuple[float, float]],
        now: float,
        *,
        percentile: float = 0.95,
    ) -> float:
        recent = deque(value for timestamp, value in samples if now - timestamp <= _HISTOGRAM_WINDOW_SECONDS)
        return cls._percentile(recent, percentile) * 1000.0

    @staticmethod
    def _bounded_harness_counts(counts: dict[str, int]) -> dict[str, int]:
        bounded: dict[str, int] = {}
        for harness, count in counts.items():
            key = harness if harness in _STABLE_HARNESSES else "other"
            bounded[key] = bounded.get(key, 0) + count
        return bounded

    @staticmethod
    def _decrement_counter(counters: dict[str, int], key: str) -> None:
        remaining = counters[key] - 1
        if remaining:
            counters[key] = remaining
        else:
            _ = counters.pop(key)


__all__ = [
    "RuntimeHookAdmission",
    "RuntimeHookAdmissionReason",
    "RuntimeHookByteReservation",
    "RuntimeHookLane",
    "RuntimeHookPermit",
    "RuntimeHookScheduler",
    "RuntimeHookSchedulerStats",
]
