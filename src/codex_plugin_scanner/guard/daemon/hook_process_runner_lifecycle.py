"""Lifecycle mixin for the isolated hook-process runner."""

# pyright: reportUninitializedInstanceVariable=false

from __future__ import annotations

import os
import queue
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress

from .hook_process_capacity import AdaptiveHookProcessCapacity, process_tree_rss_bytes
from .hook_process_metrics import increment_bounded_metric
from .hook_process_worker import HookProcessReview, HookWorkerSlot, retire_worker_slot, worker_retirement_thread

_HOOK_PROCESS_READY_TIMEOUT_SECONDS = 14.0
_HOOK_PROCESS_START_TIMEOUT_SECONDS = 30.0


def hook_worker_ready_timeout(configured_timeout: float) -> float:
    return min(_HOOK_PROCESS_START_TIMEOUT_SECONDS, max(_HOOK_PROCESS_READY_TIMEOUT_SECONDS, configured_timeout))


class HookProcessRunnerLifecycleMixin:
    _slots: queue.Queue[HookWorkerSlot]
    _all_slots: dict[int, HookWorkerSlot]
    _spawn_threads: set[threading.Thread]
    _process_creation_lock: threading.Lock
    _supervisor_thread: threading.Thread | None
    _retirement_threads: set[threading.Thread]
    _state_lock: threading.Lock
    _metrics_lock: threading.Lock
    _recovery_event: threading.Event
    _ready_slot_ids: set[int]
    _capacity_target: int
    _startup_capacity_waiting: bool
    _capacity_listener: Callable[[int], None] | None
    _adaptive_capacity: AdaptiveHookProcessCapacity | None
    _adaptive_refresh_enabled: bool
    _rss_bytes_provider: Callable[[], int | None] | None
    _active_reviews: dict[int, int]
    _generation: int
    _closed: bool
    _started: bool
    _timeouts: int
    _failures: int
    _restarts: int
    _decisions: dict[str, int]
    _reason_codes: dict[str, int]
    _routes: dict[str, int]
    wait_for_capacity: Callable[..., bool]

    def require_initial_capacity(self) -> None:
        """Refuse readiness until one isolated worker completes its handshake."""

        if not self.wait_for_capacity(minimum_workers=1, timeout_seconds=_HOOK_PROCESS_READY_TIMEOUT_SECONDS):
            raise RuntimeError("initial isolated hook worker did not become ready")

    def _withdraw_slot_capacity(self, slot: HookWorkerSlot) -> None:
        with self._state_lock:
            self._ready_slot_ids.discard(slot.process.pid or id(slot))
        self._publish_capacity()

    def _retire_idle_slot_async(self, slot: HookWorkerSlot) -> None:
        def contained() -> None:
            with self._state_lock:
                _ = self._all_slots.pop(slot.process.pid or id(slot), None)
            with suppress(OSError):
                slot.connection.close()

        thread = worker_retirement_thread(
            slot,
            graceful=True,
            name="hol-guard-hook-worker-scale-down",
            on_contained=contained,
            on_failed=self._mark_containment_failed,
            on_done=self._discard_retirement_thread,
        )
        start_failed = False
        with self._state_lock:
            if self._closed:
                return
            self._retirement_threads.add(thread)
            try:
                thread.start()
            except RuntimeError:
                self._retirement_threads.discard(thread)
                start_failed = True
        if start_failed:
            self._mark_containment_failed()

    def _discard_retirement_thread(self, thread: threading.Thread) -> None:
        with self._state_lock:
            self._retirement_threads.discard(thread)
        self._recovery_event.set()

    def _trim_excess_ready_capacity(self) -> None:
        while True:
            with self._state_lock:
                excess = len(self._ready_slot_ids) - self._capacity_target
            if excess <= 0:
                return
            try:
                slot = self._slots.get_nowait()
            except queue.Empty:
                return
            with self._state_lock:
                self._ready_slot_ids.discard(slot.process.pid or id(slot))
            self._publish_capacity()
            self._retire_idle_slot_async(slot)

    def _mark_containment_failed(self) -> None:
        with self._state_lock:
            self._closed = True
            self._started = False
            self._generation += 1
        self._recovery_event.set()
        self._increment_metric("failures")

    def _containment_status(self, attempted_slot_ids: set[int]) -> tuple[bool, bool]:
        with self._state_lock:
            current_supervisor = getattr(self, "_supervisor_thread", None)
            if current_supervisor is not None and not current_supervisor.is_alive():
                self._supervisor_thread = None
            pending_background_work = bool(
                self._retirement_threads or self._spawn_threads or self._active_reviews or self._supervisor_thread
            )
            uncontained_slot_ids = {slot.process.pid or id(slot) for slot in self._all_slots.values()}
        contained = not uncontained_slot_ids and not pending_background_work
        stalled = bool(uncontained_slot_ids and uncontained_slot_ids <= attempted_slot_ids)
        return contained, stalled and not pending_background_work

    def _increment_metric(self, metric: str) -> None:
        with self._metrics_lock:
            if metric == "timeouts":
                self._timeouts += 1
            elif metric == "failures":
                self._failures += 1
            elif metric == "restarts":
                self._restarts += 1

    def _record_response_metrics(self, response: Mapping[str, object]) -> None:
        decision = response.get("decision")
        reason_code = response.get("reason_code")
        if not self._metrics_lock.acquire(blocking=False):
            return
        try:
            increment_bounded_metric(self._decisions, decision)
            increment_bounded_metric(self._reason_codes, reason_code)
        finally:
            self._metrics_lock.release()

    def _record_route_metric(self, route: object) -> None:
        with self._metrics_lock:
            increment_bounded_metric(self._routes, route)

    def _terminal_failed_review(self, route: object, reason_code: object) -> HookProcessReview:
        self._record_route_metric(route)
        reason = reason_code if isinstance(reason_code, str) else "daemon_hook_process_failed"
        return HookProcessReview(None, reason)

    def _retire_slot(self, slot: HookWorkerSlot, *, graceful: bool = False) -> bool:
        contained = retire_worker_slot(slot, graceful=graceful)
        if contained:
            with self._state_lock:
                slot_id = slot.process.pid or id(slot)
                _ = self._all_slots.pop(slot_id, None)
                self._ready_slot_ids.discard(slot_id)
            with suppress(OSError):
                slot.connection.close()
            self._publish_capacity()
        return contained

    def _publish_capacity(self, *, generation: int | None = None) -> None:
        with self._state_lock:
            if generation is not None and (self._closed or generation != self._generation):
                return
            listener = self._capacity_listener
            capacity = len(self._ready_slot_ids)
        if listener is not None:
            listener(capacity)

    def _refresh_capacity_policy(self) -> None:
        adaptive_capacity = self._adaptive_capacity
        if adaptive_capacity is None:
            return
        with self._state_lock:
            if not self._adaptive_refresh_enabled:
                return
        with self._metrics_lock:
            outcomes = sum(self._decisions.values()) + self._failures + self._timeouts
            failure_rate = (self._failures + self._timeouts) / outcomes if outcomes else 0.0
        with self._state_lock:
            process_ids = (
                os.getpid(),
                *(
                    process.pid
                    for process in (slot.process for slot in self._all_slots.values())
                    if process.pid is not None
                ),
            )
        rss_bytes = (
            self._rss_bytes_provider() if self._rss_bytes_provider is not None else process_tree_rss_bytes(process_ids)
        )
        target = adaptive_capacity.refresh(failure_rate=failure_rate, rss_bytes=rss_bytes)
        with self._state_lock:
            if self._closed or target == self._capacity_target:
                return
            self._capacity_target = target
        self._recovery_event.set()
        self._trim_excess_ready_capacity()
