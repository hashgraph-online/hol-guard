from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import final

from .hook_process_capacity import (
    AdaptiveHookProcessCapacity,
    HookProcessStats,
    initial_hook_worker_target,
    process_cpu_ratio,
)
from .hook_process_protocol import as_string_object_dict, is_pair
from .hook_process_request import build_hook_process_review_request, runtime_hook_review_is_idempotent
from .hook_process_runner_lifecycle import _HOOK_PROCESS_READY_TIMEOUT_SECONDS, HookProcessRunnerLifecycleMixin
from .hook_process_slot_review import review_hook_worker_slot
from .hook_process_spawner import hook_worker_became_isolated, hook_worker_became_ready, spawn_hook_worker
from .hook_process_worker import HookProcessReview, HookWorkerSlot, worker_retirement_thread

_HOOK_PROCESS_MAX_LIMIT = 16
_HOOK_PROCESS_TIMEOUT_SECONDS = 2.8
_HOOK_PROCESS_START_TIMEOUT_SECONDS = 30.0
_HOOK_PROCESS_BACKFILL_DELAY_SECONDS = 2.0
_HOOK_PROCESS_BACKFILL_MAX_DEFERRAL_SECONDS = 5.0
_HOOK_PROCESS_RETRY_MAX_SECONDS = 5.0
_HOOK_PROCESS_RETRY_READY_SECONDS = 0.75
_HOOK_PROCESS_TRANSIENT_NOT_READY_RETRIES = 8
_HOOK_PROCESS_TRANSIENT_NOT_READY_BACKOFF_SECONDS = 0.025
_HOOK_PROCESS_CLOSE_CONTAINMENT_GRACE_SECONDS = 4.0


@final
class HookProcessRunner(HookProcessRunnerLifecycleMixin):
    def __init__(
        self,
        *,
        guard_home: Path | None = None,
        process_limit: int | None = None,
        timeout_seconds: float = _HOOK_PROCESS_TIMEOUT_SECONDS,
        capacity_listener: Callable[[int], None] | None = None,
        cpu_ratio_provider: Callable[[], float | None] = process_cpu_ratio,
        rss_bytes_provider: Callable[[], int | None] | None = None,
        memory_ceiling_bytes: int | None = None,
    ):
        if process_limit is not None and process_limit < 1:
            raise ValueError("process_limit must be positive")
        if process_limit is not None and process_limit > _HOOK_PROCESS_MAX_LIMIT:
            raise ValueError("process_limit must not exceed 16")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._guard_home: Path | None = guard_home.resolve(strict=False) if guard_home is not None else None
        initial_target = process_limit if process_limit is not None else initial_hook_worker_target()
        self._process_limit: int = process_limit if process_limit is not None else _HOOK_PROCESS_MAX_LIMIT
        self._timeout_seconds: float = timeout_seconds
        self._slots: queue.Queue[HookWorkerSlot] = queue.Queue(maxsize=self._process_limit)
        self._all_slots: dict[int, HookWorkerSlot] = {}
        self._recovery_event: threading.Event = threading.Event()
        self._spawn_threads: set[threading.Thread] = set()
        self._supervisor_thread: threading.Thread | None = None
        self._retirement_threads: set[threading.Thread] = set()
        self._state_lock: threading.Lock = threading.Lock()
        self._metrics_lock: threading.Lock = threading.Lock()
        self._generation: int = 0
        self._capacity_target: int = initial_target
        self._initial_target: int = initial_target
        self._startup_floor_target: int = 0
        self._ready_slot_ids: set[int] = set()
        self._capacity_listener = capacity_listener
        self._rss_bytes_provider = rss_bytes_provider
        self._adaptive_capacity = (
            AdaptiveHookProcessCapacity(
                initial_target=initial_target,
                maximum_target=self._process_limit,
                memory_ceiling_bytes=memory_ceiling_bytes,
                cpu_ratio_provider=cpu_ratio_provider,
            )
            if process_limit is None
            else None
        )
        self._backfill_not_before: float = 0.0
        self._backfill_force_after: float = 0.0
        self._adaptive_refresh_enabled: bool = True
        self._active_reviews: dict[int, int] = {}
        self._closed: bool = False
        self._started: bool = False
        self._timeouts: int = 0
        self._failures: int = 0
        self._restarts: int = 0
        self._decisions: dict[str, int] = {}
        self._reason_codes: dict[str, int] = {}
        self._routes: dict[str, int] = {}

    def start(self, *, defer_backfill: bool = False) -> None:
        nonblocking_deferred_start = defer_backfill and self._adaptive_capacity is not None
        with self._state_lock:
            if self._started and not self._closed:
                return
            if self._closed:
                if self._all_slots or self._spawn_threads or self._retirement_threads or self._active_reviews:
                    raise RuntimeError("previous hook worker generation is not contained")
                self._slots = queue.Queue(maxsize=self._process_limit)
                self._ready_slot_ids.clear()
            self._recovery_event.clear()
            self._generation += 1
            generation = self._generation
            startup_floor_target = min(2, self._initial_target) if defer_backfill else self._initial_target
            self._capacity_target = startup_floor_target
            self._startup_floor_target = startup_floor_target if nonblocking_deferred_start else 0
            self._adaptive_refresh_enabled = not defer_backfill
            now = time.monotonic()
            self._backfill_not_before = (
                now + _HOOK_PROCESS_BACKFILL_DELAY_SECONDS if nonblocking_deferred_start else 0.0
            )
            self._backfill_force_after = (
                self._backfill_not_before + _HOOK_PROCESS_BACKFILL_MAX_DEFERRAL_SECONDS
                if nonblocking_deferred_start
                else 0.0
            )
            self._closed = False
            self._started = True
            supervisor = threading.Thread(
                target=lambda: self._supervise_capacity(generation),
                name="hol-guard-hook-worker-supervisor",
                daemon=True,
            )
            self._supervisor_thread = supervisor
            try:
                supervisor.start()
            except RuntimeError:
                self._supervisor_thread = None
                self._started = False
                self._closed = True
                self._generation += 1
                self._increment_metric("failures")
                return
        if nonblocking_deferred_start:
            return
        _ = self.wait_for_capacity(
            minimum_workers=self._capacity_target,
            timeout_seconds=_HOOK_PROCESS_START_TIMEOUT_SECONDS,
        )

    def enable_full_capacity(
        self,
        *,
        delay_seconds: float = _HOOK_PROCESS_BACKFILL_DELAY_SECONDS,
        active_deferral_seconds: float | None = None,
    ) -> None:
        if active_deferral_seconds is None:
            active_deferral_seconds = _HOOK_PROCESS_BACKFILL_MAX_DEFERRAL_SECONDS
        if active_deferral_seconds < 0:
            raise ValueError("active_deferral_seconds must not be negative")
        with self._state_lock:
            if self._closed or not self._started:
                return
            now = time.monotonic()
            self._capacity_target = self._initial_target
            self._adaptive_refresh_enabled = True
            requested_not_before = now + max(0.0, delay_seconds)
            self._backfill_not_before = max(self._backfill_not_before, requested_not_before)
            self._backfill_force_after = max(
                self._backfill_force_after,
                self._backfill_not_before + active_deferral_seconds,
            )
        self._recovery_event.set()

    def review(
        self,
        *,
        payload: Mapping[str, object],
        harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        hook_env: Mapping[str, str],
        deadline: float | None = None,
        claim_saved_approval: bool = True,
        claimed_saved_allow_hash: str | None = None,
        claimed_trusted_request_override: bool = False,
        claimed_approval_request_id: str | None = None,
        _transient_not_ready_retries: int = _HOOK_PROCESS_TRANSIENT_NOT_READY_RETRIES,
    ) -> HookProcessReview:
        with self._state_lock:
            if self._closed:
                return HookProcessReview(None, "daemon_hook_process_closed")
            if not self._started:
                return HookProcessReview(None, "daemon_hook_process_not_ready")
            generation = self._generation
            self._active_reviews[generation] = self._active_reviews.get(generation, 0) + 1
        outer_deadline = deadline if deadline is not None else float("inf")
        worker_deadline = time.monotonic() + self._timeout_seconds
        review_deadline = min(worker_deadline, outer_deadline)
        caller_deadline_limited = outer_deadline <= worker_deadline
        request = build_hook_process_review_request(
            payload=payload,
            harness=harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            hook_env=hook_env,
            claim_saved_approval=claim_saved_approval,
            claimed_saved_allow_hash=claimed_saved_allow_hash,
            claimed_trusted_request_override=claimed_trusted_request_override,
            claimed_approval_request_id=claimed_approval_request_id,
        )
        try:
            if review_deadline <= time.monotonic():
                return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
            try:
                slot = (
                    self._slots.get(
                        timeout=min(
                            _HOOK_PROCESS_RETRY_READY_SECONDS,
                            max(0.0, review_deadline - time.monotonic()),
                        )
                    )
                    if deadline is not None
                    else self._slots.get_nowait()
                )
            except queue.Empty:
                return HookProcessReview(None, "daemon_hook_process_not_ready")
            review_result = review_hook_worker_slot(
                slot=slot,
                request=request,
                payload=payload,
                review_deadline=review_deadline,
                caller_deadline_limited=caller_deadline_limited,
                ready_slots=self._slots,
                replace_slot=self._replace_slot_async,
                increment_metric=self._increment_metric,
                wait_for_capacity=lambda minimum, timeout: self.wait_for_capacity(
                    minimum_workers=minimum,
                    timeout_seconds=timeout,
                ),
            )
            if isinstance(review_result, HookProcessReview):
                return review_result
            slot, raw_message = review_result
        finally:
            with self._state_lock:
                remaining_reviews = self._active_reviews.get(generation, 0) - 1
                if remaining_reviews > 0:
                    self._active_reviews[generation] = remaining_reviews
                else:
                    _ = self._active_reviews.pop(generation, None)
            self._recovery_event.set()

        if time.monotonic() >= review_deadline:
            self._replace_slot_async(slot)
            return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
        if not is_pair(raw_message):
            self._increment_metric("failures")
            self._replace_slot_async(slot)
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
        message_type, result = raw_message
        if message_type != "result":
            self._increment_metric("failures")
            self._replace_slot_async(slot)
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
        with self._state_lock:
            return_slot = slot.process.is_alive() and not self._closed and generation == self._generation
            retire_for_scale_down = return_slot and len(self._ready_slot_ids) > self._capacity_target
            if return_slot and not retire_for_scale_down:
                self._slots.put_nowait(slot)
            elif retire_for_scale_down:
                self._ready_slot_ids.discard(slot.process.pid or id(slot))
        if retire_for_scale_down:
            self._publish_capacity()
            self._retire_idle_slot_async(slot)
        elif not return_slot:
            self._replace_slot_async(slot)
        typed_result = as_string_object_dict(result)
        if typed_result is None:
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
        reason_code = typed_result.get("reason_code")
        response = typed_result.get("payload")
        if response is None:
            if (
                _transient_not_ready_retries > 0
                and reason_code == "daemon_hook_process_not_ready"
                and runtime_hook_review_is_idempotent(payload)
                and time.monotonic() < review_deadline
            ):
                time.sleep(
                    min(
                        _HOOK_PROCESS_TRANSIENT_NOT_READY_BACKOFF_SECONDS,
                        max(0.0, review_deadline - time.monotonic()),
                    )
                )
                return self.review(
                    payload=payload,
                    harness=harness,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    workspace=workspace,
                    hook_env=hook_env,
                    deadline=review_deadline,
                    claim_saved_approval=claim_saved_approval,
                    claimed_saved_allow_hash=claimed_saved_allow_hash,
                    claimed_trusted_request_override=claimed_trusted_request_override,
                    claimed_approval_request_id=claimed_approval_request_id,
                    _transient_not_ready_retries=_transient_not_ready_retries - 1,
                )
            return self._terminal_failed_review(typed_result.get("route"), reason_code)
        typed_response = as_string_object_dict(response)
        if typed_response is None:
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
        if time.monotonic() >= review_deadline:
            return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
        self._record_response_metrics(typed_response)
        self._record_route_metric(typed_result.get("route"))
        if time.monotonic() >= review_deadline:
            return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
        return HookProcessReview(typed_response, None)

    def wait_for_capacity(self, *, minimum_workers: int, timeout_seconds: float) -> bool:
        if not 1 <= minimum_workers <= self._process_limit:
            raise ValueError("minimum_workers must be within configured capacity")
        if timeout_seconds < 0:
            raise ValueError("timeout_seconds must not be negative")
        deadline = time.monotonic() + timeout_seconds
        while True:
            with self._state_lock:
                if self._closed or not self._started:
                    return False
                if self._slots.qsize() >= minimum_workers:
                    return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.02, remaining))

    def stats(self) -> HookProcessStats:
        with self._state_lock:
            worker_count = len(self._all_slots)
            usable_count = len(self._ready_slot_ids)
            ready_count = self._slots.qsize()
            target = self._capacity_target
        with self._metrics_lock:
            return {
                "configured": self._process_limit,
                "workers": worker_count,
                "ready": ready_count,
                "busy": max(0, usable_count - ready_count),
                "target": target,
                "timeouts": self._timeouts,
                "failures": self._failures,
                "restarts": self._restarts,
                "decisions": dict(self._decisions),
                "reason_codes": dict(self._reason_codes),
                "routes": dict(self._routes),
            }

    def set_capacity_listener(self, listener: Callable[[int], None]) -> None:
        with self._state_lock:
            self._capacity_listener = listener
            capacity = len(self._ready_slot_ids)
        listener(capacity)

    def observe_load(self, *, queue_p95_ms: float, queued: int) -> None:
        adaptive_capacity = self._adaptive_capacity
        if adaptive_capacity is None:
            return
        adaptive_capacity.observe_load(queue_p95_ms=queue_p95_ms, queued=queued)
        if queued > 0:
            self.notify_queued_work()
        self._refresh_capacity_policy()

    def notify_queued_work(self) -> None:
        with self._state_lock:
            self._backfill_not_before = 0.0
            self._backfill_force_after = 0.0
        self._recovery_event.set()

    def close(self) -> None:
        _ = self.close_contained()

    def close_contained(self) -> bool:
        with self._state_lock:
            self._closed = True
            self._started = False
            self._generation += 1
            self._recovery_event.set()

        containment_grace_seconds = min(
            _HOOK_PROCESS_CLOSE_CONTAINMENT_GRACE_SECONDS,
            _HOOK_PROCESS_READY_TIMEOUT_SECONDS,
        )
        deadline = time.monotonic() + _HOOK_PROCESS_READY_TIMEOUT_SECONDS + containment_grace_seconds
        attempted_slot_ids: set[int] = set()
        while True:
            with self._state_lock:
                slots = list(self._all_slots.values())
                supervisor = self._supervisor_thread
                spawn_threads = list(self._spawn_threads)
                retirement_threads = list(self._retirement_threads)

            for slot in slots:
                slot_id = slot.process.pid or id(slot)
                if slot_id in attempted_slot_ids:
                    continue
                attempted_slot_ids.add(slot_id)
                if not slot.isolation_ready and not slot.pre_isolation_contained:
                    remaining = max(0.0, deadline - time.monotonic())
                    _ = hook_worker_became_isolated(slot, min(_HOOK_PROCESS_READY_TIMEOUT_SECONDS, remaining))
                _ = self._retire_slot(slot, graceful=True)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            for thread in (*retirement_threads, *spawn_threads):
                if thread is not threading.current_thread() and thread.is_alive():
                    thread.join(timeout=min(0.05, remaining))
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
            if remaining > 0 and supervisor is not None and supervisor is not threading.current_thread():
                supervisor.join(timeout=min(0.05, remaining))

            contained, stalled = self._containment_status(attempted_slot_ids)
            if contained:
                return True
            if stalled:
                return False
            _ = self._recovery_event.wait(timeout=min(0.05, max(0.0, deadline - time.monotonic())))
            self._recovery_event.clear()

        return self._containment_status(attempted_slot_ids)[0]

    def _start_slot(self, *, generation: int) -> HookWorkerSlot:
        slot = spawn_hook_worker(self._guard_home)
        process = slot.process
        with self._state_lock:
            stale = self._closed or generation != self._generation
            if not stale:
                self._all_slots[process.pid or id(slot)] = slot
        if stale:
            _ = hook_worker_became_isolated(slot, _HOOK_PROCESS_READY_TIMEOUT_SECONDS)
            if not self._retire_slot(slot):
                with self._state_lock:
                    self._all_slots[process.pid or id(slot)] = slot
                self._mark_containment_failed()
        return slot

    def _supervise_capacity(self, generation: int) -> None:
        retry_delay = 0.05
        while True:
            with self._state_lock:
                closed = self._closed or generation != self._generation
                should_wait = len(self._all_slots) >= self._capacity_target
                startup_floor_pending = len(self._ready_slot_ids) < self._startup_floor_target
                active_reviews = self._active_reviews.get(generation, 0)
                backfill_not_before = self._backfill_not_before
                backfill_force_after = self._backfill_force_after
            if closed:
                return
            now = time.monotonic()
            backfill_delay = 0.0 if startup_floor_pending else max(0.0, backfill_not_before - now)
            active_review_delay = (
                max(0.0, backfill_force_after - now) if active_reviews > 0 and not startup_floor_pending else 0.0
            )
            if should_wait or backfill_delay > 0 or active_review_delay > 0:
                capacity_delay = max(backfill_delay, active_review_delay)
                timeout = min(0.05, capacity_delay) if capacity_delay > 0 else 1.0
                _ = self._recovery_event.wait(timeout=timeout)
                self._recovery_event.clear()
                self._refresh_capacity_policy()
                self._trim_excess_ready_capacity()
                retry_delay = 0.05
                continue
            self._recovery_event.clear()
            replacement = self._start_slot_interruptibly(generation)
            if replacement is None:
                self._recovery_event.clear()
                with self._state_lock:
                    closed = self._closed or generation != self._generation
                if closed:
                    return
                _ = self._recovery_event.wait(timeout=retry_delay)
                retry_delay = min(retry_delay * 2, _HOOK_PROCESS_RETRY_MAX_SECONDS)
                continue
            ready = hook_worker_became_ready(replacement, _HOOK_PROCESS_READY_TIMEOUT_SECONDS)
            with self._state_lock:
                cancelled = self._closed or generation != self._generation
                if not cancelled and not ready:
                    self._increment_metric("failures")
            if cancelled:
                return
            if not ready:
                if not self._retire_slot(replacement):
                    self._mark_containment_failed()
                    return
                self._recovery_event.clear()
                _ = self._recovery_event.wait(timeout=retry_delay)
                retry_delay = min(retry_delay * 2, _HOOK_PROCESS_RETRY_MAX_SECONDS)
                continue
            queue_full = False
            with self._state_lock:
                if self._closed or generation != self._generation:
                    return
                try:
                    self._slots.put_nowait(replacement)
                except queue.Full:
                    queue_full = True
                else:
                    self._ready_slot_ids.add(replacement.process.pid or id(replacement))
                    if len(self._ready_slot_ids) >= self._startup_floor_target:
                        self._startup_floor_target = 0
            if queue_full and not self._retire_slot(replacement):
                self._mark_containment_failed()
                return
            self._publish_capacity(generation=generation)
            retry_delay = 0.05

    def _start_slot_interruptibly(self, generation: int) -> HookWorkerSlot | None:
        outcomes: queue.Queue[HookWorkerSlot | BaseException] = queue.Queue(maxsize=1)

        def attempt() -> None:
            try:
                outcomes.put(self._start_slot(generation=generation))
            except BaseException as error:
                outcomes.put(error)
            finally:
                with self._state_lock:
                    self._spawn_threads.discard(threading.current_thread())
                self._recovery_event.set()

        thread = threading.Thread(target=attempt, name="hol-guard-hook-worker-spawn", daemon=True)
        start_failed = False
        with self._state_lock:
            if self._closed or generation != self._generation:
                return None
            self._spawn_threads.add(thread)
            try:
                thread.start()
            except RuntimeError:
                self._spawn_threads.discard(thread)
                start_failed = True
        if start_failed:
            self._increment_metric("failures")
            return None
        cancelled = False
        while thread.is_alive():
            _ = self._recovery_event.wait(timeout=0.05)
            with self._state_lock:
                cancelled = cancelled or self._closed or generation != self._generation
            if cancelled:
                return None
        with self._state_lock:
            cancelled = cancelled or self._closed or generation != self._generation
        outcome = outcomes.get_nowait()
        if isinstance(outcome, BaseException):
            if not cancelled:
                self._increment_metric("failures")
            return None
        if cancelled:
            return None
        return outcome

    def _replace_slot_async(self, slot: HookWorkerSlot) -> None:
        self._withdraw_slot_capacity(slot)

        def contained() -> None:
            with self._state_lock:
                slot_id = slot.process.pid or id(slot)
                _ = self._all_slots.pop(slot_id, None)
                self._ready_slot_ids.discard(slot_id)
            with suppress(OSError):
                slot.connection.close()
            self._publish_capacity()
            self._increment_metric("restarts")
            self._recovery_event.set()

        thread = worker_retirement_thread(
            slot,
            graceful=False,
            name="hol-guard-hook-worker-retire",
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


__all__ = ["HookProcessReview", "HookProcessRunner"]
