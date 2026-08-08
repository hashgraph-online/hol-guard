from __future__ import annotations

import os
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
    process_tree_rss_bytes,
)
from .hook_process_metrics import increment_bounded_metric
from .hook_process_protocol import (
    HOOK_ENV_ALLOWLIST,
    as_string_object_dict,
    is_pair,
)
from .hook_process_spawner import hook_worker_became_isolated, hook_worker_became_ready, spawn_hook_worker
from .hook_process_worker import (
    HookProcessReview,
    HookWorkerSlot,
    retire_worker_slot,
    worker_retirement_thread,
)

_HOOK_PROCESS_MAX_LIMIT = 16
_HOOK_PROCESS_TIMEOUT_SECONDS = 2.8
_HOOK_PROCESS_READY_TIMEOUT_SECONDS = 14.0
_HOOK_PROCESS_BACKFILL_DELAY_SECONDS = 2.0
_HOOK_PROCESS_BACKFILL_MAX_DEFERRAL_SECONDS = 5.0
_HOOK_PROCESS_RETRY_MAX_SECONDS = 5.0
_HOOK_PROCESS_RETRY_READY_SECONDS = 0.75
_HOOK_PROCESS_TRANSIENT_NOT_READY_RETRIES = 2
_HOOK_PROCESS_TRANSIENT_NOT_READY_BACKOFF_SECONDS = 0.025


@final
class HookProcessRunner:
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

    def start(self, *, defer_backfill: bool = False) -> None:
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
            self._capacity_target = min(2, self._initial_target) if defer_backfill else self._initial_target
            self._adaptive_refresh_enabled = not defer_backfill
            self._backfill_not_before = 0.0
            self._backfill_force_after = 0.0
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
        _ = self.wait_for_capacity(
            minimum_workers=self._capacity_target,
            timeout_seconds=_HOOK_PROCESS_READY_TIMEOUT_SECONDS,
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
            self._backfill_not_before = now + max(0.0, delay_seconds)
            self._backfill_force_after = self._backfill_not_before + active_deferral_seconds
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
        request = {
            "payload": dict(payload),
            "harness": harness,
            "home_dir": str(home_dir),
            "guard_home": str(guard_home),
            "workspace": str(workspace) if workspace is not None else None,
            "hook_env": {key: value for key, value in hook_env.items() if key in HOOK_ENV_ALLOWLIST},
        }
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
            try:
                slot.connection.send(("review", request))
                remaining_seconds = max(0.0, review_deadline - time.monotonic())
                if not slot.connection.poll(remaining_seconds):
                    self._replace_slot_async(slot)
                    if caller_deadline_limited:
                        return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
                    self._increment_metric("timeouts")
                    return HookProcessReview(None, "daemon_hook_process_timeout")
                raw_message = slot.connection.recv()
            except (BrokenPipeError, EOFError, OSError):
                self._increment_metric("failures")
                retry_slot: HookWorkerSlot | None = None
                if _runtime_hook_review_is_idempotent(payload):
                    with suppress(queue.Empty):
                        retry_slot = self._slots.get_nowait()
                self._replace_slot_async(slot)
                if not _runtime_hook_review_is_idempotent(payload):
                    return HookProcessReview(None, "daemon_hook_process_failed")
                if retry_slot is None:
                    remaining_seconds = max(0.0, review_deadline - time.monotonic())
                    if not self.wait_for_capacity(
                        minimum_workers=1,
                        timeout_seconds=min(_HOOK_PROCESS_RETRY_READY_SECONDS, remaining_seconds),
                    ):
                        reason_code = (
                            "daemon_hook_process_deadline_exhausted"
                            if time.monotonic() >= review_deadline
                            else "daemon_hook_process_failed"
                        )
                        return HookProcessReview(None, reason_code)
                    try:
                        retry_slot = self._slots.get_nowait()
                    except queue.Empty:
                        return HookProcessReview(None, "daemon_hook_process_failed")
                slot = retry_slot
                try:
                    slot.connection.send(("review", request))
                    remaining_seconds = max(0.0, review_deadline - time.monotonic())
                    if not slot.connection.poll(remaining_seconds):
                        self._replace_slot_async(slot)
                        return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
                    raw_message = slot.connection.recv()
                except (BrokenPipeError, EOFError, OSError):
                    self._increment_metric("failures")
                    self._replace_slot_async(slot)
                    return HookProcessReview(None, "daemon_hook_process_failed")
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
                and _runtime_hook_review_is_idempotent(payload)
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
                    _transient_not_ready_retries=_transient_not_ready_retries - 1,
                )
            return HookProcessReview(
                None,
                reason_code if isinstance(reason_code, str) else "daemon_hook_process_failed",
            )
        typed_response = as_string_object_dict(response)
        if typed_response is None:
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
        if time.monotonic() >= review_deadline:
            return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
        self._record_response_metrics(typed_response)
        accepted_review = HookProcessReview(typed_response, None)
        if time.monotonic() >= review_deadline:
            return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
        return accepted_review

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
        self._refresh_capacity_policy()

    def close(self) -> None:
        _ = self.close_contained()

    def close_contained(self) -> bool:
        with self._state_lock:
            self._closed = True
            self._started = False
            self._generation += 1
            slots = list(self._all_slots.values())
            supervisor = self._supervisor_thread
            spawn_threads = list(self._spawn_threads)
            retirement_threads = list(self._retirement_threads)
            self._recovery_event.set()
        for slot in slots:
            _ = self._retire_slot(slot, graceful=True)
        for retirement_thread in retirement_threads:
            if retirement_thread is not threading.current_thread():
                retirement_thread.join(timeout=3.0)
        if supervisor is not None:
            supervisor.join(timeout=1.0)
        for spawn_thread in spawn_threads:
            if spawn_thread is not threading.current_thread():
                spawn_thread.join(timeout=0.2)
        with self._state_lock:
            if supervisor is not None and not supervisor.is_alive():
                self._supervisor_thread = None
            contained = not self._all_slots and not self._retirement_threads
            contained = contained and not self._spawn_threads and not self._active_reviews
            contained = contained and self._supervisor_thread is None
        return contained

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
                active_reviews = self._active_reviews.get(generation, 0)
                backfill_not_before = self._backfill_not_before
                backfill_force_after = self._backfill_force_after
            if closed:
                return
            now = time.monotonic()
            backfill_delay = max(0.0, backfill_not_before - now)
            active_review_delay = max(0.0, backfill_force_after - now) if active_reviews > 0 else 0.0
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
                with self._state_lock:
                    closed = self._closed or generation != self._generation
                if closed:
                    return
                _ = self._recovery_event.wait(timeout=retry_delay)
                retry_delay = min(retry_delay * 2, _HOOK_PROCESS_RETRY_MAX_SECONDS)
                continue
            if not hook_worker_became_ready(replacement, _HOOK_PROCESS_READY_TIMEOUT_SECONDS):
                self._increment_metric("failures")
                if not self._retire_slot(replacement):
                    self._mark_containment_failed()
                    return
                _ = self._recovery_event.wait(timeout=retry_delay)
                retry_delay = min(retry_delay * 2, _HOOK_PROCESS_RETRY_MAX_SECONDS)
                continue
            try:
                self._slots.put_nowait(replacement)
            except queue.Full:
                if not self._retire_slot(replacement):
                    self._mark_containment_failed()
                    return
            with self._state_lock:
                self._ready_slot_ids.add(replacement.process.pid or id(replacement))
            self._publish_capacity()
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
        while thread.is_alive():
            _ = self._recovery_event.wait(timeout=0.05)
            with self._state_lock:
                if self._closed or generation != self._generation:
                    return None
        outcome = outcomes.get_nowait()
        if isinstance(outcome, BaseException):
            self._increment_metric("failures")
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

    def _publish_capacity(self) -> None:
        with self._state_lock:
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


def _runtime_hook_review_is_idempotent(payload: Mapping[str, object]) -> bool:
    event_name = payload.get("hook_event_name") or payload.get("hookEventName")
    if not isinstance(event_name, str):
        return False
    return any(
        isinstance(payload.get(identity_key), str) and bool(payload.get(identity_key))
        for identity_key in ("tool_call_id", "toolCallId", "action_id", "operation_id")
    )


__all__ = ["HookProcessReview", "HookProcessRunner"]
