from __future__ import annotations

import multiprocessing
import os
import queue
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import final

from .hook_process_entrypoint import hook_worker_main
from .hook_process_protocol import (
    HOOK_ENV_ALLOWLIST,
    as_string_object_dict,
    is_pair,
)
from .hook_process_worker import HookProcessReview, HookWorkerSlot, retire_worker_slot

_HOOK_PROCESS_LIMIT = 4
_HOOK_PROCESS_TIMEOUT_SECONDS = 2.8
_HOOK_PROCESS_READY_TIMEOUT_SECONDS = 14.0
_HOOK_PROCESS_ACQUIRE_TIMEOUT_SECONDS = 0.2
_HOOK_PROCESS_BACKFILL_DELAY_SECONDS = 2.0
_HOOK_PROCESS_BACKFILL_MAX_DEFERRAL_SECONDS = 5.0
_HOOK_PROCESS_RETRY_MAX_SECONDS = 5.0
_HOOK_PROCESS_CLOSE_REVIEW_TIMEOUT_SECONDS = 1.0


@final
class HookProcessRunner:
    def __init__(
        self,
        *,
        guard_home: Path | None = None,
        process_limit: int = _HOOK_PROCESS_LIMIT,
        timeout_seconds: float = _HOOK_PROCESS_TIMEOUT_SECONDS,
    ):
        if process_limit < 1:
            raise ValueError("process_limit must be positive")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._guard_home: Path | None = guard_home.resolve(strict=False) if guard_home is not None else None
        self._process_limit: int = process_limit
        self._timeout_seconds: float = timeout_seconds
        self._slots: queue.Queue[HookWorkerSlot] = queue.Queue(maxsize=process_limit)
        self._all_slots: dict[int, HookWorkerSlot] = {}
        self._recovery_event: threading.Event = threading.Event()
        self._spawn_threads: set[threading.Thread] = set()
        self._supervisor_thread: threading.Thread | None = None
        self._retirement_threads: set[threading.Thread] = set()
        self._state_lock: threading.Lock = threading.Lock()
        self._metrics_lock: threading.Lock = threading.Lock()
        self._generation: int = 0
        self._capacity_target: int = process_limit
        self._backfill_not_before: float = 0.0
        self._backfill_force_after: float = 0.0
        self._active_reviews: dict[int, int] = {}
        self._closed: bool = False
        self._started: bool = False
        self._timeouts: int = 0
        self._failures: int = 0
        self._restarts: int = 0

    def start(self, *, defer_backfill: bool = False) -> None:
        with self._state_lock:
            if self._started and not self._closed:
                return
            if self._closed:
                if self._all_slots or self._spawn_threads or self._retirement_threads or self._active_reviews:
                    raise RuntimeError("previous hook worker generation is not contained")
                self._slots = queue.Queue(maxsize=self._process_limit)
            self._recovery_event.clear()
            self._generation += 1
            generation = self._generation
            self._capacity_target = 1 if defer_backfill else self._process_limit
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

    def enable_full_capacity(self, *, delay_seconds: float = _HOOK_PROCESS_BACKFILL_DELAY_SECONDS) -> None:
        with self._state_lock:
            if self._closed or not self._started:
                return
            now = time.monotonic()
            self._capacity_target = self._process_limit
            self._backfill_not_before = now + max(0.0, delay_seconds)
            self._backfill_force_after = self._backfill_not_before + _HOOK_PROCESS_BACKFILL_MAX_DEFERRAL_SECONDS
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
    ) -> HookProcessReview:
        with self._state_lock:
            if self._closed:
                return HookProcessReview(None, "daemon_hook_process_closed")
            if not self._started:
                return HookProcessReview(None, "daemon_hook_process_not_ready")
            generation = self._generation
            self._active_reviews[generation] = self._active_reviews.get(generation, 0) + 1
        started_at = time.monotonic()
        try:
            try:
                slot = self._slots.get(timeout=min(_HOOK_PROCESS_ACQUIRE_TIMEOUT_SECONDS, self._timeout_seconds))
            except queue.Empty:
                return HookProcessReview(None, "daemon_hook_process_overloaded")
            try:
                request = {
                    "payload": dict(payload),
                    "harness": harness,
                    "home_dir": str(home_dir),
                    "guard_home": str(guard_home),
                    "workspace": str(workspace) if workspace is not None else None,
                    "hook_env": {key: value for key, value in hook_env.items() if key in HOOK_ENV_ALLOWLIST},
                }
                slot.connection.send(("review", request))
                remaining_seconds = max(0.0, self._timeout_seconds - (time.monotonic() - started_at))
                if not slot.connection.poll(remaining_seconds):
                    self._increment_metric("timeouts")
                    self._replace_slot_async(slot)
                    return HookProcessReview(None, "daemon_hook_process_timeout")
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
            if return_slot:
                self._slots.put_nowait(slot)
        if not return_slot:
            self._replace_slot_async(slot)
        typed_result = as_string_object_dict(result)
        if typed_result is None:
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
        reason_code = typed_result.get("reason_code")
        response = typed_result.get("payload")
        if response is None:
            return HookProcessReview(
                None,
                reason_code if isinstance(reason_code, str) else "daemon_hook_process_failed",
            )
        typed_response = as_string_object_dict(response)
        if typed_response is None:
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
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

    def stats(self) -> dict[str, int]:
        with self._state_lock:
            worker_count = len(self._all_slots)
        with self._metrics_lock:
            return {
                "configured": self._process_limit,
                "workers": worker_count,
                "ready": self._slots.qsize(),
                "timeouts": self._timeouts,
                "failures": self._failures,
                "restarts": self._restarts,
            }

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
        active_review_deadline = time.monotonic() + _HOOK_PROCESS_CLOSE_REVIEW_TIMEOUT_SECONDS
        while True:
            with self._state_lock:
                if not self._active_reviews:
                    break
            remaining = active_review_deadline - time.monotonic()
            if remaining <= 0:
                break
            _ = self._recovery_event.wait(timeout=min(0.05, remaining))
            self._recovery_event.clear()
        with self._state_lock:
            if supervisor is not None and not supervisor.is_alive():
                self._supervisor_thread = None
            contained = not self._all_slots and not self._retirement_threads
            contained = contained and not self._spawn_threads and not self._active_reviews
            contained = contained and self._supervisor_thread is None
        return contained

    def _start_slot(self, *, generation: int) -> HookWorkerSlot:
        context = multiprocessing.get_context("spawn")
        parent_connection, child_connection = context.Pipe(duplex=True)
        process = context.Process(
            target=hook_worker_main,
            args=(child_connection, str(self._guard_home) if self._guard_home is not None else None),
            name="hol-guard-hook-worker",
            daemon=False,
        )
        try:
            process.start()
        except BaseException:
            parent_connection.close()
            child_connection.close()
            raise
        child_connection.close()
        slot = HookWorkerSlot(
            process=process,
            connection=parent_connection,
            isolation_ready=False,
        )
        with self._state_lock:
            stale = self._closed or generation != self._generation
            if not stale:
                self._all_slots[process.pid or id(slot)] = slot
        if stale:
            _ = self._slot_became_isolated(slot, _HOOK_PROCESS_READY_TIMEOUT_SECONDS)
            if not self._retire_slot(slot):
                with self._state_lock:
                    self._all_slots[process.pid or id(slot)] = slot
                self._mark_containment_failed()
        return slot

    @staticmethod
    def _slot_became_isolated(slot: HookWorkerSlot, timeout: float) -> bool:
        if timeout <= 0:
            return False
        try:
            if not slot.connection.poll(timeout):
                return False
            message = slot.connection.recv()
            if message == ("isolation_failed", None):
                slot.pre_isolation_contained = True
                return False
            if not is_pair(message) or message[0] != "isolated":
                return False
            proof = as_string_object_dict(message[1])
            if proof is None:
                return False
            if os.name == "nt":
                if proof.get("windows_job_contained") is not True:
                    return False
                slot.windows_job_contained = True
            elif proof.get("process_group_id") != slot.process.pid:
                return False
            slot.isolation_ready = True
            return True
        except (EOFError, OSError):
            return False

    @classmethod
    def _slot_became_ready(cls, slot: HookWorkerSlot, timeout: float) -> bool:
        if timeout <= 0:
            return False
        deadline = time.monotonic() + timeout
        if not slot.isolation_ready and not cls._slot_became_isolated(slot, timeout):
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            return slot.connection.poll(remaining) and slot.connection.recv() == ("ready", None)
        except (EOFError, OSError):
            return False

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
                timeout = min(0.05, capacity_delay) if capacity_delay > 0 else None
                _ = self._recovery_event.wait(timeout=timeout)
                self._recovery_event.clear()
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
            if not self._slot_became_ready(replacement, _HOOK_PROCESS_READY_TIMEOUT_SECONDS):
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
        def retire() -> None:
            try:
                if not self._retire_slot(slot):
                    self._mark_containment_failed()
                    return
                self._increment_metric("restarts")
                self._recovery_event.set()
            finally:
                with self._state_lock:
                    self._retirement_threads.discard(threading.current_thread())

        thread = threading.Thread(target=retire, name="hol-guard-hook-worker-retire", daemon=True)
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

    def _retire_slot(self, slot: HookWorkerSlot, *, graceful: bool = False) -> bool:
        contained = retire_worker_slot(slot, graceful=graceful)
        if contained:
            with self._state_lock:
                _ = self._all_slots.pop(slot.process.pid or id(slot), None)
            with suppress(OSError):
                slot.connection.close()
        return contained


__all__ = ["HookProcessReview", "HookProcessRunner"]
