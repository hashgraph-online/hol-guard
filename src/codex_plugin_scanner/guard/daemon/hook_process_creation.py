"""Ownership-aware creation of isolated hook workers."""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .hook_process_spawner import hook_worker_became_isolated
from .hook_process_worker import HookWorkerSlot

if TYPE_CHECKING:
    from .hook_process_runner import HookProcessRunner


@dataclass(frozen=True, slots=True)
class WorkerBatchResult:
    started: bool
    cancelled: bool
    retry_after_batch: bool


def start_hook_worker_slot(
    runner: HookProcessRunner,
    *,
    generation: int,
    spawn: Callable[[Path | None], HookWorkerSlot],
    isolation_timeout: float,
) -> HookWorkerSlot:
    """Create and register one slot without allowing close to split ownership."""

    with runner._process_creation_lock:
        with runner._state_lock:
            if runner._closed or generation != runner._generation:
                raise RuntimeError("hook worker creation cancelled")
        slot = spawn(runner._guard_home)
        process = slot.process
        with runner._state_lock:
            stale = runner._closed or generation != runner._generation
            if not stale:
                runner._all_slots[process.pid or id(slot)] = slot
        if stale:
            _ = hook_worker_became_isolated(slot, isolation_timeout)
            if not runner._retire_slot(slot):
                with runner._state_lock:
                    runner._all_slots[process.pid or id(slot)] = slot
                runner._mark_containment_failed()
        return slot


def start_hook_worker_slots_interruptibly(
    runner: HookProcessRunner,
    *,
    generation: int,
    count: int,
) -> list[HookWorkerSlot]:
    """Start a bounded batch while keeping every spawn owned by the runner."""

    if count <= 0:
        return []
    if count == 1:
        replacement = runner._start_slot_interruptibly(generation)
        return [] if replacement is None else [replacement]
    outcomes: queue.Queue[HookWorkerSlot | BaseException] = queue.Queue(maxsize=count)
    threads: list[threading.Thread] = []

    def attempt() -> None:
        try:
            outcomes.put(runner._start_slot(generation=generation))
        except BaseException as error:
            outcomes.put(error)
        finally:
            with runner._state_lock:
                runner._spawn_threads.discard(threading.current_thread())
            runner._recovery_event.set()

    with runner._state_lock:
        if runner._closed or generation != runner._generation:
            return []
        for index in range(count):
            thread = threading.Thread(
                target=attempt,
                name=f"hol-guard-hook-worker-spawn-{index}",
                daemon=True,
            )
            threads.append(thread)
            runner._spawn_threads.add(thread)
            try:
                thread.start()
            except RuntimeError as error:
                runner._spawn_threads.discard(thread)
                outcomes.put(error)

    cancelled = False
    while any(thread.is_alive() for thread in threads):
        with runner._state_lock:
            cancelled = cancelled or runner._closed or generation != runner._generation
        if cancelled:
            return []
        _ = runner._recovery_event.wait(timeout=0.05)
        runner._recovery_event.clear()
    with runner._state_lock:
        cancelled = cancelled or runner._closed or generation != runner._generation

    slots: list[HookWorkerSlot] = []
    for _ in range(count):
        outcome = outcomes.get_nowait()
        if isinstance(outcome, BaseException):
            if not cancelled:
                runner._increment_metric("failures")
            continue
        slots.append(outcome)
    return [] if cancelled else slots


def wait_for_startup_capacity_release(
    runner: HookProcessRunner,
    *,
    generation: int,
    slots_needed: int,
) -> bool:
    """Hold parallel retry until the caller's bounded startup wait completes."""

    if slots_needed <= 1:
        return True
    with runner._state_lock:
        closed = runner._closed or generation != runner._generation
        startup_capacity_waiting = runner._startup_capacity_waiting
    if closed:
        return False
    while startup_capacity_waiting:
        _ = runner._recovery_event.wait(timeout=0.05)
        runner._recovery_event.clear()
        with runner._state_lock:
            closed = runner._closed or generation != runner._generation
            startup_capacity_waiting = runner._startup_capacity_waiting
        if closed:
            return False
    runner._recovery_event.clear()
    return True


def backoff_after_failed_worker_batch(
    runner: HookProcessRunner,
    *,
    generation: int,
    slots_needed: int,
    retry_delay: float,
    start_timeout: float,
    max_retry_delay: float,
) -> float | None:
    """Back off failed startup without retrying parallel work during start()."""

    runner._recovery_event.clear()
    with runner._state_lock:
        if runner._closed or generation != runner._generation:
            return None
    if not wait_for_startup_capacity_release(
        runner,
        generation=generation,
        slots_needed=slots_needed,
    ):
        return None
    if slots_needed > 1:
        retry_delay = min(max(retry_delay, start_timeout), max_retry_delay)
    _ = runner._recovery_event.wait(timeout=retry_delay)
    if slots_needed > 1:
        return min(max(retry_delay * 2, start_timeout), max_retry_delay)
    return min(retry_delay * 2, max_retry_delay)


def admit_hook_worker_batch(
    runner: HookProcessRunner,
    *,
    generation: int,
    count: int,
    ready: Callable[[HookWorkerSlot, float], bool],
    ready_timeout: float,
) -> WorkerBatchResult:
    """Start, ready, and enqueue a bounded worker batch under runner ownership."""

    replacements = runner._start_slots_interruptibly(generation, count)
    if not replacements:
        with runner._state_lock:
            cancelled = runner._closed or generation != runner._generation
        return WorkerBatchResult(False, cancelled, False)

    retry_after_batch = False
    for replacement in replacements:
        is_ready = ready(replacement, ready_timeout)
        with runner._state_lock:
            cancelled = runner._closed or generation != runner._generation
            if not cancelled and not is_ready:
                runner._increment_metric("failures")
        if cancelled:
            return WorkerBatchResult(True, True, retry_after_batch)
        if not is_ready:
            if not runner._retire_slot(replacement):
                runner._mark_containment_failed()
                return WorkerBatchResult(True, True, retry_after_batch)
            retry_after_batch = True
            continue

        with runner._state_lock:
            if runner._closed or generation != runner._generation:
                return WorkerBatchResult(True, True, retry_after_batch)
            try:
                runner._slots.put_nowait(replacement)
            except queue.Full:
                queue_full = True
            else:
                queue_full = False
                runner._ready_slot_ids.add(replacement.process.pid or id(replacement))
                if len(runner._ready_slot_ids) >= runner._startup_floor_target:
                    runner._startup_floor_target = 0
        if queue_full:
            if not runner._retire_slot(replacement):
                runner._mark_containment_failed()
                return WorkerBatchResult(True, True, retry_after_batch)
            retry_after_batch = True
            continue
        runner._publish_capacity(generation=generation)
    return WorkerBatchResult(True, False, retry_after_batch)


__all__ = [
    "WorkerBatchResult",
    "admit_hook_worker_batch",
    "backoff_after_failed_worker_batch",
    "start_hook_worker_slot",
    "start_hook_worker_slots_interruptibly",
    "wait_for_startup_capacity_release",
]
