"""Worker-slot review I/O and idempotent retry handling."""

from __future__ import annotations

import queue
import time
from collections.abc import Callable, Mapping
from contextlib import suppress

from .hook_process_request import runtime_hook_review_is_idempotent
from .hook_process_worker import HookProcessReview, HookWorkerSlot

_HOOK_PROCESS_RETRY_READY_SECONDS = 0.75


def review_hook_worker_slot(
    *,
    slot: HookWorkerSlot,
    request: dict[str, object],
    payload: Mapping[str, object],
    review_deadline: float,
    caller_deadline_limited: bool,
    ready_slots: queue.Queue[HookWorkerSlot],
    replace_slot: Callable[[HookWorkerSlot], None],
    increment_metric: Callable[[str], None],
    wait_for_capacity: Callable[[int, float], bool],
) -> tuple[HookWorkerSlot, object] | HookProcessReview:
    try:
        return slot, _send_review_to_slot(slot, request, review_deadline)
    except TimeoutError:
        replace_slot(slot)
        if caller_deadline_limited:
            return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
        increment_metric("timeouts")
        return HookProcessReview(None, "daemon_hook_process_timeout")
    except (BrokenPipeError, EOFError, OSError):
        increment_metric("failures")
        # Withdraw the failed slot before waiting for or reserving replacement
        # capacity. Otherwise the scheduler can observe stale capacity while
        # the failed slot is still registered with the runner.
        replace_slot(slot)
        retry_slot = _retry_slot_for_idempotent_review(
            payload=payload,
            ready_slots=ready_slots,
            wait_for_capacity=wait_for_capacity,
            review_deadline=review_deadline,
        )
        if not runtime_hook_review_is_idempotent(payload):
            return HookProcessReview(None, "daemon_hook_process_failed")
        if retry_slot is None:
            reason = (
                "daemon_hook_process_deadline_exhausted"
                if time.monotonic() >= review_deadline
                else "daemon_hook_process_failed"
            )
            return HookProcessReview(None, reason)
        try:
            return retry_slot, _send_review_to_slot(retry_slot, request, review_deadline)
        except TimeoutError:
            replace_slot(retry_slot)
            return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
        except (BrokenPipeError, EOFError, OSError):
            increment_metric("failures")
            replace_slot(retry_slot)
            return HookProcessReview(None, "daemon_hook_process_failed")


def _send_review_to_slot(slot: HookWorkerSlot, request: dict[str, object], review_deadline: float) -> object:
    remaining_seconds = max(0.0, review_deadline - time.monotonic())
    if not slot.handshake_lock.acquire(timeout=remaining_seconds):
        raise TimeoutError
    try:
        slot.connection.send(("review", request))
        slot.request_exposed = True
        remaining_seconds = max(0.0, review_deadline - time.monotonic())
        if not slot.connection.poll(remaining_seconds):
            raise TimeoutError
        return slot.connection.recv()
    finally:
        slot.handshake_lock.release()


def _retry_slot_for_idempotent_review(
    *,
    payload: Mapping[str, object],
    ready_slots: queue.Queue[HookWorkerSlot],
    wait_for_capacity: Callable[[int, float], bool],
    review_deadline: float,
) -> HookWorkerSlot | None:
    if not runtime_hook_review_is_idempotent(payload):
        return None
    with suppress(queue.Empty):
        return ready_slots.get_nowait()
    remaining_seconds = max(0.0, review_deadline - time.monotonic())
    if not wait_for_capacity(1, min(_HOOK_PROCESS_RETRY_READY_SECONDS, remaining_seconds)):
        return None
    try:
        return ready_slots.get_nowait()
    except queue.Empty:
        return None


__all__ = ["review_hook_worker_slot"]
