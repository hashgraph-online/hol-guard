"""Settle a burst of Cloud Review decisions on parallel leases.

A reviewer who approves several requests at once queues one exact Review job
per request. The main command worker leases and settles them one at a time,
and every job costs a lease, an acknowledgement and a result round trip, so
the last request in a bulk approval waited on every request before it.

When the main worker leases an exact Review job, a few drain workers start
beside it. Each one leases exact Review jobs only, never waits for a job to
appear, and stops at its first empty lease, so an idle device still holds just
the main worker's one long poll. Guard Cloud locks each delivery while it
leases it, so parallel leases never receive the same job.

Each drain worker keeps its own queue state. A worker whose result upload
fails retries it with a short backoff. A result still unsent when the worker
gives up stays in that worker's state, and the main worker restarts the pool
on its next poll, so the result is sent without waiting for another job.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

from ..adapters.base import HarnessContext
from ..store import GuardStore
from .command_queue_state import (
    COMMAND_QUEUE_STATE_KEY,
    CommandQueueLane,
    enter_command_queue_lane,
)
from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION

REVIEW_DRAIN_WORKERS = 3
REVIEW_DRAIN_RETRY_DELAYS_SECONDS = (0.25, 0.5, 1.0, 2.0, 4.0)

_LOGGER = logging.getLogger(__name__)

PollOnce = Callable[[GuardStore, HarnessContext], dict[str, object]]


def review_drain_lane(slot: int) -> CommandQueueLane:
    """The queue lane drain worker ``slot`` owns: its own state, exact Review jobs, no wait."""

    return CommandQueueLane(
        state_key=f"{COMMAND_QUEUE_STATE_KEY}.review_drain.{slot}",
        operations=(EXACT_CLOUD_REVIEW_OPERATION,),
        wait_ms=0,
    )


def drain_review_jobs(
    store: GuardStore,
    context: HarnessContext,
    *,
    slot: int,
    stop_event: Any,
    poll_once: PollOnce,
    format_error: Callable[[BaseException], str],
) -> None:
    """Settle exact Review jobs until a lease comes back empty.

    A poll that raises or leaves a result unsent is retried after each delay in
    ``REVIEW_DRAIN_RETRY_DELAYS_SECONDS``; any other state ends the worker.
    """

    enter_command_queue_lane(review_drain_lane(slot))
    failures = 0
    while not stop_event.is_set():
        try:
            status = poll_once(store, context)
        except Exception as error:
            # A job this worker could not finish is re-leased once its lease
            # goes stale; a result it could not send stays in its state.
            _LOGGER.warning("Guard Review drain poll failed: error=%s", format_error(error))
            status = None
        if status is not None and status.get("state") == "idle":
            if status.get("last_poll_was_empty") is True:
                return
            failures = 0
            continue
        retryable = status is None or status.get("state") == "result_pending"
        if not retryable or failures >= len(REVIEW_DRAIN_RETRY_DELAYS_SECONDS):
            return
        stop_event.wait(REVIEW_DRAIN_RETRY_DELAYS_SECONDS[failures])
        failures += 1


def review_drain_has_pending_result(store: GuardStore) -> bool:
    """Whether any drain lane holds a result it has not sent yet.

    A lane whose state cannot be read is skipped, so it never stops the main
    worker's poll or hides another lane's unsent result.
    """

    for slot in range(REVIEW_DRAIN_WORKERS):
        try:
            payload = store.get_sync_payload(review_drain_lane(slot).state_key)
        except Exception as error:
            _LOGGER.warning("Guard Review drain state unreadable: slot=%s error=%s", slot, type(error).__name__)
            continue
        if isinstance(payload, dict) and isinstance(payload.get("pending_result"), dict):
            return True
    return False


class ReviewDrainPool:
    """Start drain workers on demand; at most one thread per slot."""

    def __init__(
        self,
        store: GuardStore,
        context: HarnessContext,
        *,
        stop_event: Any,
        poll_once: PollOnce,
        format_error: Callable[[BaseException], str],
        workers: int = REVIEW_DRAIN_WORKERS,
    ) -> None:
        self._store = store
        self._context = context
        self._stop_event = stop_event
        self._poll_once = poll_once
        self._format_error = format_error
        self._threads: list[threading.Thread | None] = [None] * workers
        self._lock = threading.Lock()

    def start(self) -> int:
        """Start every idle slot; return how many workers were started."""

        started = 0
        with self._lock:
            for slot, thread in enumerate(self._threads):
                if self._stop_event.is_set():
                    break
                if thread is not None and thread.is_alive():
                    continue
                worker = threading.Thread(
                    target=drain_review_jobs,
                    kwargs={
                        "store": self._store,
                        "context": self._context,
                        "slot": slot,
                        "stop_event": self._stop_event,
                        "poll_once": self._poll_once,
                        "format_error": self._format_error,
                    },
                    name=f"guard-review-drain-{slot}",
                    daemon=True,
                )
                try:
                    worker.start()
                except RuntimeError as error:
                    # The leased job settles on the main worker either way.
                    _LOGGER.warning("Guard Review drain worker did not start: error=%s", self._format_error(error))
                    break
                self._threads[slot] = worker
                started += 1
        return started


def with_review_drains(
    store: GuardStore,
    context: HarnessContext,
    *,
    stop_event: Any,
    poll_once: Callable[..., dict[str, object]],
    format_error: Callable[[BaseException], str],
) -> PollOnce:
    """Wrap the main worker's poll so it starts drain workers when they have work.

    The pool starts when the main worker leases an exact Review job, and on any
    poll while a drain lane still holds an unsent result.
    """

    pool = ReviewDrainPool(store, context, stop_event=stop_event, poll_once=poll_once, format_error=format_error)

    def poll(poll_store: GuardStore, poll_context: HarnessContext) -> dict[str, object]:
        if review_drain_has_pending_result(poll_store):
            pool.start()
        return poll_once(poll_store, poll_context, on_exact_review_lease=pool.start)

    return poll


__all__ = [
    "REVIEW_DRAIN_RETRY_DELAYS_SECONDS",
    "REVIEW_DRAIN_WORKERS",
    "ReviewDrainPool",
    "drain_review_jobs",
    "review_drain_has_pending_result",
    "review_drain_lane",
    "with_review_drains",
]
