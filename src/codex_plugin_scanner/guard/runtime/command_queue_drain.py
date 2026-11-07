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

Each drain worker keeps its own queue state. A result it could not upload
stays with that worker and is retried the next time the pool starts, which
also happens when the daemon starts.
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

_LOGGER = logging.getLogger(__name__)

PollOnce = Callable[[GuardStore, HarnessContext], dict[str, object]]


def review_drain_lane(slot: int) -> CommandQueueLane:
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
    """Settle exact Review jobs until a lease comes back empty."""

    enter_command_queue_lane(review_drain_lane(slot))
    while not stop_event.is_set():
        try:
            status = poll_once(store, context)
        except Exception as error:
            # The main worker keeps leasing; a job this worker could not
            # finish is re-leased once its lease goes stale.
            _LOGGER.warning("Guard Review drain worker stopped: error=%s", format_error(error))
            return
        if status.get("last_poll_was_empty") is True or status.get("state") != "idle":
            return


def review_drain_has_pending_result(store: GuardStore) -> bool:
    for slot in range(REVIEW_DRAIN_WORKERS):
        payload = store.get_sync_payload(review_drain_lane(slot).state_key)
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
                self._threads[slot] = worker
                worker.start()
                started += 1
        return started


__all__ = [
    "REVIEW_DRAIN_WORKERS",
    "ReviewDrainPool",
    "drain_review_jobs",
    "review_drain_has_pending_result",
    "review_drain_lane",
]
