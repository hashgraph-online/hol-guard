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

Guard Cloud can lease the ready jobs in one response: the main worker asks
for up to ``REVIEW_LEASE_BATCH_SIZE`` and hands every job after its own to the
drain workers, so those jobs skip a lease round trip of their own. A bulk
approval's decisions keep landing while the batch settles, so every batch
also starts a watch: one worker holds a lease open for up to
``REVIEW_WATCH_SECONDS`` to take the rest as they land, instead of leaving
them for a worker that frees up only once its own job has settled and its
result is sent. The batch is one job smaller than the pool, so even a full
batch leaves a worker free to watch. When the response held fewer jobs than
asked for, nothing else was ready, so only as many workers start as there are
jobs to hand over, plus the watch worker. Each batch restarts the watch, and at
most one worker watches at a time. A watch that returns jobs passes the watch
to another worker while it settles the first of them.

Each drain worker keeps its own queue state. A worker whose result upload
fails retries it with a short backoff. A result still unsent when the worker
gives up stays in that worker's state, and the main worker restarts the pool
on its next poll, so the result is sent without waiting for another job.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Final

from ..adapters.base import HarnessContext
from ..store import GuardStore
from .command_queue_http import format_redacted_error
from .command_queue_state import (
    COMMAND_QUEUE_STATE_KEY,
    CommandQueueLane,
    enter_command_queue_lane,
)
from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION

REVIEW_DRAIN_WORKERS = 7
# The main worker's job plus one handed to every drain worker but one, which
# stays free to watch for the rest of the burst.
REVIEW_LEASE_BATCH_SIZE = REVIEW_DRAIN_WORKERS
STOP_DRAIN: Final = object()
# How long after a batch one worker keeps a lease open for the rest of a bulk
# approval.
REVIEW_WATCH_SECONDS = 1.5
# A watch with less time than this left stops rather than lease.
_REVIEW_WATCH_MIN_SECONDS = 0.05
REVIEW_DRAIN_RETRY_DELAYS_SECONDS = (0.25, 0.5, 1.0, 2.0, 4.0)

_LOGGER = logging.getLogger(__name__)

PollOnce = Callable[..., dict[str, object]]


@dataclass(frozen=True)
class ReviewLeaseBatch:
    """Exact Review jobs Guard Cloud leased beside the main worker's job.

    ``more_may_be_ready`` is false when the lease returned fewer jobs than it
    asked for, so there was nothing else to lease at that moment.
    """

    jobs: tuple[dict[str, object], ...] = ()
    more_may_be_ready: bool = True


def start_review_drains(
    on_exact_review_lease: Callable[[ReviewLeaseBatch], object],
    jobs: list[dict[str, object]],
    *,
    more_may_be_ready: bool,
) -> None:
    """Hands leased Review jobs to the drain pool; a failure only logs."""
    try:
        on_exact_review_lease(ReviewLeaseBatch(jobs=tuple(jobs), more_may_be_ready=more_may_be_ready))
    except Exception as error:
        _LOGGER.warning("Guard Review drain start failed: error=%s", format_redacted_error(error))


@dataclass(frozen=True)
class ReviewWatch:
    """Tells a drain worker to hold one lease open for up to ``wait_ms``."""

    wait_ms: int


class _Handoff:
    """Leased jobs waiting for a drain worker, shared by the pool's workers."""

    def __init__(self) -> None:
        self.jobs: deque[dict[str, object]] = deque()
        self.may_lease = True
        self.watch_until = 0.0
        self.watcher: int | None = None
        # Bumped by every batch that renews the watch window; the watcher keeps
        # the value it saw when it took the watch up.
        self.watch_epoch = 0
        self.watcher_epoch = 0


def review_drain_lane(slot: int, *, wait_ms: int = 0) -> CommandQueueLane:
    """The queue lane drain worker ``slot`` owns: its own state, exact Review jobs, no wait by default."""

    return CommandQueueLane(
        state_key=f"{COMMAND_QUEUE_STATE_KEY}.review_drain.{slot}",
        operations=(EXACT_CLOUD_REVIEW_OPERATION,),
        wait_ms=wait_ms,
    )


class _LaneWriters:
    """Which drain workers in this process are writing each lane's state.

    A pool stopped by a worker restart does not wait for its drain workers, so
    an old worker can still be saving an unsent result while a new pool's
    worker runs the same slot. A worker trusts its own poll's word about its
    lane only while it was the lane's sole writer from that poll onward.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count: dict[str, int] = {}
        self._entries: dict[str, int] = {}

    @contextmanager
    def writing(self, key: str) -> Iterator[Callable[[], int | None]]:
        with self._lock:
            self._count[key] = self._count.get(key, 0) + 1
            self._entries[key] = self._entries.get(key, 0) + 1
        try:
            yield lambda: self._sole_since(key)
        finally:
            with self._lock:
                remaining = self._count[key] - 1
                if remaining:
                    self._count[key] = remaining
                else:
                    del self._count[key]

    def _sole_since(self, key: str) -> int | None:
        """A token that changes once another writer enters, or ``None`` while one is live."""

        with self._lock:
            return self._entries[key] if self._count.get(key) == 1 else None


_LANE_WRITERS = _LaneWriters()


def _lane_writer_key(store: GuardStore, slot: int) -> str:
    return f"{getattr(store, 'path', id(store))}#{slot}"


def drain_review_jobs(
    store: GuardStore,
    context: HarnessContext,
    *,
    slot: int,
    stop_event: Any,
    poll_once: PollOnce,
    format_error: Callable[[BaseException], str],
    take_job: Callable[..., object] | None = None,
    release: Callable[[int], bool] | None = None,
    on_watch_lease: Callable[[ReviewLeaseBatch], object] | None = None,
) -> None:
    """Settle handed-over and leased exact Review jobs until there are none.

    Each turn ``take_job`` hands the worker a leased job to settle, ``None`` to
    poll (lease, or send an unsent result), a ``ReviewWatch`` to poll with the
    lease held open, or ``STOP_DRAIN`` when its pool says not to lease. A
    watch lease may return a batch, whose other jobs go to ``on_watch_lease``.
    The worker also stops at its first empty lease once
    ``release`` agrees. Both decide under the pool's lock, so a job handed over
    while the worker stops is never left behind. A poll that raises or leaves a
    result unsent is retried after each delay in
    ``REVIEW_DRAIN_RETRY_DELAYS_SECONDS``; any other state ends the worker.
    """

    with _LANE_WRITERS.writing(_lane_writer_key(store, slot)) as sole_writer:
        _drain_lane(
            store,
            context,
            slot=slot,
            stop_event=stop_event,
            poll_once=poll_once,
            format_error=format_error,
            take_job=take_job,
            release=release,
            on_watch_lease=on_watch_lease,
            sole_writer=sole_writer,
        )


def _drain_lane(
    store: GuardStore,
    context: HarnessContext,
    *,
    slot: int,
    stop_event: Any,
    poll_once: PollOnce,
    format_error: Callable[[BaseException], str],
    take_job: Callable[..., object] | None,
    release: Callable[[int], bool] | None,
    on_watch_lease: Callable[[ReviewLeaseBatch], object] | None,
    sole_writer: Callable[[], int | None],
) -> None:
    enter_command_queue_lane(review_drain_lane(slot))
    failures = 0
    # While no other worker writes this lane, the status this worker's last
    # poll returned says whether the lane still holds an unsent result.
    lane_clear = False
    polled_alone: int | None = None
    while not stop_event.is_set():
        trusted = lane_clear and polled_alone is not None and sole_writer() == polled_alone
        job = take_job(slot, lane_clear=trusted) if take_job is not None else None
        if job is STOP_DRAIN:
            return
        polled_alone = sole_writer()
        try:
            if isinstance(job, dict):
                status = poll_once(store, context, leased_item=job)
            elif isinstance(job, ReviewWatch):
                enter_command_queue_lane(review_drain_lane(slot, wait_ms=job.wait_ms))
                try:
                    if on_watch_lease is None:
                        status = poll_once(store, context)
                    else:
                        status = poll_once(store, context, on_exact_review_lease=on_watch_lease)
                finally:
                    enter_command_queue_lane(review_drain_lane(slot))
            else:
                status = poll_once(store, context)
        except Exception as error:
            # A job this worker could not finish is re-leased once its lease
            # goes stale; a result it could not send stays in its state.
            _LOGGER.warning("Guard Review drain poll failed: error=%s", format_error(error))
            status = None
        lane_clear = status is not None and not isinstance(status.get("pending_result"), dict)
        if status is not None and status.get("state") == "idle":
            if status.get("last_poll_was_empty") is True and (release is None or release(slot)):
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

    return any(_lane_has_pending_result(store, slot) for slot in range(REVIEW_DRAIN_WORKERS))


def _lane_has_pending_result(store: GuardStore, slot: int, *, unreadable: bool = False) -> bool:
    try:
        payload = store.get_sync_payload(review_drain_lane(slot).state_key)
    except Exception as error:
        _LOGGER.warning("Guard Review drain state unreadable: slot=%s error=%s", slot, type(error).__name__)
        return unreadable
    return isinstance(payload, dict) and isinstance(payload.get("pending_result"), dict)


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
        self._handoff = _Handoff()

    def has_handoff(self) -> bool:
        """Whether leased jobs are still waiting for a worker."""

        with self._lock:
            return bool(self._handoff.jobs)

    def _take_job(self, slot: int, *, lane_clear: bool = False) -> object:
        """A handed-over job for worker ``slot``, ``None`` to poll, a ``ReviewWatch``, or ``STOP_DRAIN``.

        ``lane_clear`` is the worker's own word, from the status its last poll
        returned, that its lane holds no unsent result; the lane's state is then
        not read again before the next job.
        """

        # A lane still holding an unsent result sends it first; a job handed to
        # it now would have nowhere to keep its own result if that upload failed.
        # A lane whose state cannot be read is treated the same way: a handed
        # job skips the pending-result retry and could overwrite that result.
        if not lane_clear and _lane_has_pending_result(self._store, slot, unreadable=True):
            return None
        with self._lock:
            if self._handoff.jobs:
                return self._handoff.jobs.popleft()
            # A watch lease answers at once when jobs are ready, so the worker
            # that takes up the watch loses nothing over a plain lease.
            self._drop_dead_watcher()
            if self._handoff.watcher in (None, slot):
                remaining = self._handoff.watch_until - time.monotonic()
                if remaining >= _REVIEW_WATCH_MIN_SECONDS:
                    self._handoff.watcher = slot
                    self._handoff.watcher_epoch = self._handoff.watch_epoch
                    return ReviewWatch(wait_ms=int(remaining * 1000))
            if self._handoff.may_lease:
                return None
            self._free(slot)
            return STOP_DRAIN

    def _release(self, slot: int) -> bool:
        """Whether worker ``slot`` may stop after an empty lease; frees its slot when it may."""

        with self._lock:
            if self._handoff.jobs:
                return False
            if self._handoff.watcher == slot and self._handoff.watcher_epoch != self._handoff.watch_epoch:
                # Another batch renewed the window while this watch was open,
                # so the burst is not over: the worker takes the watch up again.
                self._handoff.watcher = None
                return False
            self._free(slot)
            return True

    def _drop_dead_watcher(self) -> None:
        # A watch worker that ended on an error never reached ``_free``.
        watcher = self._handoff.watcher
        if watcher is not None:
            thread = self._threads[watcher]
            if thread is None or not thread.is_alive():
                self._handoff.watcher = None

    def _free(self, slot: int) -> None:
        if self._handoff.watcher == slot:
            # The watch lease came back empty or its time ran out, so the
            # burst is over; no other worker takes the watch up again.
            self._handoff.watcher = None
            self._handoff.watch_until = 0.0
        if self._threads[slot] is threading.current_thread():
            self._threads[slot] = None

    def start(self, batch: ReviewLeaseBatch | None = None) -> int:
        """Hand over ``batch``'s jobs and start idle slots; return how many started.

        Every batch opens a watch for the rest of the burst. Without a batch,
        or when more jobs may be ready, every idle slot starts: one watches and
        the rest lease. Otherwise enough slots start to take the handed jobs,
        and one more to watch unless a worker already is.
        """

        started = 0
        with self._lock:
            if batch is not None:
                self._handoff.jobs.extend(batch.jobs)
                self._handoff.watch_until = time.monotonic() + REVIEW_WATCH_SECONDS
                self._handoff.watch_epoch += 1
            if batch is None or batch.more_may_be_ready:
                self._handoff.may_lease = True
            else:
                # Cloud returned fewer jobs than asked for, so the queue is
                # empty; workers finish what they hold and one watches.
                self._handoff.may_lease = False
            wanted = len(self._threads)
            self._drop_dead_watcher()
            watcher = self._handoff.watcher
            if watcher is not None and self._threads[watcher] is threading.current_thread():
                # The watch lease returned jobs and its worker now settles the
                # first one. The rest of the burst keeps landing meanwhile, so
                # another worker takes the watch.
                self._handoff.watcher = None
            if not self._handoff.may_lease:
                watch = self._handoff.watcher is None and self._handoff.watch_until > time.monotonic()
                wanted = len(self._handoff.jobs) + watch
            for slot, thread in enumerate(self._threads):
                if self._stop_event.is_set() or started >= wanted:
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
                        "take_job": self._take_job,
                        "release": self._release,
                        "on_watch_lease": self.start,
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
    poll while a drain lane still holds an unsent result or a handed-over job
    is still waiting for a worker.
    """

    pool = ReviewDrainPool(store, context, stop_event=stop_event, poll_once=poll_once, format_error=format_error)

    def poll(poll_store: GuardStore, poll_context: HarnessContext) -> dict[str, object]:
        if pool.has_handoff() or review_drain_has_pending_result(poll_store):
            pool.start()
        return poll_once(poll_store, poll_context, on_exact_review_lease=pool.start)

    return poll


__all__ = [
    "REVIEW_DRAIN_RETRY_DELAYS_SECONDS",
    "REVIEW_DRAIN_WORKERS",
    "REVIEW_LEASE_BATCH_SIZE",
    "REVIEW_WATCH_SECONDS",
    "STOP_DRAIN",
    "ReviewDrainPool",
    "ReviewLeaseBatch",
    "ReviewWatch",
    "drain_review_jobs",
    "review_drain_has_pending_result",
    "review_drain_lane",
    "with_review_drains",
]
