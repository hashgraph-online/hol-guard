"""Hold a pending approval request read open until the request is resolved.

A hook waiting on an approval asks for the request again and again until it is
resolved. Polling on a fixed interval made every decision wait for the next
tick, so a hook can now ask the daemon to hold the read open with ``wait_ms``.
A decision this daemon commits ends the wait at once through the store's
review-event wake. A decision written by another process raises no wake in this
one, so the request is read again on a short interval as well, and such a
decision is seen no later than a polling hook would have seen it.

While it waits, a held read checks only the request's stored status. Every
review event in the daemon wakes every held read, and a bulk approval raises
many of them, so building the full request on each wake made the waiting hooks
compete with the approvals they were waiting for. The full request is read once
the status changes, or at the deadline.

Held reads woken by the same review event share one status read. The first to
wake reads the status of every request still held open in a single query, and
the others take their answer from it, so a bulk approval costs one read per
review event rather than one per waiting hook. A recheck without a wake still
reads its own request, since that is how a decision written by another process
is seen.

A held read keeps one of the daemon's request slots for as long as it waits,
so only a few are held at once. Beyond that a read is answered immediately,
and its hook falls back to polling, leaving the remaining slots for hook
evaluations and decisions.

A hook writes its pending request through the native store, whose commit wake
fires in the hook's process rather than this one. The hook's first read of the
request is therefore the daemon's first sign of it, and that read wakes the
Cloud Review sync worker so the request reaches Guard Cloud now instead of on
the worker's next safety poll.
"""

from __future__ import annotations

import threading
import time
import weakref
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from urllib.parse import parse_qs

from ..fork_safety import forget_in_child
from ..review_event_wake import ReviewEventWakeSignal, review_event_wake_signal
from ..runtime.review_wait_activity import note_review_wait
from ..store import GuardStore

MAX_RESOLUTION_WAIT_SECONDS = 1.0
RESOLUTION_RECHECK_SECONDS = 0.2
MAX_HELD_RESOLUTION_READS = 8

_MAX_RESOLUTION_WAIT_MS = int(MAX_RESOLUTION_WAIT_SECONDS * 1000)
_held_reads = threading.BoundedSemaphore(MAX_HELD_RESOLUTION_READS)
# Remembers recent requests whose first read already woke the sync worker, so a
# hook polling one request wakes it once rather than on every read.
MAX_WOKEN_REQUESTS = 256
_woken_lock = threading.Lock()
_woken_requests: OrderedDict[str, None] = OrderedDict()


class _SharedStatusReads:
    """The statuses of every request held open on one store, read once per wake."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Only one held read queries at a time; the rest wait for its answer.
        self._reader = threading.Lock()
        self._waiting: Counter[str] = Counter()
        self._read_generation = -1
        self._statuses: dict[str, str | None] = {}

    @contextmanager
    def holding(self, request_id: str) -> Iterator[None]:
        with self._lock:
            self._waiting[request_id] += 1
        try:
            yield
        finally:
            with self._lock:
                self._waiting[request_id] -= 1
                if self._waiting[request_id] <= 0:
                    del self._waiting[request_id]
                    self._statuses.pop(request_id, None)

    def status_after(
        self,
        store: GuardStore,
        signal: ReviewEventWakeSignal,
        generation: int,
        request_id: str,
    ) -> str | None:
        """The request's status as read no earlier than wake ``generation``."""

        with self._reader:
            with self._lock:
                if self._read_generation >= generation and request_id in self._statuses:
                    return self._statuses[request_id]
                request_ids = sorted({*self._waiting, request_id})
            # Take the generation before reading, so the answer is never reused
            # for a wake raised by a commit the read may have missed.
            read_generation = signal.generation()
            statuses = store.get_approval_request_statuses(request_ids)
            with self._lock:
                self._read_generation = read_generation
                self._statuses = {item: statuses.get(item) for item in request_ids if item in self._waiting}
            return statuses.get(request_id)


_shared_reads_lock = threading.Lock()
_shared_reads: weakref.WeakKeyDictionary[ReviewEventWakeSignal, _SharedStatusReads] = weakref.WeakKeyDictionary()
forget_in_child(_shared_reads)


def _shared_status_reads(signal: ReviewEventWakeSignal) -> _SharedStatusReads:
    with _shared_reads_lock:
        reads = _shared_reads.get(signal)
        if reads is None:
            reads = _SharedStatusReads()
            _shared_reads[signal] = reads
        return reads


def requested_resolution_wait_seconds(query: str) -> float:
    """The wait a request read asked for, bounded to what the daemon allows."""

    values = parse_qs(query).get("wait_ms")
    if not values:
        return 0.0
    try:
        wait_ms = int(values[-1])
    except ValueError:
        return 0.0
    return min(max(wait_ms, 0), _MAX_RESOLUTION_WAIT_MS) / 1000


def wait_for_request_resolution(
    store: GuardStore,
    request_id: str,
    approval: dict[str, object],
    timeout_seconds: float,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, object] | None:
    """The request once it is no longer pending, or as it stands at the deadline."""

    if timeout_seconds <= 0 or approval.get("status") != "pending":
        return approval
    note_review_wait()
    _wake_review_delivery_once(store, request_id)
    if not _held_reads.acquire(blocking=False):
        return approval
    try:
        return _wait_while_pending(store, request_id, timeout_seconds, monotonic)
    finally:
        _held_reads.release()


def _wake_review_delivery_once(store: GuardStore, request_id: str) -> None:
    with _woken_lock:
        if request_id in _woken_requests:
            return
        _woken_requests[request_id] = None
        if len(_woken_requests) > MAX_WOKEN_REQUESTS:
            _woken_requests.popitem(last=False)
    review_event_wake_signal(store.path).notify()


def _wait_while_pending(
    store: GuardStore,
    request_id: str,
    timeout_seconds: float,
    monotonic: Callable[[], float],
) -> dict[str, object] | None:
    signal = review_event_wake_signal(store.path)
    shared = _shared_status_reads(signal)
    deadline = monotonic() + timeout_seconds
    with shared.holding(request_id):
        # Take the generation before reading, so a decision committed between
        # the read and the wait still ends the wait.
        generation = signal.generation()
        status = store.get_approval_request_status(request_id)
        while True:
            if status != "pending":
                return store.get_approval_request(request_id)
            remaining = deadline - monotonic()
            if remaining <= 0:
                return store.get_approval_request(request_id)
            woke = signal.wait(generation, min(remaining, RESOLUTION_RECHECK_SECONDS))
            if woke != generation:
                generation = woke
                status = shared.status_after(store, signal, generation, request_id)
            else:
                # No wake in this process: a decision another process wrote is
                # seen only by reading the request again.
                generation = signal.generation()
                status = store.get_approval_request_status(request_id)
