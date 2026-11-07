"""Hold a pending approval request read open until the request is resolved.

A hook waiting on an approval asks for the request again and again until it is
resolved. Polling on a fixed interval made every decision wait for the next
tick, so a hook can now ask the daemon to hold the read open with ``wait_ms``.
A decision this daemon commits ends the wait at once through the store's
review-event wake. A decision written by another process raises no wake in this
one, so the request is read again on a short interval as well, and such a
decision is seen no later than a polling hook would have seen it.

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
from collections import OrderedDict
from collections.abc import Callable
from urllib.parse import parse_qs

from ..review_event_wake import review_event_wake_signal
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
    _wake_review_delivery_once(store, request_id)
    if not _held_reads.acquire(blocking=False):
        return approval
    try:
        return _wait_while_pending(store, request_id, approval, timeout_seconds, monotonic)
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
    approval: dict[str, object],
    timeout_seconds: float,
    monotonic: Callable[[], float],
) -> dict[str, object] | None:
    signal = review_event_wake_signal(store.path)
    deadline = monotonic() + timeout_seconds
    current: dict[str, object] | None = approval
    while True:
        # Take the generation before reading, so a decision committed between
        # the read and the wait still ends the wait.
        generation = signal.generation()
        current = store.get_approval_request(request_id)
        if current is None or current.get("status") != "pending":
            return current
        remaining = deadline - monotonic()
        if remaining <= 0:
            return current
        signal.wait(generation, min(remaining, RESOLUTION_RECHECK_SECONDS))
