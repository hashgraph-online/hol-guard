"""Hold a pending approval request read open until the request is resolved.

A hook waiting on an approval asks for the request again and again until it is
resolved. Polling on a fixed interval made every decision wait for the next
tick, so a hook can now ask the daemon to hold the read open with ``wait_ms``.
A decision this daemon commits ends the wait at once through the store's
review-event wake. A decision written by another process raises no wake in this
one, so the request is read again on a short interval as well, and such a
decision is seen no later than a polling hook would have seen it.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from urllib.parse import parse_qs

from ..review_event_wake import review_event_wake_signal
from ..store import GuardStore

MAX_RESOLUTION_WAIT_SECONDS = 1.0
RESOLUTION_RECHECK_SECONDS = 0.2


def requested_resolution_wait_seconds(query: str) -> float:
    """The wait a request read asked for, bounded to what the daemon allows."""

    values = parse_qs(query).get("wait_ms")
    if not values:
        return 0.0
    try:
        wait_ms = int(values[-1])
    except ValueError:
        return 0.0
    return min(max(wait_ms, 0) / 1000, MAX_RESOLUTION_WAIT_SECONDS)


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
