"""Keep a Codex hook asking a daemon that is still starting.

A cold start on a busy Windows machine can take tens of seconds. Denying the
tool call after one retry turns that start into a string of failed actions.
While a launch marker says the start has not settled, the hook keeps asking
the daemon instead. Only an authenticated daemon reply comes back from here;
the wait never produces a decision of its own.
"""

from __future__ import annotations

import http.client
import time
import urllib.error
from collections.abc import Callable
from pathlib import Path

from .codex_daemon_dead_fastpath import daemon_start_in_progress

FIRST_POLL_SECONDS = 0.25
MAX_POLL_SECONDS = 1.0
# Failures that mean "not up yet": no state, a stopped state, nothing
# listening, or a new daemon replacing the state mid-request.
RETRYABLE_REASONS = frozenset(
    {
        "daemon_connection_refused",
        "daemon_generation_changed",
        "daemon_state_missing",
        "daemon_state_stopped",
        "daemon_state_unreadable",
        "daemon_transport_unavailable",
    }
)


def await_started_daemon(
    *,
    state_path: str | Path,
    stop_at: float,
    first_request: Callable[[], dict[str, object] | None],
    request: Callable[[], dict[str, object] | None],
    started: bool,
    failure_reason: Callable[[BaseException], str],
) -> dict[str, object] | None:
    """Ask the daemon until it answers, the start settles or ``stop_at`` passes.

    ``started`` means the start command succeeded, so ``first_request`` is made
    once even without a launch marker, as before the wait existed. Later polls
    use ``request``, which must stay inside ``stop_at`` so the local fallback
    keeps its slice. A failed request is retried only for a retryable reason
    while a marker is fresh; any other failure, including an authenticated
    refusal, is raised unchanged.
    """

    poll = FIRST_POLL_SECONDS
    if started:
        try:
            return first_request()
        except _REQUEST_ERRORS as error:
            if not _keep_waiting(error, state_path, stop_at, poll, failure_reason):
                raise
    elif time.monotonic() + poll >= stop_at or not daemon_start_in_progress(state_path):
        return None
    while True:
        time.sleep(poll)
        poll = min(poll * 2, MAX_POLL_SECONDS)
        try:
            return request()
        except _REQUEST_ERRORS as error:
            if not _keep_waiting(error, state_path, stop_at, poll, failure_reason):
                raise


_REQUEST_ERRORS = (OSError, ValueError, http.client.HTTPException, urllib.error.URLError)


def _keep_waiting(
    error: BaseException,
    state_path: str | Path,
    stop_at: float,
    poll: float,
    failure_reason: Callable[[BaseException], str],
) -> bool:
    return (
        failure_reason(error) in RETRYABLE_REASONS
        and time.monotonic() + poll < stop_at
        and daemon_start_in_progress(state_path)
    )


__all__ = ["await_started_daemon"]
