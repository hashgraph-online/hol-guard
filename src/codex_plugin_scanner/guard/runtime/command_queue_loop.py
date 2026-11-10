"""Backoff loop for the local Guard command queue worker."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from ..adapters.base import HarnessContext
from ..store import GuardStore
from .command_queue_activation import command_queue_long_poll_enabled, nonnegative_env_float
from .command_queue_protocol import retry_wait_seconds
from .review_wait_activity import review_wait_recent
from .runner import GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError

COMMAND_QUEUE_POLL_INTERVAL_ENV = "GUARD_CLOUD_COMMAND_QUEUE_POLL_INTERVAL_SECONDS"
COMMAND_QUEUE_ERROR_BACKOFF_ENV = "GUARD_CLOUD_COMMAND_QUEUE_ERROR_BACKOFF_SECONDS"

_DEFAULT_POLL_INTERVAL_SECONDS = 2.0
_DEFAULT_ERROR_BACKOFF_SECONDS = 30.0
_LONG_POLL_EMPTY_MIN_WAIT_SECONDS = 0.05
# An empty lease that took at least this long was held open by Cloud, so the
# next lease goes out at once. Backing off after it would leave the device
# without an open lease for up to a poll interval once it has been idle a few
# minutes, and a decision made in that gap would wait for the next poll.
_LONG_POLL_HELD_SECONDS = 1.0
# While an agent waits on a decision, a failed poll is retried at this pace so a
# decision made during an outage reaches it soon after the network returns. An
# error backoff already under way is slept in slices of this length, so an
# agent that starts waiting partway through it still ends it early.
_REVIEW_WAITING_ERROR_RETRY_SECONDS = 2.0


class StopEvent(Protocol):
    def is_set(self) -> bool: ...

    def wait(self, timeout: float) -> bool: ...


def run_command_queue_loop(
    store: GuardStore,
    context: HarnessContext,
    *,
    stop_event: StopEvent,
    enabled: Callable[[GuardStore], bool],
    poll_once: Callable[[GuardStore, HarnessContext], dict[str, object]],
    load_state: Callable[[GuardStore], dict[str, object]],
    save_state: Callable[[GuardStore, dict[str, object]], None],
    format_error: Callable[[BaseException], str],
    now: Callable[[], str],
) -> None:
    if not enabled(store):
        return
    poll_interval = nonnegative_env_float(COMMAND_QUEUE_POLL_INTERVAL_ENV, _DEFAULT_POLL_INTERVAL_SECONDS)
    error_backoff = nonnegative_env_float(COMMAND_QUEUE_ERROR_BACKOFF_ENV, _DEFAULT_ERROR_BACKOFF_SECONDS)
    empty_streak = 0
    error_streak = 0
    while not stop_event.is_set():
        wait_seconds = poll_interval
        error_wait = False
        try:
            poll_started = time.monotonic()
            status = poll_once(store, context)
            error_streak = 0
            if status.get("last_poll_was_empty") is True:
                empty_streak += 1
                long_poll = command_queue_long_poll_enabled()
                if long_poll and time.monotonic() - poll_started >= _LONG_POLL_HELD_SECONDS:
                    empty_streak = 0
                    wait_seconds = _LONG_POLL_EMPTY_MIN_WAIT_SECONDS
                elif long_poll:
                    wait_seconds = min(
                        poll_interval,
                        _LONG_POLL_EMPTY_MIN_WAIT_SECONDS * (2 ** min(empty_streak - 1, 8)),
                    )
                else:
                    wait_seconds = retry_wait_seconds(poll_interval, error_backoff, empty_streak)
            else:
                empty_streak = 0
                if status.get("state") == "idle" and command_queue_long_poll_enabled():
                    # A job just finished. Lease again at once: a decision made
                    # while this device slept would otherwise wait out the
                    # whole poll interval before it is seen.
                    wait_seconds = _LONG_POLL_EMPTY_MIN_WAIT_SECONDS
        except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
            empty_streak = 0
            error_streak += 1
            state = "auth_expired" if isinstance(error, GuardSyncAuthorizationExpiredError) else "not_configured"
            save_state(
                store,
                {**load_state(store), "state": state, "last_error": format_error(error), "last_poll_at": now()},
            )
            wait_seconds = retry_wait_seconds(poll_interval, error_backoff, error_streak)
        except Exception as error:
            empty_streak = 0
            error_streak += 1
            save_state(
                store,
                {**load_state(store), "state": "error", "last_error": format_error(error), "last_poll_at": now()},
            )
            wait_seconds = retry_wait_seconds(poll_interval, error_backoff, error_streak)
            error_wait = True
        if error_wait:
            if _wait_out_error_backoff(stop_event, wait_seconds):
                return
        elif stop_event.wait(wait_seconds):
            return


def _wait_out_error_backoff(stop_event: StopEvent, seconds: float) -> bool:
    """Sleep out an error backoff, ending it early once an agent waits on a decision.

    Returns True when the worker was asked to stop.
    """
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        if stop_event.wait(min(remaining, _REVIEW_WAITING_ERROR_RETRY_SECONDS)):
            return True
        if review_wait_recent():
            return False


__all__ = ["COMMAND_QUEUE_ERROR_BACKOFF_ENV", "COMMAND_QUEUE_POLL_INTERVAL_ENV", "run_command_queue_loop"]
