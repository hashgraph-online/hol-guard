"""Backoff loop for the local Guard command queue worker."""

from __future__ import annotations

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
# While an agent waits on a decision, a failed poll is retried at this pace so a
# decision made during an outage reaches it soon after the network returns.
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
        try:
            status = poll_once(store, context)
            error_streak = 0
            if status.get("last_poll_was_empty") is True:
                empty_streak += 1
                if command_queue_long_poll_enabled():
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
            if review_wait_recent():
                wait_seconds = min(wait_seconds, _REVIEW_WAITING_ERROR_RETRY_SECONDS)
        if stop_event.wait(wait_seconds):
            return


__all__ = ["COMMAND_QUEUE_ERROR_BACKOFF_ENV", "COMMAND_QUEUE_POLL_INTERVAL_ENV", "run_command_queue_loop"]
