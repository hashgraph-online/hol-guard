"""Bounded hook wait while a policy update holds the business-source fence.

The extension-control authority holds its mutation lock exclusively while it
rebuilds the business-source anchor. Native admission then reports
``native_business_source_mutation_in_progress`` without evaluating anything.
A hook polls through that window inside its own deadline and is admitted once
the fence clears. When the wait runs out the action is not run: callers answer
with the stable policy-update message and never allow.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Protocol, cast

_LOGGER = logging.getLogger(__name__)

POLICY_SOURCE_FENCE_ERRORS = frozenset({"native_business_source_mutation_in_progress"})
POLICY_UPDATE_PENDING_REASON_CODE = "native_policy_update_in_progress"
POLICY_SOURCE_FENCE_WINDOW_EVENT = "policy_source_fence_window"
REBUILD_WAIT_SECONDS = 8.0
POLL_SECONDS = 0.1
# Left for rendering and transport so a harness that fails open on hook
# timeout always receives the fail-closed answer first.
DEADLINE_MARGIN_SECONDS = 0.25
# Held back from the last poll so it can finish, even if it stalls, before
# that response margin begins.
ATTEMPT_MARGIN_SECONDS = 0.25


def policy_update_pending_reason(retry_seconds: float = REBUILD_WAIT_SECONDS) -> str:
    retry = max(1, math.ceil(retry_seconds))
    return f"Guard is finishing a policy update; this action was not run. Retry after {retry} seconds."


class PolicySourceFenceBusyError(RuntimeError):
    """Native admission was refused only because the fence is held."""

    def __init__(self, code: str, *, recording_only: bool = False) -> None:
        if code not in POLICY_SOURCE_FENCE_ERRORS:
            raise ValueError("unsupported policy source fence error")
        super().__init__(code)
        self.code = code
        self.recording_only = recording_only is True


class _EventStore(Protocol):
    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None: ...


def fence_wait_until(started: float, deadline: float | None) -> float:
    """The monotonic instant a fenced hook stops polling.

    A missing deadline grants no wait. Otherwise the wait is the shorter of
    the rebuild bound and the hook's remaining budget less the last poll's
    margin and the response margin.
    """

    if deadline is None:
        return started
    return min(started + REBUILD_WAIT_SECONDS, deadline - DEADLINE_MARGIN_SECONDS - ATTEMPT_MARGIN_SECONDS)


class PolicySourceFenceWindow:
    """Count the hooks absorbed by one fence window, process-wide.

    A window opens when the first hook meets the fence and closes when the
    last waiting hook leaves it. Closing records one timeline event with the
    window's bounds and how many hooks were re-admitted or stopped.
    """

    def __init__(self, *, wall_clock: Callable[[], datetime] | None = None) -> None:
        self._lock = threading.Lock()
        self._wall_clock = wall_clock or (lambda: datetime.now(timezone.utc))
        self._waiting = 0
        self._started_at: datetime | None = None
        self._absorbed = 0
        self._exhausted = 0

    def enter(self) -> None:
        with self._lock:
            if self._waiting == 0:
                self._started_at = self._wall_clock()
                self._absorbed = 0
                self._exhausted = 0
            self._waiting += 1

    def leave(self, store: _EventStore | None, *, admitted: bool) -> None:
        with self._lock:
            if self._waiting <= 0:
                return
            self._waiting -= 1
            if admitted:
                self._absorbed += 1
            else:
                self._exhausted += 1
            if self._waiting or self._started_at is None:
                return
            ended_at = self._wall_clock()
            payload: dict[str, object] = {
                "started_at": self._started_at.isoformat(),
                "ended_at": ended_at.isoformat(),
                "absorbed_calls": self._absorbed,
                "exhausted_calls": self._exhausted,
            }
            self._started_at = None
        _record_window(store, payload, ended_at)

    def absorb_direct(self, store: _EventStore | None, waited_seconds: float) -> None:
        """Count one hook the resident's direct lane held through the fence.

        The resident has no event store, so that hook reports its wait with
        its drained evidence. A window the daemon still holds open takes the
        hook into its count. Otherwise the wait is a window of its own.
        """

        waited = timedelta(seconds=min(max(waited_seconds, 0.0), REBUILD_WAIT_SECONDS))
        with self._lock:
            if self._waiting:
                self._absorbed += 1
                return
            ended_at = self._wall_clock()
        payload: dict[str, object] = {
            "started_at": (ended_at - waited).isoformat(),
            "ended_at": ended_at.isoformat(),
            "absorbed_calls": 1,
            "exhausted_calls": 0,
        }
        _record_window(store, payload, ended_at)


def _record_window(store: _EventStore | None, payload: dict[str, object], ended_at: datetime) -> None:
    """Write one window event; a store failure never changes a hook's answer."""

    add_event = getattr(store, "add_event", None)
    if not callable(add_event):
        return
    try:
        add_event(POLICY_SOURCE_FENCE_WINDOW_EVENT, payload, ended_at.isoformat())
    except Exception:
        _LOGGER.warning("policy source fence window event was not recorded", exc_info=True)


FENCE_WINDOW = PolicySourceFenceWindow()


class PolicySourceFenceWait:
    """One hook's bounded poll through the fence."""

    def __init__(
        self,
        deadline: float | None,
        *,
        store: _EventStore | None,
        window: PolicySourceFenceWindow = FENCE_WINDOW,
        monotonic: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._deadline = deadline
        self._store = store
        self._window = window
        self._monotonic = monotonic or time.monotonic
        self._sleep = sleep or time.sleep
        self._until: float | None = None
        self._exhausted = False

    def pause(self) -> bool:
        """Sleep one poll interval; False once the bounded wait is spent."""

        now = self._monotonic()
        if self._until is None:
            self._until = fence_wait_until(now, self._deadline)
            self._window.enter()
        if now + POLL_SECONDS > self._until:
            self._exhausted = True
            return False
        self._sleep(POLL_SECONDS)
        if self._monotonic() > self._until:
            # The sleep ran late; another poll could outlast the budget.
            self._exhausted = True
            return False
        return True

    @property
    def attempt_deadline(self) -> float | None:
        """The deadline for this hook's next native attempt.

        The first attempt keeps the hook's own deadline. A poll after a wait
        stops one margin short of it, so a poll that stalls still leaves time
        for the fail-closed answer.
        """

        if self._until is None or self._deadline is None:
            return self._deadline
        return self._deadline - DEADLINE_MARGIN_SECONDS

    def finish(self) -> None:
        """Leave the window once; a spent wait counts as an exhausted call."""

        if self._until is None:
            return
        self._until = None
        self._window.leave(self._store, admitted=not self._exhausted)


def record_direct_fence_wait(
    store: object, waited_ms: object, *, window: PolicySourceFenceWindow = FENCE_WINDOW
) -> None:
    """Record the fence wait a drained direct-lane hook reports, if any."""

    if isinstance(waited_ms, bool) or not isinstance(waited_ms, int) or waited_ms <= 0:
        return
    window.absorb_direct(cast("_EventStore | None", store), waited_ms / 1_000)
