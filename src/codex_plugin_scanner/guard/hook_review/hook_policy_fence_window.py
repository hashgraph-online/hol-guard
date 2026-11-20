"""Bounded polling around the resident-owned policy-source fence window."""

from __future__ import annotations

import math
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from ..native_policy_fence_window import record_policy_fence_window

POLICY_SOURCE_FENCE_ERRORS = frozenset({"native_business_source_mutation_in_progress"})
POLICY_UPDATE_PENDING_REASON_CODE = "native_policy_update_in_progress"
POLICY_SOURCE_FENCE_WINDOW_EVENT = "policy_source_fence_window"
REBUILD_WAIT_SECONDS = 8.0
POLL_SECONDS = 0.1
DEADLINE_MARGIN_SECONDS = 0.25
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


def fence_wait_until(started: float, deadline: float | None) -> float:
    """The monotonic instant a fenced hook stops polling."""

    if deadline is None:
        return started
    return min(started + REBUILD_WAIT_SECONDS, deadline - DEADLINE_MARGIN_SECONDS - ATTEMPT_MARGIN_SECONDS)


class PolicySourceFenceWait:
    """One hook's bounded poll through the resident-owned fence."""

    def __init__(
        self,
        deadline: float | None,
        *,
        guard_home: Path,
        monotonic: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._deadline = deadline
        self._guard_home = guard_home
        self._monotonic = monotonic or time.monotonic
        self._sleep = sleep or time.sleep
        self._until: float | None = None
        self._exhausted = False
        self._attempt_registered = False
        self._request_id = f"policy-fence-wait-{uuid.uuid4().hex}"

    def pause(self) -> bool:
        """Sleep one poll interval; False once the bounded wait is spent."""

        now = self._monotonic()
        if self._until is None:
            self._until = fence_wait_until(now, self._deadline)
            record_policy_fence_window(
                self._guard_home,
                action="enter",
                request_id=self._request_id,
                deadline=self._deadline,
            )
            now = self._monotonic()
        if now + POLL_SECONDS > self._until:
            self._exhausted = True
            return False
        self._sleep(POLL_SECONDS)
        if self._monotonic() > self._until:
            self._exhausted = True
            return False
        return True

    @property
    def attempt_deadline(self) -> float | None:
        if self._until is None or self._deadline is None:
            return self._deadline
        deadline = self._deadline - DEADLINE_MARGIN_SECONDS
        if not self._attempt_registered:
            self._attempt_registered = True
            remaining = max(0.0, deadline - self._monotonic())
            attempt_until_micros = max(0, int((time.time() + remaining) * 1_000_000))
            record_policy_fence_window(
                self._guard_home,
                action="attempt",
                attempt_until_micros=attempt_until_micros,
                request_id=self._request_id,
                deadline=deadline,
            )
        return deadline

    def finish(self) -> None:
        """Leave this hook's resident fence window share once."""

        if self._until is None:
            return
        self._until = None
        record_policy_fence_window(
            self._guard_home,
            action="leave",
            request_id=self._request_id,
            admitted=not self._exhausted,
            deadline=self._deadline,
        )


__all__ = [
    "POLICY_SOURCE_FENCE_ERRORS",
    "POLICY_SOURCE_FENCE_WINDOW_EVENT",
    "POLICY_UPDATE_PENDING_REASON_CODE",
    "PolicySourceFenceBusyError",
    "PolicySourceFenceWait",
    "fence_wait_until",
    "policy_update_pending_reason",
]
