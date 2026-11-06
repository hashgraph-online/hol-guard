"""Bring a native resident that stopped answering back inside the hook budget.

A hook waits a few seconds for the publisher's acknowledgement. When the
resident hangs or refuses connections, the publisher used to retry on its own
exponential schedule and nothing ever asked the resident to come back, so every
hook in the meantime spent its whole budget and then told the agent the policy
was not ready. Three things close that gap:

* a waiting hook pulls the next publish attempt forward (``nudge_retry``);
* a run of consecutive resident failures lifts the respawn pacing in the
  background (``revive_native_resident``), at most once per cooldown;
* the hook barrier stops waiting once the failures have repeated, so a dead
  resident answers fast with advice instead of burning each hook's budget.

Nothing here can approve anything. An unavailable resident still means the hook
fails closed; this only shortens how long that takes to end.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_approval_errors import NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher

# Consecutive resident failures before the publisher asks for a revival.
RESIDENT_REVIVE_FAILURE_STREAK = 3
# A revival that did not help is not repeated inside this window.
RESIDENT_REVIVE_COOLDOWN_SECONDS = 30.0
# Revivals attempted without a single acknowledgement in between. A resident
# that keeps crash-looping through this many revivals has a cause a restart
# cannot clear (a broken binary, a bad state directory), so the crash-loop
# backoff is left in place and `hol-guard repair` is the way forward.
RESIDENT_REVIVE_MAX_ATTEMPTS = 3
# Waiting hooks cannot start publish attempts faster than this.
RESIDENT_NUDGE_MIN_INTERVAL_SECONDS = 0.5
# From this many consecutive failures a hook stops waiting for the resident.
RESIDENT_FAIL_FAST_STREAK = 4

logger = logging.getLogger(__name__)

_RESIDENT_CODE_PREFIXES = ("native_client_", "native_frame_", "native_resident_")


def is_resident_class_error(code: object) -> bool:
    """True for a failure of the resident transport rather than of the policy."""

    return isinstance(code, str) and (
        code in NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES or code.startswith(_RESIDENT_CODE_PREFIXES)
    )


class NativePolicySnapshotResidentRecoveryMixin:
    """Publisher state and actions for resident recovery."""

    _resident_failure_streak: int = 0
    _last_attempt_monotonic: float | None = None
    _last_revive_monotonic: float | None = None
    _resident_revive_attempts: int = 0
    _resident_reviver: Callable[[Path], bool] | None = None

    def _init_resident_recovery(self, reviver: Callable[[Path], bool] | None = None) -> None:
        self._resident_failure_streak = 0
        self._last_attempt_monotonic = None
        self._last_revive_monotonic = None
        self._resident_revive_attempts = 0
        self._resident_reviver = reviver

    def resident_failure_streak(self) -> int:
        """Consecutive resident failures since the last acknowledgement."""

        publisher = cast("NativePolicySnapshotPublisher", self)
        with publisher._condition:
            return publisher._resident_failure_streak

    def nudge_retry(self, *, force: bool = False) -> bool:
        """Pull the next publish attempt forward for a caller that is waiting.

        Returns True when an attempt was queued. Attempts are rate limited so a
        burst of hooks cannot turn one hung resident into a connection storm,
        and nothing is queued for a failure a retry cannot clear.
        """

        from .native_policy_snapshot_constants import POLICY_SNAPSHOT_UNRECOVERABLE_ERRORS

        publisher = cast("NativePolicySnapshotPublisher", self)
        with publisher._condition:
            # No error yet means the first attempt is still in flight; a retry
            # then adds nothing and would only publish twice.
            if publisher._closed or publisher._acked or publisher._last_error is None:
                return False
            if publisher._last_error in POLICY_SNAPSHOT_UNRECOVERABLE_ERRORS:
                return False
            now = publisher._monotonic_clock()
            last = publisher._last_attempt_monotonic
            if not force and last is not None and now - last < RESIDENT_NUDGE_MIN_INTERVAL_SECONDS:
                return False
            retry_at = publisher._retry_not_before_monotonic
            if retry_at is not None and retry_at > now:
                publisher._retry_not_before_monotonic = now
        publisher._publish_event.set()
        return True

    def _note_publish_attempt(self) -> None:
        publisher = cast("NativePolicySnapshotPublisher", self)
        with publisher._condition:
            publisher._last_attempt_monotonic = publisher._monotonic_clock()

    def _note_publish_failure_locked(self, code: str) -> bool:
        """Count a failure under the publisher lock; True when a revival is due."""

        publisher = cast("NativePolicySnapshotPublisher", self)
        if not is_resident_class_error(code):
            # The resident answered, with a failure of its own: it is alive,
            # so the run of resident failures it was counting has ended.
            publisher._resident_failure_streak = 0
            return False
        publisher._resident_failure_streak += 1
        if publisher._resident_failure_streak < RESIDENT_REVIVE_FAILURE_STREAK:
            return False
        if publisher._resident_revive_attempts >= RESIDENT_REVIVE_MAX_ATTEMPTS:
            return False
        now = publisher._monotonic_clock()
        last = publisher._last_revive_monotonic
        if last is not None and now - last < RESIDENT_REVIVE_COOLDOWN_SECONDS:
            return False
        publisher._last_revive_monotonic = now
        publisher._resident_revive_attempts += 1
        return True

    def _note_resident_acknowledged_locked(self) -> None:
        """An acknowledgement ends the failure run and refills the revival budget."""

        publisher = cast("NativePolicySnapshotPublisher", self)
        publisher._resident_failure_streak = 0
        publisher._resident_revive_attempts = 0

    def _start_resident_revival(self) -> threading.Thread | None:
        """Lift the respawn pacing off the publisher thread, then retry at once."""

        publisher = cast("NativePolicySnapshotPublisher", self)

        def revive() -> None:
            reviver = publisher._resident_reviver
            try:
                if reviver is None:
                    from .native_resident_revival import revive_native_resident

                    reviver = revive_native_resident
                if not reviver(publisher.guard_home):
                    logger.info("native resident revival did not bring the resident back")
            except (OSError, RuntimeError, TypeError, ValueError) as error:
                logger.warning("native resident revival failed: %s", type(error).__name__)
            finally:
                publisher.nudge_retry(force=True)

        thread = threading.Thread(target=revive, name="hol-guard-native-resident-revival", daemon=True)
        thread.start()
        return thread


__all__ = [
    "RESIDENT_FAIL_FAST_STREAK",
    "RESIDENT_NUDGE_MIN_INTERVAL_SECONDS",
    "RESIDENT_REVIVE_COOLDOWN_SECONDS",
    "RESIDENT_REVIVE_FAILURE_STREAK",
    "RESIDENT_REVIVE_MAX_ATTEMPTS",
    "NativePolicySnapshotResidentRecoveryMixin",
    "is_resident_class_error",
]
