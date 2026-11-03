"""Hand the native resident update barrier back before post-update repair."""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path

from ..native_resident_update_lock import NativeResidentUpdateLock, NativeResidentUpdateLockError


def release_before_post_update_repair(lock: NativeResidentUpdateLock | None, executable: Path) -> None:
    """Publish the installed runtime identity and release the barrier.

    Package shim and harness repair talk to the native runtime, and every native
    client request takes the shared side of this barrier. While the updater still
    holds the exclusive side, those requests refuse with
    ``native_resident_update_in_progress``. A digest the runtime cannot accept is
    left unpublished here, as the caller's final release would also leave it; the
    caller decides whether that fails the update.
    """

    if lock is None or not lock.active:
        return
    with suppress(NativeResidentUpdateLockError):
        _ = lock.publish_runtime_digest(executable)
    lock.release()


def subprocess_failure_summary(output: str) -> str:
    """Return the last line of a failed child's output, so notes never carry a traceback."""

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-1] if lines else ""
