"""What `hol-guard sync` reports when another Guard process is using Guard Cloud."""

from __future__ import annotations

GUARD_SYNC_IN_PROGRESS_MESSAGE = (
    "Another Guard process is talking to Guard Cloud right now, so this sync did not start. "
    "Run `hol-guard sync` again in a minute. `hol-guard status` shows when Guard last synced."
)


class GuardCloudSyncBusyError(TimeoutError):
    """Another Guard process holds the Guard Cloud sync lock."""
