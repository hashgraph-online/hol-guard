"""Start the Guard daemon after an install, so the first hook finds Guard warm.

A Codex or Cursor session has no session-start hook to bring Guard up early,
so its first tool call used to pay for the daemon and the resident runtime
starting. After a successful install this reserves one detached daemon ensure
through the native daemon manager; the daemon prewarms the resident when it
starts. Nothing here inspects a command or decides anything, and a reservation
that fails leaves the first hook to start Guard as it always did.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path


def prewarm_after_install(guard_home: Path, *, home_dir: Path | None = None) -> None:
    """Reserve a detached daemon ensure for ``guard_home``, best effort.

    A test Guard home is skipped, by the same rule the daemon manager uses,
    so a suite of installs does not leave a daemon behind for each one.
    """

    from ..native_daemon_manage import _guard_home_is_ephemeral, schedule_guard_daemon_ensure

    with suppress(OSError, RuntimeError, ValueError, KeyError, TypeError):
        if _guard_home_is_ephemeral(guard_home):
            return
        _ = schedule_guard_daemon_ensure(guard_home, home_dir=home_dir)
