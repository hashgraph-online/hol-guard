"""Start the Guard daemon after an install, so the first hook finds Guard warm.

A Codex or Cursor session has no session-start hook to bring Guard up early,
so its first tool call used to pay for the daemon and the resident runtime
starting. A cold start takes a few seconds, and Codex's first hook has about
four, so a daemon that was only scheduled could still be starting when the
first command arrived and that command was refused.

After a successful install this asks the native daemon manager to bring the
daemon up and waits, up to a bound, until it reports ready. A start that does
not finish in time falls back to one detached ensure so the daemon keeps
coming up in the background. Nothing here inspects a command or decides
anything, and a failure leaves the first hook to start Guard as it always did.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path

# Long enough for a cold start on a slow host, short enough that an install
# whose daemon cannot start still returns promptly.
INSTALL_READY_WAIT_SECONDS = 15.0


def prewarm_after_install(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
    wait_seconds: float = INSTALL_READY_WAIT_SECONDS,
) -> bool:
    """Bring the daemon for ``guard_home`` up and wait for it, best effort.

    Returns True when the daemon reported ready before the install returned.
    A test Guard home is skipped, by the same rule the daemon manager uses,
    so a suite of installs does not leave a daemon behind for each one.
    """

    from ..native_daemon_manage import (
        _guard_home_is_ephemeral,
        ensure_guard_daemon,
        schedule_guard_daemon_ensure,
    )

    try:
        if _guard_home_is_ephemeral(guard_home):
            return False
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return False
    try:
        _ = ensure_guard_daemon(guard_home, home_dir=home_dir, start_timeout=wait_seconds)
        return True
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        pass
    with suppress(OSError, RuntimeError, ValueError, KeyError, TypeError):
        _ = schedule_guard_daemon_ensure(guard_home, home_dir=home_dir)
    return False
