"""Stop the local Guard daemon for a Guard home without side effects beyond that."""

from __future__ import annotations

import json
import os
import signal
from contextlib import suppress
from pathlib import Path


def stop_guard_daemon(guard_home: Path) -> dict[str, object]:
    """SIGTERM the daemon recorded for ``guard_home`` when it provably is Guard's.

    The recorded pid is only signalled when it is alive and its command line
    names this Guard home. The daemon state file is cleared either way.
    """

    from .daemon.manager import (
        _guard_daemon_pid_is_running,
        _guard_daemon_pid_matches_command,
        clear_guard_daemon_state,
    )

    state_path = guard_home / "daemon-state.json"
    stopped = False
    pid: int | None = None
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text())
            pid = state.get("pid") if isinstance(state, dict) else None
            if (
                isinstance(pid, int)
                and pid > 0
                and _guard_daemon_pid_is_running(pid)
                and _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home)
            ):
                os.kill(pid, signal.SIGTERM)
                stopped = True
        except (ProcessLookupError, PermissionError, OSError, json.JSONDecodeError, ValueError):
            pass
    with suppress(OSError):
        clear_guard_daemon_state(guard_home)
    payload: dict[str, object] = {"stopped": stopped, "running": False}
    if pid is not None:
        payload["pid"] = pid
    return payload


__all__ = ["stop_guard_daemon"]
