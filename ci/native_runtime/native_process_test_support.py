from __future__ import annotations

import os
import sys
from pathlib import Path


def process_is_alive(process_id: int) -> bool:
    """Preserve process-presence checks, including unreaped POSIX children."""
    if os.name == "nt":
        from codex_plugin_scanner.guard.windows_paths import windows_process_is_running

        return windows_process_is_running(process_id)
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True


def process_is_executing(process_id: int) -> bool:
    """Distinguish executable tasks from unreaped dead tasks for containment.

    Reaping tests must continue using process_is_alive so a zombie cannot
    satisfy their stronger requirement that the process has been removed.
    """
    if not process_is_alive(process_id):
        return False
    if sys.platform == "linux":
        # kill(pid, 0) also succeeds for a zombie. In containers whose PID 1
        # does not reap promptly, that is not evidence of an executing resident.
        # A live/stopped task still fails the caller's containment assertion.
        try:
            stat = Path(f"/proc/{process_id}/stat").read_bytes()
        except FileNotFoundError:
            return False
        # The comm field may contain spaces and closing parentheses. Only
        # the last ')' terminates it; malformed/unreadable data must not pass.
        fields = stat.rpartition(b")")[2].split()
        if not stat.startswith(f"{process_id} (".encode()) or len(fields) < 2 or not fields[1].isdigit():
            raise RuntimeError("native_test_process_state_unavailable")
        return fields[0] != b"Z"
    return True
