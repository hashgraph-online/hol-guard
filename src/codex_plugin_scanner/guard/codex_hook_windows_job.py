"""Contain the running Windows bootstrap in a Job Object the native runtime holds."""

from __future__ import annotations

import json
import os
import subprocess
import threading
from contextlib import suppress

from .codex_hook_launch_runtime import (
    LAUNCHER_ARGS,
    launcher_popen_options,
    native_launcher_path,
)

_HOLD_ACK_TIMEOUT_SECONDS = 10.0


def assign_current_process_to_windows_hook_job(
    *,
    allow_breakaway: bool = False,
) -> subprocess.Popen[bytes]:
    """Have the native runtime put this process in a kill-on-close job before it spawns anything.

    The job lives as long as the returned holder: the holder ends it when its
    stdin closes, which also happens when this process dies. Keep the holder
    referenced for the life of the process.
    """
    if os.name != "nt":
        raise OSError("Windows Job Objects are unavailable")
    from .native_runtime import _isolated_environment

    launcher = native_launcher_path()
    if launcher is None:
        raise OSError("the native runtime is unavailable to contain this process")
    holder = subprocess.Popen(
        [launcher, *LAUNCHER_ARGS],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_isolated_environment(),
        **launcher_popen_options(),
    )
    watchdog = threading.Timer(_HOLD_ACK_TIMEOUT_SECONDS, holder.kill)
    watchdog.start()
    try:
        request = {"op": "hold_job", "process_id": os.getpid(), "allow_breakaway": allow_breakaway}
        if holder.stdin is None or holder.stdout is None:
            raise OSError("hook launcher pipes are unavailable")
        holder.stdin.write(json.dumps(request).encode("utf-8") + b"\n")
        holder.stdin.flush()
        acknowledgement = holder.stdout.readline()
        answer = json.loads(acknowledgement) if acknowledgement else None
        if not isinstance(answer, dict) or answer.get("held") is not True:
            raise OSError("the native runtime could not contain this process")
    except BaseException:
        with suppress(OSError):
            holder.kill()
        raise
    finally:
        watchdog.cancel()
    return holder


__all__ = ["assign_current_process_to_windows_hook_job"]
