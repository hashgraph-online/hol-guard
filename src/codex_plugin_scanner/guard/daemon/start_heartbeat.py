"""Early "starting" heartbeat from a freshly spawned Guard daemon.

A cold daemon on a slow machine spends tens of seconds importing Python before
it can journal ``start_requested`` or take the owner lock. Without any signal
in that window the launcher cannot tell a slow child from a stuck one and
terminates both. The launcher therefore hands the child a heartbeat path in its
environment; the child writes one tiny record before importing anything heavy.

The record only extends the launcher's patience. It is bounded by
``SLOW_START_MAX_SECONDS`` after spawn, must name a pid inside the spawned
process tree, and is never read as proof that the daemon is ready or trusted.
"""

from __future__ import annotations

import time
from pathlib import Path

from ..private_file_io import read_private_regular_text

START_HEARTBEAT_ENV = "HOL_GUARD_DAEMON_START_HEARTBEAT"
START_HEARTBEAT_FILE = "daemon-start-heartbeat"
START_HEARTBEAT_MAX_BYTES = 256
# Hard ceiling on how long a child that has only emitted this heartbeat is
# treated as starting. Past it the child is classified like any silent one.
SLOW_START_MAX_SECONDS = 180.0

# Run by the child before it imports Guard. Stdlib only, never raises.
#
# It is embedded in the daemon's ``-c`` bootstrap, so it is deliberately one
# line with only single quotes and no backslashes: process inventory splits the
# command line shell-style and must still recognise the daemon. The record is
# ``<pid> <time_ns>``, written to a private temp file (no symlink following)
# and renamed into place so a reader never sees an empty or partial record.
START_HEARTBEAT_CODE = (
    "with __import__('contextlib').suppress(BaseException): "
    + "import os,time; "
    + f"p=os.environ.pop('{START_HEARTBEAT_ENV}',''); "
    + "p[0]; "
    + "t='%s.%d.tmp'%(p,os.getpid()); "
    + "fd=os.open(t,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),384); "
    + "os.write(fd,('%d %d'%(os.getpid(),time.time_ns())).encode()); "
    + "os.close(fd); "
    + "os.replace(t,p)"
)


def start_heartbeat_path(guard_home: Path) -> Path:
    return guard_home / START_HEARTBEAT_FILE


def load_start_heartbeat(guard_home: Path) -> tuple[int, int] | None:
    """Return ``(pid, recorded_at_ns)`` from a well-formed heartbeat record."""

    try:
        raw = read_private_regular_text(
            start_heartbeat_path(guard_home),
            max_bytes=START_HEARTBEAT_MAX_BYTES,
            require_private_parent=True,
        )
        fields = raw.split() if raw else []
        if len(fields) != 2 or not all(field.isascii() and field.isdigit() for field in fields):
            return None
        pid, recorded_at_ns = int(fields[0]), int(fields[1])
    except (OSError, ValueError):
        return None
    if pid <= 0 or recorded_at_ns <= 0:
        return None
    return pid, recorded_at_ns


def clear_start_heartbeat(guard_home: Path) -> None:
    try:
        start_heartbeat_path(guard_home).unlink()
    except OSError:
        return


def heartbeat_is_within_window(recorded_at_ns: int, *, spawned_at_ns: int, now_ns: int | None = None) -> bool:
    now = time.time_ns() if now_ns is None else now_ns
    if recorded_at_ns <= spawned_at_ns:
        return False
    return now - spawned_at_ns < int(SLOW_START_MAX_SECONDS * 1_000_000_000)


__all__ = [
    "SLOW_START_MAX_SECONDS",
    "START_HEARTBEAT_CODE",
    "START_HEARTBEAT_ENV",
    "clear_start_heartbeat",
    "heartbeat_is_within_window",
    "load_start_heartbeat",
    "start_heartbeat_path",
]
