"""Hand ``hol-guard daemon --serve`` to the native daemon process.

The native runtime serves the approval center itself when it advertises
``daemon-serve-v1``. This process replaces itself with it (same pid, so the
launcher's spawn and liveness checks still name the process it started) after
putting the one-line launch configuration on its standard input.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

SERVE_FEATURE = "daemon-serve-v1"
SERVE_COMMAND = "daemon-serve"
LAUNCH_SCHEMA = "guard-daemon-serve-launch.v1"
# Set to "1" to serve from the native daemon process.
NATIVE_SERVE_ENV = "HOL_GUARD_NATIVE_DAEMON_SERVE"
_LAUNCH_NONCE_ENV = "HOL_GUARD_DAEMON_LAUNCH_NONCE"
_NONCE_PATTERN = re.compile(r"[0-9a-f]{64}")
# A pipe holds at least this much on every supported platform, so the write
# never blocks before the exec.
_MAX_LAUNCH_BYTES = 16 * 1024


def native_serve_executable(guard_home: Path) -> Path | None:
    """The native runtime that serves the daemon, or ``None`` to stay in Python."""

    if os.name != "posix" or os.environ.get(NATIVE_SERVE_ENV, "").strip() == "0":
        return None
    from ..adapters.native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(SERVE_FEATURE, guard_home=guard_home)


def launch_configuration(guard_home: Path, port: int, *, user_home: Path | None = None) -> dict[str, object]:
    """The launch line the native daemon reads from its standard input."""

    from ...version import __version__
    from ..native_approval_gate import session_signals
    from ..sqlite_tuning import sqlite_connect_timeout_seconds
    from .dashboard_bundle import dashboard_build_id
    from .manager import (
        GUARD_DAEMON_COMPATIBILITY_VERSION,
        _current_guard_daemon_runtime_fingerprint,
        _current_guard_daemon_source_root,
        _daemon_state_executable,
    )
    from .native_edge_handshake import _daemon_fingerprint, _user_home, guard_cli_command
    from .server import _guard_daemon_idle_timeout_seconds

    home = os.path.abspath(guard_home)
    config: dict[str, object] = {
        "schema": LAUNCH_SCHEMA,
        "guard_home": home,
        "port": port,
        "store_path": os.path.join(home, "guard.db"),
        "source": "default",
        "busy_timeout_ms": max(1, min(60_000, int(sqlite_connect_timeout_seconds() * 1000))),
        "cwd": os.getcwd(),
        "cli_command": guard_cli_command(),
        "workers": True,
        "state": {
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "package_version": __version__,
            "executable": _daemon_state_executable(),
            "source_root": _current_guard_daemon_source_root(),
            "runtime_fingerprint": _current_guard_daemon_runtime_fingerprint(),
        },
    }
    optional: dict[str, object | None] = {
        "dashboard_build": dashboard_build_id(Path(__file__).with_name("static")),
        "user_home": str(user_home) if user_home is not None else _user_home(),
        "session_signals": session_signals() or None,
        "daemon_fingerprint": _daemon_fingerprint(),
        "idle_timeout_seconds": _guard_daemon_idle_timeout_seconds(Path(home)),
    }
    config.update({key: value for key, value in optional.items() if value is not None})
    nonce = os.environ.get(_LAUNCH_NONCE_ENV, "")
    if _NONCE_PATTERN.fullmatch(nonce):
        config["launch_nonce"] = nonce
    return config


def exec_native_daemon(guard_home: Path, port: int, *, user_home: Path | None = None) -> None:
    """Replace this process with the native daemon; returns when it cannot."""

    executable = native_serve_executable(guard_home)
    if executable is None:
        return
    line = (
        json.dumps(launch_configuration(guard_home, port, user_home=user_home), separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    if len(line) > _MAX_LAUNCH_BYTES:
        return
    argv = [
        str(executable),
        SERVE_COMMAND,
        "--guard-home",
        os.path.abspath(guard_home),
        "--port",
        str(port),
    ]
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, line)
    finally:
        os.close(write_end)
    sys.stdout.flush()
    sys.stderr.flush()
    os.dup2(read_end, 0)
    os.close(read_end)
    os.execv(str(executable), argv)


__all__ = ["LAUNCH_SCHEMA", "NATIVE_SERVE_ENV", "SERVE_FEATURE", "exec_native_daemon", "launch_configuration"]
