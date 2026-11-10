"""Hand ``hol-guard daemon --serve`` to the native daemon process.

The native runtime serves the approval center itself when it advertises
``daemon-serve-v1``. This process replaces itself with it (same pid, so the
launcher's spawn and liveness checks still name the process it started) after
putting the one-line launch configuration on its standard input.

Windows has no exec, so there this process starts the native daemon, names
itself in the launch line as the pid to report, keeps the daemon's standard
input open and waits. The daemon stops when that input closes, so ending this
process ends the daemon.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
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

    if os.name not in {"posix", "nt"} or os.environ.get(NATIVE_SERVE_ENV, "").strip() == "0":
        return None
    from ..adapters.native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(SERVE_FEATURE, guard_home=guard_home)


def _cached_trust_status(guard_home: Path) -> dict[str, object] | None:
    """The policy-integrity state the daemon publishes as its trust status."""

    from ..store import GuardStore

    try:
        return GuardStore(guard_home, prime_policy_integrity=False).get_cached_policy_integrity_state()
    except Exception:
        return None


def launch_configuration(guard_home: Path, port: int, *, user_home: Path | None = None) -> dict[str, object]:
    """The launch line the native daemon reads from its standard input."""

    from ...version import __version__
    from ..native_approval_gate import session_signals
    from ..native_daemon_manage import (
        GUARD_DAEMON_COMPATIBILITY_VERSION,
        _current_guard_daemon_runtime_fingerprint,
        _current_guard_daemon_source_root,
        _daemon_state_executable,
    )
    from ..routes.request_handler import _guard_daemon_idle_timeout_seconds
    from ..sqlite_tuning import sqlite_connect_timeout_seconds
    from .dashboard_bundle import dashboard_build_id
    from .native_edge_handshake import _daemon_fingerprint, _user_home, guard_cli_command

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
        "dashboard_dir": str(Path(__file__).with_name("static").resolve()),
        "user_home": str(user_home) if user_home is not None else _user_home(),
        "session_signals": session_signals() or None,
        "daemon_fingerprint": _daemon_fingerprint(),
        "idle_timeout_seconds": _guard_daemon_idle_timeout_seconds(Path(home)),
    }
    config.update({key: value for key, value in optional.items() if value is not None})
    trust_status = _cached_trust_status(Path(home))
    if trust_status is not None:
        state = config["state"]
        assert isinstance(state, dict)
        state["trust_status"] = trust_status
    nonce = os.environ.get(_LAUNCH_NONCE_ENV, "")
    if _NONCE_PATTERN.fullmatch(nonce):
        config["launch_nonce"] = nonce
    return config


def exec_native_daemon(guard_home: Path, port: int, *, user_home: Path | None = None) -> None:
    """Replace this process with the native daemon; returns when it cannot."""

    executable = native_serve_executable(guard_home)
    if executable is None:
        return
    config = launch_configuration(guard_home, port, user_home=user_home)
    if os.name == "nt":
        config["launcher_pid"] = os.getpid()
    line = json.dumps(config, separators=(",", ":")).encode("utf-8") + b"\n"
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
    if os.name == "nt":
        sys.exit(_run_native_daemon(argv, line))
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


def _run_native_daemon(argv: list[str], line: bytes) -> int:
    """Runs the native daemon as a child that lives as long as this process."""

    sys.stdout.flush()
    sys.stderr.flush()
    process = subprocess.Popen(argv, stdin=subprocess.PIPE)
    stdin = process.stdin
    if stdin is None:
        process.kill()
        return 1
    try:
        stdin.write(line)
        stdin.flush()
        # The input stays open: the daemon stops when it closes.
        return process.wait()
    except KeyboardInterrupt:
        return 0
    finally:
        stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


__all__ = ["LAUNCH_SCHEMA", "NATIVE_SERVE_ENV", "SERVE_FEATURE", "exec_native_daemon", "launch_configuration"]
