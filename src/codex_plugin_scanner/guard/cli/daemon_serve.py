"""Fast path for `hol-guard daemon --serve` without the Guard parser surface."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

_VALUE_FLAGS = frozenset({"--guard-home", "--home", "--port", "--workspace"})
# The dashboard bundle the native daemon serves.
_DASHBOARD_DIR = Path(__file__).resolve().parents[1] / "daemon" / "static"
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
        # The native daemon pins and fingerprints the bundle it serves from here.
        "dashboard_dir": str(_DASHBOARD_DIR.resolve()),
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


def guard_cli_command() -> list[str]:
    """The argv prefix that runs this Guard's own CLI."""

    if getattr(sys, "frozen", False):
        return [sys.executable]
    from ..codex_hook_launch_runtime import isolated_guard_cli_command

    package_root = Path(__file__).resolve().parents[3]
    return list(isolated_guard_cli_command(sys.executable, package_root, ("guard",)))


def _user_home() -> str | None:
    try:
        return str(Path.home())
    except RuntimeError:
        return None


def _daemon_fingerprint() -> str | None:
    """The daemon's runtime identity, or ``None`` when the runtime cannot name it.

    Without it the native daemon leaves containment health to its library steps.
    """

    from ..native_daemon_manage import current_guard_daemon_runtime_fingerprint

    try:
        return current_guard_daemon_runtime_fingerprint()
    except RuntimeError:
        return None


def is_daemon_serve_fast_path_argv(argv: Sequence[str]) -> bool:
    """Return True when argv is a bounded daemon serve launch.

    Desktop and the isolated Python launcher start the approval-center with
    `--serve` plus home/port flags. Help and unknown options stay on argparse.
    """

    tokens = list(argv)
    if tokens[:1] == ["guard"]:
        tokens = tokens[1:]
    if not tokens or tokens[0] != "daemon":
        return False
    rest = tokens[1:]
    if "--serve" not in rest or any(token in {"-h", "--help"} for token in rest):
        return False
    index = 0
    while index < len(rest):
        token = rest[index]
        if token == "--serve":
            index += 1
            continue
        if token in _VALUE_FLAGS:
            if index + 1 >= len(rest) or rest[index + 1].startswith("-"):
                return False
            index += 2
            continue
        return False
    return True


def run_daemon_serve_cli(argv: Sequence[str] | None = None) -> int:
    """Start the local approval-center without building the Guard command parser."""

    tokens = list(sys.argv[1:] if argv is None else argv)
    if tokens[:1] == ["guard"]:
        tokens = tokens[1:]
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--guard-home")
    parser.add_argument("--home")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--workspace")
    args = parser.parse_args(tokens[1:])
    if not args.serve:
        print("Choose daemon --serve.", file=sys.stderr)
        return 2

    from ..config import resolve_guard_home

    return serve_native_daemon(
        resolve_guard_home(args.guard_home or args.home),
        args.port or 0,
        user_home=Path(args.home).expanduser().resolve() if args.home else None,
    )


def serve_native_daemon(guard_home: Path, port: int, *, user_home: Path | None) -> int:
    """Hands this process to the native daemon; returns only when it cannot run."""

    exec_native_daemon(guard_home, port, user_home=user_home)
    print(
        "The Guard daemon needs HOL Guard's native runtime. Run `hol-guard doctor` to repair the installation.",
        file=sys.stderr,
    )
    return 1


__all__ = [
    "LAUNCH_SCHEMA",
    "NATIVE_SERVE_ENV",
    "SERVE_FEATURE",
    "exec_native_daemon",
    "is_daemon_serve_fast_path_argv",
    "launch_configuration",
    "native_serve_executable",
    "run_daemon_serve_cli",
    "serve_native_daemon",
]
