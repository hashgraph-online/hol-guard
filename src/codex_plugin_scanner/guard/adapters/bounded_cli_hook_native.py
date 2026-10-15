"""Native runtime launcher for bounded CLI hooks."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path

NATIVE_BOUNDED_HOOK_COMMAND = "bounded-hook-bridge"
NATIVE_BOUNDED_HOOK_FEATURE = "bounded-hook-bridge-v1"
# Harnesses whose hook the native runtime answers from the daemon itself.
_NATIVE_BOUNDED_HOOK_HARNESSES = frozenset(
    {"copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline", "opencode", "grok"}
)
_NATIVE_ELAPSED_ENV = "HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS"
_NATIVE_DAEMON_TRIED_ENV = "HOL_GUARD_BOUNDED_NATIVE_DAEMON_TRIED"


def bounded_python_argv(argv: Sequence[object]) -> list[object]:
    """The Python bridge argv inside a native launcher prefix, else ``argv``.

    The native runtime answers a bounded hook from the daemon itself and runs
    the Python bridge argv that follows its subcommand for everything else, so
    a native and a Python registration of one hook name the same bridge.
    """
    values = list(argv)
    if len(values) > 2 and isinstance(values[0], str) and values[0] and values[1] == NATIVE_BOUNDED_HOOK_COMMAND:
        return values[2:]
    return values


def daemon_start_command(
    python_executable: str, package_root: Path, guard_home: Path, cli_args: Sequence[str]
) -> list[str]:
    """The daemon-start argv the native bridge runs when the daemon is unreachable.

    The native bridge runs it only on that failure path, then asks the daemon
    once more or fails the hook closed; it never runs the Python bridge.
    """
    from ..codex_hook_launch_runtime import isolated_daemon_start_command

    args = list(cli_args)
    home_dir = next((Path(args[i + 1]) for i in range(len(args) - 1) if args[i] == "--home"), None)
    return list(
        isolated_daemon_start_command(python_executable, package_root, guard_home.resolve(strict=False), home_dir)
    )


def native_bridge_executable(harness: str) -> Path | None:
    """The native runtime that launches ``harness`` hooks, or None for Python."""

    # HOL_GUARD_BOUNDED_HOOK_BRIDGE=python keeps the Python bridge argv. Contract
    # tests set it so a subprocess install and the parent verifier agree. The
    # Python bridge is the same fallback used when the native runtime is absent.
    if harness not in _NATIVE_BOUNDED_HOOK_HARNESSES or os.environ.get("HOL_GUARD_BOUNDED_HOOK_BRIDGE") == "python":
        return None
    from .native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(NATIVE_BOUNDED_HOOK_FEATURE)


def take_native_handoff_environment() -> tuple[Callable[[float], float], bool]:
    """Read and drop what the native bridge passed, so no hook child inherits it.

    Returns the time the native bridge already spent on this hook, capped at a
    limit, and whether it already asked the daemon. The elapsed time only ever
    shortens the deadline, and a hook the daemon already saw goes straight to
    the isolated CLI evaluation, so neither value can loosen a decision.
    """

    raw_elapsed = os.environ.pop(_NATIVE_ELAPSED_ENV, None)
    daemon_tried = os.environ.pop(_NATIVE_DAEMON_TRIED_ENV, None) == "1"

    def elapsed_seconds(limit: float) -> float:
        if raw_elapsed is None or not raw_elapsed.isascii() or not raw_elapsed.isdigit():
            return 0.0
        return min(int(raw_elapsed) / 1000.0, max(0.0, limit))

    return elapsed_seconds, daemon_tried


__all__ = [
    "NATIVE_BOUNDED_HOOK_COMMAND",
    "NATIVE_BOUNDED_HOOK_FEATURE",
    "bounded_python_argv",
    "native_bridge_executable",
    "take_native_handoff_environment",
]
