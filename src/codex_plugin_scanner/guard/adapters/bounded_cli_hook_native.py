"""Native runtime launcher for bounded CLI hooks."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

NATIVE_BOUNDED_HOOK_COMMAND = "bounded-hook-bridge"
NATIVE_BOUNDED_HOOK_FEATURE = "bounded-hook-bridge-v1"
# Harnesses whose hook the native runtime answers from the daemon itself.
_NATIVE_BOUNDED_HOOK_HARNESSES = frozenset(
    {"copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline", "opencode", "grok"}
)


def bounded_python_argv(argv: Sequence[object]) -> list[object]:
    """The Python bridge argv inside a native launcher prefix, else ``argv``.

    The native runtime answers a bounded hook from the daemon itself and never
    runs the Python bridge argv that follows its subcommand; the argv keeps a
    native and a Python registration of one hook naming the same bridge.
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


def frozen_daemon_start_command(executable: str, guard_home: Path, cli_args: Sequence[str]) -> list[str]:
    """The frozen Guard's daemon-recovery argv for the native bridge's failure path.

    A frozen Guard has no interpreter to run the source install's bootstrap,
    so the native bridge runs the frozen recovery entrypoint instead.
    """
    from ..frozen_runtime_commands import frozen_daemon_recovery_command

    args = list(cli_args)
    home_dir = next((Path(args[i + 1]) for i in range(len(args) - 1) if args[i] == "--home"), Path.home())
    return list(frozen_daemon_recovery_command(guard_home, home_dir, executable=executable))


def native_bridge_executable(harness: str, *, guard_home: Path | None = None) -> Path | None:
    """The native runtime that launches ``harness`` hooks, or None for Python.

    A frozen build names its runtime's durable copy under ``guard_home``.
    """

    # HOL_GUARD_BOUNDED_HOOK_BRIDGE=python keeps the Python bridge argv. Contract
    # tests set it so a subprocess install and the parent verifier agree. The
    # Python bridge is the same fallback used when the native runtime is absent.
    if harness not in _NATIVE_BOUNDED_HOOK_HARNESSES or os.environ.get("HOL_GUARD_BOUNDED_HOOK_BRIDGE") == "python":
        return None
    from .native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(NATIVE_BOUNDED_HOOK_FEATURE, guard_home=guard_home)


__all__ = [
    "NATIVE_BOUNDED_HOOK_COMMAND",
    "NATIVE_BOUNDED_HOOK_FEATURE",
    "bounded_python_argv",
    "frozen_daemon_start_command",
    "native_bridge_executable",
]
