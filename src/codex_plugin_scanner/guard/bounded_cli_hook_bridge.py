"""Hook command for harnesses whose hooks the native runtime answers.

The native runtime reads the install-time config, asks the daemon and fails
closed on its own. The native ``harness_adapter`` kind writes the config and
names the runtime. Python keeps the frozen ``__guard-bounded-hook`` entry,
which hands a stored launch to the runtime or refuses it with a repair message.
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from .bounded_cli_hook_native import NATIVE_BOUNDED_HOOK_COMMAND, NATIVE_BOUNDED_HOOK_FEATURE, NATIVE_MUSE_HOOK_FEATURE
from .hook_failure_bridge import RUNTIME_MISSING

_TRAILING_MANAGED_MARKERS = frozenset({"HOL_GUARD_MANAGED_ZCODE"})
# The native bridge answers within the hook deadline; this only bounds a
# runtime that stopped answering.
_NATIVE_EXIT_GRACE_SECONDS = 2.0


def _config_argv(argv: Sequence[str]) -> dict[str, object] | None:
    # ZCode hook commands end with "# <marker>". POSIX shells drop that comment,
    # but cmd.exe has no comment syntax and passes both words as arguments.
    if not (len(argv) == 1 or (len(argv) == 3 and argv[1] == "#" and argv[2] in _TRAILING_MANAGED_MARKERS)):
        return None
    try:
        config = json.loads(argv[0])
    except ValueError:
        return None
    return config if isinstance(config, dict) else None


def _refuse(_harness: str) -> int:
    """Block a hook the native runtime cannot answer; stderr names the repair."""

    print(RUNTIME_MISSING, file=sys.stderr)
    return 2


def main_from_argv(argv: Sequence[str]) -> int:
    """Hand a frozen Guard's ``__guard-bounded-hook`` call to the native runtime.

    The signed Desktop proxy falls back to this when its proxy cannot run.
    The runtime reads the hook from the inherited stdin; without one the hook
    is blocked with a repair message.
    """

    started = time.monotonic()
    config = _config_argv(argv)
    harness = config.get("harness") if config is not None else None
    harness = harness if isinstance(harness, str) else "unknown"
    timeout = config.get("timeout_seconds") if config is not None else None
    if config is None or isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        return _refuse(harness)
    if not math.isfinite(timeout) or timeout <= 0:
        return _refuse(harness)
    guard_home = config.get("guard_home")
    deadline = started + float(timeout)
    from .native_hook_bridge import native_hook_bridge_executable

    feature = NATIVE_MUSE_HOOK_FEATURE if harness == "muse" else NATIVE_BOUNDED_HOOK_FEATURE
    try:
        native = native_hook_bridge_executable(
            feature,
            guard_home=Path(guard_home) if isinstance(guard_home, str) and guard_home else None,
            deadline_monotonic=deadline,
        )
    except (OSError, RuntimeError, ValueError):
        native = None
    remaining = deadline - time.monotonic()
    if native is None or remaining <= 0:
        return _refuse(harness)
    budgeted = json.dumps({**config, "timeout_seconds": remaining}, ensure_ascii=True, separators=(",", ":"))
    sys.stdout.flush()
    try:
        completed = subprocess.run(
            [str(native), NATIVE_BOUNDED_HOOK_COMMAND, budgeted, *argv[1:]],
            timeout=remaining + _NATIVE_EXIT_GRACE_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return _refuse(harness)
    return completed.returncode


__all__ = [
    "NATIVE_BOUNDED_HOOK_COMMAND",
    "NATIVE_BOUNDED_HOOK_FEATURE",
    "RUNTIME_MISSING",
    "main_from_argv",
]
