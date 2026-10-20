"""Daemon recovery for a frozen Guard's Python bounded hook bridge.

A frozen Guard has no cold evaluator. When its daemon does not answer, the
bridge runs the frozen recovery entrypoint and asks the daemon once more;
when that fails too, the hook fails closed.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Sequence
from pathlib import Path

from ..codex_hook_launch_runtime import isolated_hook_environment, run_isolated_hook_process
from .bounded_cli_hook_native import frozen_daemon_start_command

_RECOVERY_TIMEOUT_SECONDS = 3.0
_MINIMUM_RECOVERY_SECONDS = 1.5
_ANSWER_RESERVE_SECONDS = 1.0


def ask_after_frozen_recovery(
    *,
    guard_home: Path,
    harness: str,
    input_text: str,
    cli_args: Sequence[str],
    deadline: float,
) -> tuple[str, str, int] | None:
    """Recover the daemon and ask it once more, or None to fail the hook closed."""

    from .bounded_cli_hook_daemon import try_daemon_hook

    window = min(_RECOVERY_TIMEOUT_SECONDS, deadline - _ANSWER_RESERVE_SECONDS - time.monotonic())
    if window < _MINIMUM_RECOVERY_SECONDS:
        return None
    environment = isolated_hook_environment()
    environment["HOL_GUARD_HOOK_FAILURE_KIND"] = "transport-failure"
    result = run_isolated_hook_process(
        frozen_daemon_start_command(sys.executable, guard_home, cli_args),
        input_text="",
        cwd=Path.home(),
        environment=environment,
        timeout_seconds=window,
        allow_windows_breakaway=True,
    )
    if result.returncode != 0 or result.timed_out or result.output_limit_exceeded:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    return try_daemon_hook(
        guard_home=guard_home,
        harness=harness,
        input_text=input_text,
        timeout_seconds=remaining,
        deadline_monotonic=deadline,
    )


__all__ = ["ask_after_frozen_recovery"]
