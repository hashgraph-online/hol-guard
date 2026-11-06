"""Daemon recovery for the Python bounded hook bridge.

The bridge has no cold evaluator. When the daemon does not answer, it runs
the daemon-start command once, waits for a daemon other than the one that
failed to come up, and asks that daemon once; when none answers in time,
the hook fails closed. The native bridge recovers the same way
(`hook_bridge_daemon_start.rs`).
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from pathlib import Path

from ..codex_hook_launch_runtime import isolated_hook_environment, run_isolated_hook_process
from ..daemon.auth_token import load_guard_daemon_auth_token
from ..private_file_io import read_private_regular_text

# The native bridge's START_TIMEOUT, MINIMUM_START, RETRY_RESERVE,
# MINIMUM_REQUEST and START_WAIT.
_START_TIMEOUT_SECONDS = 8.0
_MINIMUM_START_SECONDS = 1.5
_RETRY_RESERVE_SECONDS = 1.0
_MINIMUM_REQUEST_SECONDS = 0.5
_START_WAIT_SECONDS = 8.0
_FIRST_POLL_SECONDS = 0.05
_MAX_POLL_SECONDS = 0.25

DaemonIdentity = tuple[str, str]


def daemon_identity(guard_home: Path) -> DaemonIdentity | None:
    """The daemon state text and auth token that name the current daemon, or None.

    A state that names no daemon, such as the ``{}`` the start path writes
    before a daemon comes up, is no daemon yet.
    """

    from .bounded_cli_hook_daemon import daemon_state_origin

    state = read_private_regular_text(
        guard_home / "daemon-state.json",
        max_bytes=64 * 1024,
        require_private_parent=True,
    )
    if state is None or daemon_state_origin(state) is None:
        return None
    token = load_guard_daemon_auth_token(guard_home)
    return None if token is None else (state, token)


def ask_after_daemon_recovery(
    *,
    start_command: Sequence[str],
    guard_home: Path,
    harness: str,
    input_text: str,
    deadline: float,
    failed: DaemonIdentity | None,
) -> tuple[str, str, int] | None:
    """Start the daemon and ask a new one once, or None to fail the hook closed.

    ``failed`` names the daemon that already saw the hook; it is never asked
    again, so a slow daemon cannot decide the same hook twice.
    """

    from .bounded_cli_hook_daemon import try_daemon_hook

    left = deadline - time.monotonic()
    if not start_command or left < _MINIMUM_START_SECONDS:
        return None
    timeout = min(left - _RETRY_RESERVE_SECONDS, _START_TIMEOUT_SECONDS)
    environment = isolated_hook_environment()
    environment["HOL_GUARD_HOOK_FAILURE_KIND"] = "transport-failure"
    result = run_isolated_hook_process(
        tuple(start_command),
        input_text="",
        cwd=Path.home(),
        environment=environment,
        timeout_seconds=timeout,
        allow_windows_breakaway=True,
    )
    if result.returncode != 0 or result.timed_out or result.output_limit_exceeded:
        return None
    # The start command only schedules the daemon, so wait for it to publish
    # its state with a short doubling backoff.
    stop = min(time.monotonic() + _START_WAIT_SECONDS, deadline - _MINIMUM_REQUEST_SECONDS)
    pause = _FIRST_POLL_SECONDS
    while True:
        current = daemon_identity(guard_home)
        if current is not None and current != failed:
            break
        if time.monotonic() + pause >= stop:
            return None
        time.sleep(pause)
        pause = min(pause * 2, _MAX_POLL_SECONDS)
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


__all__ = ["DaemonIdentity", "ask_after_daemon_recovery", "daemon_identity"]
