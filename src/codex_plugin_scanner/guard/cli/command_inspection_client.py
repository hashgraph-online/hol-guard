"""Ask the local daemon to inspect one command, never turning an outage into a verdict.

This module only orchestrates the daemon round trip for ``hol-guard command
test`` and ``command explain``. The daemon's native runtime owns the verdict.
When it cannot answer, the result is a typed ``native_unavailable`` payload
whose ``readiness`` block names why; it is never ``no_match``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from ..native_daemon_client import GuardDaemonRequestError
from ..runtime.command_inspection import inspection_readiness, unavailable_command_inspection

# A freshly started runtime may need a moment before its first native answer.
# Inspection has no side effects, so an unavailable answer is asked again
# until this budget runs out; the last unavailable answer is then reported.
WARMUP_BUDGET_SECONDS = 5.0
WARMUP_POLL_SECONDS = 0.5

Inspect = Callable[[dict[str, object]], dict[str, object]]


def _still_warming(payload: dict[str, object]) -> bool:
    if payload.get("status") != "native_unavailable":
        return False
    readiness = payload.get("readiness")
    # A failed native evaluation is a terminal block, not a cold runtime.
    return not (isinstance(readiness, dict) and readiness.get("state") == "failed")


def _with_readiness(payload: dict[str, object], reason_code: str) -> dict[str, object]:
    if payload.get("status") == "native_unavailable" and not isinstance(payload.get("readiness"), dict):
        payload["readiness"] = inspection_readiness(reason_code)
    return payload


def inspect_through_daemon(
    command_text: str,
    *,
    guard_home: Path,
    workspace: Path,
    home: Path,
    client_for: Callable[[Path], object],
    ensure_daemon: Callable[..., object],
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    """Return the daemon's inspection, or a typed unavailable result."""

    request = {"command": command_text, "cwd": str(workspace), "home_dir": str(home)}

    def unavailable(code: str) -> dict[str, object]:
        return unavailable_command_inspection(command_text, cwd=workspace, home_dir=home, reason_code=code)

    try:
        payload = client_for(guard_home).inspect_command(request)  # type: ignore[attr-defined]
    except GuardDaemonRequestError:
        try:
            ensure_daemon(guard_home, home_dir=home)
        except TimeoutError:
            return unavailable("daemon_start_timeout")
        except (RuntimeError, OSError):
            return unavailable("daemon_start_failed")
        try:
            payload = client_for(guard_home).inspect_command(request)  # type: ignore[attr-defined]
        except GuardDaemonRequestError:
            return unavailable("daemon_request_failed")
    deadline = clock() + WARMUP_BUDGET_SECONDS
    while _still_warming(payload) and clock() + WARMUP_POLL_SECONDS < deadline:
        sleep(WARMUP_POLL_SECONDS)
        try:
            payload = client_for(guard_home).inspect_command(request)  # type: ignore[attr-defined]
        except GuardDaemonRequestError:
            return unavailable("daemon_request_failed")
    return _with_readiness(payload, "native_review_unavailable")
