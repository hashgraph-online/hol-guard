"""Bounded process identity proof for a locally waiting hook.

The native runtime reads each process's start token and owner marker
(`process-identity --stdin`), with the same code the Codex hook bridge uses
to record its own identity. Without a runtime that offers it, no identity is
proven.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Mapping

CODEX_BROWSER_WAIT_PROCESS_KEY = "guard_codex_browser_wait_process"
CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY = "guard_codex_browser_wait_timeout_seconds"
_FEATURE = "native-process-identity-v1"
_SCHEMA = "process-identity.v1"
_PS_TIMEOUT_SECONDS = 0.5
_TIMEOUT_SECONDS = 5.0


def current_process_identity() -> dict[str, object] | None:
    """Capture an opaque identity that distinguishes PID reuse."""

    pid = os.getpid()
    start_token = process_start_token(pid)
    if start_token is None:
        return None
    return {"pid": pid, "startToken": start_token}


def process_identity_matches(value: object) -> bool:
    """Prove that the captured process is still the same live process."""

    if not isinstance(value, Mapping):
        return False
    try:
        identity = json.loads(json.dumps(value))
    except (TypeError, ValueError):
        return False
    answer = _ask({"op": "matches", "identity": identity})
    return answer is not None and answer.get("matches") is True


def process_start_token(pid: int, *, deadline_monotonic: float | None = None) -> str | None:
    """Return the platform-specific marker for the process currently using ``pid``."""

    if type(pid) is not int or pid <= 0:
        return None

    def request() -> dict[str, object] | None:
        remaining = _PS_TIMEOUT_SECONDS
        if deadline_monotonic is not None:
            remaining = min(remaining, deadline_monotonic - time.monotonic())
        if remaining <= 0:
            return None
        return {"op": "start_token", "pid": pid, "timeout_ms": max(1, int(remaining * 1000))}

    answer = _ask(request, deadline=deadline_monotonic)
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        return None
    token = None if answer is None else answer.get("start_token")
    return token if isinstance(token, str) and token else None


def process_owner_marker(pid: int) -> str | None:
    """Return an OS-backed owner marker for the process currently using ``pid``."""

    if type(pid) is not int or pid <= 0:
        return None
    answer = _ask({"op": "owner_marker", "pid": pid})
    marker = None if answer is None else answer.get("owner_marker")
    return marker if isinstance(marker, str) and marker else None


def _ask(
    request: dict[str, object] | Callable[[], dict[str, object] | None],
    *,
    deadline: float | None = None,
) -> dict[str, object] | None:
    def built() -> dict[str, object] | None:
        body = request() if callable(request) else request
        return None if body is None else {"schema": _SCHEMA, **body}

    if deadline is not None and time.monotonic() >= deadline:
        return None
    from .mdm.runtime_request import runtime_answer

    return runtime_answer(
        _FEATURE,
        "process-identity",
        built,
        output_limit=4096,
        timeout_seconds=None if deadline is not None else _TIMEOUT_SECONDS,
        deadline=deadline,
    )


__all__ = [
    "CODEX_BROWSER_WAIT_PROCESS_KEY",
    "CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY",
    "current_process_identity",
    "process_identity_matches",
    "process_owner_marker",
    "process_start_token",
]
