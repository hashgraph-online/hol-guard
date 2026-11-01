"""Resident bridge for the ``extension_control_terminal`` op.

Whether the session asking to enroll extension-control authority is really at
the local keyboard is decided by the resident
(``extension_control_terminal.rs``). This module runs no probe and reads no
probe output: callers collect the signals, this module frames one request,
binds the reply by ``request_id`` plus ``request_sha256`` and returns the
verdict. There is no Python fallback verdict, because a session whose locality
cannot be established is exactly the session an enrollment must refuse.
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Final

from .native_resident_decision import BoundCall, bound_resident_call

EXTENSION_CONTROL_TERMINAL_FEATURE: Final = "extension-control-terminal-v1"
_REQUEST_SCHEMA: Final = "guard-extension-control-terminal-request.v1"
_CALL: Final = BoundCall(
    operation="extension_control_terminal",
    feature=EXTENSION_CONTROL_TERMINAL_FEATURE,
    prefix="native_extension_control_terminal",
    result_schema="guard-extension-control-terminal-result.v1",
    max_request_bytes=256 * 1024,
    timeout_seconds=2.0,
    check_circuit=True,
    transport_failure="unavailable",
)
# `local` lets the caller prompt; every other verdict names the refusal it owes
# the user. An unavailable resident is not one of them: it has no verdict.
VERDICTS: Final = frozenset({"local", "remote_terminal", "interactive_local_terminal", "single_terminal"})
_REQUEST_IDS: Final = itertools.count()


def native_extension_control_terminal_verdict(
    *,
    remote_environment: tuple[str, ...],
    posix: dict[str, object] | None,
    windows: dict[str, object] | None,
    guard_home: Path | None = None,
) -> str:
    """The resident's verdict on this terminal.

    A resident that answers nothing has not placed the session somewhere else;
    it has not placed the session at all. That raises ``ResidentCallError``
    carrying this bridge's own code, so the caller refuses the enrollment for
    the runtime it could not reach instead of for a remote terminal nobody
    observed.
    """

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"extension-control-terminal-{next(_REQUEST_IDS)}",
        "remote_environment": list(remote_environment),
        "posix": posix,
        "windows": windows,
    }
    reply = bound_resident_call(_CALL, request, guard_home=guard_home)
    envelope = reply.envelope
    payload = envelope.get("payload")
    verdict = payload.get("verdict") if isinstance(payload, dict) else None
    if (
        envelope.get("status") != "ok"
        or envelope.get("code") != "ok"
        or not isinstance(verdict, str)
        or verdict not in VERDICTS
    ):
        raise reply.fail()
    reply.healthy()
    return verdict
