"""Thin client for the native automatic-update bookkeeping.

The runtime owns the saved ``guard_auto_update_state`` row: whether a check is
due, whether a fetched status should be applied, and what an installer run
leaves behind. Each step is one immediate SQLite transaction in the runtime.
This module only spawns the runtime and returns its answer.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

AUTO_UPDATE_STATE_COMMAND = "auto-update-state"
AUTO_UPDATE_STATE_FEATURE = "native-auto-update-state-v1"
AUTO_UPDATE_STATE_SCHEMA = "auto-update-state.v1"
AUTO_UPDATE_STATE_TIMEOUT_SECONDS = 10.0
AUTO_UPDATE_STATE_OUTPUT_LIMIT_BYTES = 64 * 1024


class AutoUpdateStateError(RuntimeError):
    """The runtime gave no answer, or refused the request."""

    def __init__(self, code: str = "native_auto_update_state_unavailable") -> None:
        super().__init__(code)
        self.code = code


def native_auto_update_state(guard_home: Path, op: str, *, now: str, **fields: object) -> object:
    """Run one bookkeeping step and return its result.

    Fields that are ``None`` are left out of the request; the runtime reads an
    absent ``status`` or ``update_payload`` as a fetch or run that raised.
    Raises ``AutoUpdateStateError`` when no capable runtime answers or when it
    refuses.
    """

    from .native_runtime import _run_native_process, native_runtime_status

    request = {
        "schema": AUTO_UPDATE_STATE_SCHEMA,
        "guard_home": str(guard_home),
        "op": op,
        "now": now,
        **{key: value for key, value in fields.items() if value is not None},
    }
    deadline = time.monotonic() + AUTO_UPDATE_STATE_TIMEOUT_SECONDS
    status = native_runtime_status(deadline_monotonic=deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or AUTO_UPDATE_STATE_FEATURE not in status.capabilities.features
    ):
        raise AutoUpdateStateError
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AutoUpdateStateError
    try:
        input_text = json.dumps(request, separators=(",", ":"))
    except (TypeError, ValueError) as error:
        raise AutoUpdateStateError("auto_update_state_request_unencodable") from error
    output = _run_native_process(
        status.identity.path,
        (AUTO_UPDATE_STATE_COMMAND, "--stdin"),
        input_text=input_text,
        timeout_seconds=remaining,
        output_limit=AUTO_UPDATE_STATE_OUTPUT_LIMIT_BYTES,
    )
    if output is None:
        raise AutoUpdateStateError
    try:
        response = json.loads(output)
    except ValueError as error:
        raise AutoUpdateStateError from error
    if not isinstance(response, dict):
        raise AutoUpdateStateError
    if response.get("ok") is not True:
        code = response.get("error")
        raise AutoUpdateStateError(code if isinstance(code, str) and code else "auto_update_state_unavailable")
    return response.get("result")


__all__ = [
    "AUTO_UPDATE_STATE_FEATURE",
    "AutoUpdateStateError",
    "native_auto_update_state",
]
