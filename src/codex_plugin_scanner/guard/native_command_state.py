"""Thin client for the native Guard Cloud command ledger.

The runtime keeps the jobs waiting for a local confirmation, the signed grants
that confirm them and the replay rows of consumed jobs. Each operation is one
immediate SQLite transaction in the runtime, so concurrent writers in any
process cannot drop each other's rows. This module only spawns the runtime and
reports its answer or its refusal.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

COMMAND_STATE_COMMAND = "command-state"
COMMAND_STATE_FEATURE = "native-command-state-v3"
COMMAND_STATE_SCHEMA = "command-state.v1"
COMMAND_STATE_TIMEOUT_SECONDS = 10.0
# The largest answer is the pending list: at most 64 rows of job identity.
COMMAND_STATE_OUTPUT_LIMIT_BYTES = 1024 * 1024


class CommandStateUnavailableError(RuntimeError):
    """The runtime gave no answer: missing, without the ledger, or failed."""

    reason: str = "native_command_state_unavailable"


class CommandStateRefusedError(ValueError):
    """The runtime answered with a refusal code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def native_command_state(guard_home: Path, op: str, *, now: str, **fields: object) -> object:
    """Run one ledger operation and return its result.

    Fields that are ``None`` are left out of the request. Raises
    ``CommandStateRefusedError`` with the runtime's code when it refuses, and
    ``CommandStateUnavailableError`` when no capable runtime answers.
    """

    from .native_runtime import _run_native_process, native_runtime_status

    request = {
        "schema": COMMAND_STATE_SCHEMA,
        "guard_home": str(guard_home),
        "op": op,
        "now": now,
        **{key: value for key, value in fields.items() if value is not None},
    }
    deadline = time.monotonic() + COMMAND_STATE_TIMEOUT_SECONDS
    status = native_runtime_status(deadline_monotonic=deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or COMMAND_STATE_FEATURE not in status.capabilities.features
    ):
        raise CommandStateUnavailableError
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CommandStateUnavailableError
    output = _run_native_process(
        status.identity.path,
        (COMMAND_STATE_COMMAND, "--stdin"),
        input_text=json.dumps(request, separators=(",", ":")),
        timeout_seconds=remaining,
        output_limit=COMMAND_STATE_OUTPUT_LIMIT_BYTES,
    )
    if output is None:
        raise CommandStateUnavailableError
    try:
        response = json.loads(output)
    except ValueError as error:
        raise CommandStateUnavailableError from error
    if not isinstance(response, dict):
        raise CommandStateUnavailableError
    if response.get("ok") is not True:
        code = response.get("error")
        raise CommandStateRefusedError(code if isinstance(code, str) and code else "command_state_unavailable")
    return response.get("result")


__all__ = [
    "COMMAND_STATE_FEATURE",
    "CommandStateRefusedError",
    "CommandStateUnavailableError",
    "native_command_state",
]
