"""Thin client for the native Guard Cloud command-result builder.

The runtime turns a settled command job and its local execution into the
payload Guard Cloud records, including the versioned exact Review result and
its contract checks. This module only spawns the runtime and reports its
answer or its refusal.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from datetime import datetime, timezone

COMMAND_RESULT_COMMAND = "command-result"
COMMAND_RESULT_FEATURE = "native-command-result-v1"
COMMAND_RESULT_SCHEMA = "command-result.v1"
COMMAND_RESULT_TIMEOUT_SECONDS = 10.0
# A generic command posts its execution back whole, and Guard Cloud accepts
# result bodies up to 8 MiB. The request carries the job beside it, and the
# answer repeats the ids in its idempotency key.
COMMAND_RESULT_REQUEST_LIMIT_BYTES = 16 * 1024 * 1024
COMMAND_RESULT_OUTPUT_LIMIT_BYTES = COMMAND_RESULT_REQUEST_LIMIT_BYTES + 64 * 1024
_MISSING_JOB_FIELD_MESSAGES = {
    "command_job_id_missing": "Guard command job is missing an id.",
    "command_job_lease_missing": "Guard command job is missing a lease id.",
}


class CommandResultUnavailableError(RuntimeError):
    """No capable runtime answered, so the job's result cannot be built."""

    def __init__(self, code: str = "native_command_result_unavailable") -> None:
        super().__init__(code)
        self.code = code


def native_command_result(job: Mapping[str, object], execution: Mapping[str, object]) -> dict[str, object]:
    """Return the payload to post for one settled job.

    Raises ``RuntimeError`` naming the missing field for a job without an id or
    a lease id, and ``CommandResultUnavailableError`` when no capable runtime
    answers.
    """

    from .native_runtime import _run_native_process, native_runtime_status

    try:
        input_text = json.dumps(
            {
                "schema": COMMAND_RESULT_SCHEMA,
                "job": dict(job),
                "execution": dict(execution),
                "now": datetime.now(timezone.utc).isoformat(),
            },
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:
        raise CommandResultUnavailableError("command_result_request_unencodable") from error
    if len(input_text.encode("utf-8")) > COMMAND_RESULT_REQUEST_LIMIT_BYTES:
        raise CommandResultUnavailableError("command_result_request_too_large")
    deadline = time.monotonic() + COMMAND_RESULT_TIMEOUT_SECONDS
    status = native_runtime_status(deadline_monotonic=deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or COMMAND_RESULT_FEATURE not in status.capabilities.features
    ):
        raise CommandResultUnavailableError
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CommandResultUnavailableError
    output = _run_native_process(
        status.identity.path,
        (COMMAND_RESULT_COMMAND, "--stdin"),
        input_text=input_text,
        timeout_seconds=remaining,
        output_limit=COMMAND_RESULT_OUTPUT_LIMIT_BYTES,
    )
    if output is None:
        raise CommandResultUnavailableError
    try:
        response = json.loads(output)
    except ValueError as error:
        raise CommandResultUnavailableError from error
    if not isinstance(response, dict):
        raise CommandResultUnavailableError
    if response.get("ok") is not True:
        code = response.get("error")
        message = _MISSING_JOB_FIELD_MESSAGES.get(code) if isinstance(code, str) else None
        if message is not None:
            raise RuntimeError(message)
        raise CommandResultUnavailableError(code if isinstance(code, str) and code else "command_result_unavailable")
    result = response.get("result")
    if not isinstance(result, dict):
        raise CommandResultUnavailableError
    return result


__all__ = [
    "COMMAND_RESULT_FEATURE",
    "CommandResultUnavailableError",
    "native_command_result",
]
