"""One JSON request to a native runtime command on behalf of an MDM module."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import cast

_STATUS_TIMEOUT_SECONDS = 10.0


def runtime_answer(
    feature: str,
    command: str,
    request: Mapping[str, object] | str,
    *,
    output_limit: int,
    timeout_seconds: float | None = None,
    deadline: float | None = None,
    extra_features: tuple[str, ...] = (),
) -> dict[str, object] | None:
    """The runtime's JSON object answer to one request.

    `None` when no compatible runtime offers `feature` or its answer is not a
    JSON object. A caller that maps an unencodable request to its own error
    passes the encoded text, so runtime faults never read as bad input. A
    `deadline` bounds the status check and the command together; without one
    the command gets `timeout_seconds` of its own.
    """

    from ..native_runtime import _run_native_process, native_runtime_status

    input_text = request if isinstance(request, str) else json.dumps(request, sort_keys=True)
    status_deadline = time.monotonic() + _STATUS_TIMEOUT_SECONDS
    status = native_runtime_status(
        deadline_monotonic=status_deadline if deadline is None else min(deadline, status_deadline)
    )
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or any(name not in status.capabilities.features for name in (feature, *extra_features))
    ):
        return None
    if deadline is not None:
        timeout_seconds = deadline - time.monotonic()
    if timeout_seconds is None or timeout_seconds <= 0:
        return None
    output = _run_native_process(
        status.identity.path,
        (command, "--stdin"),
        input_text=input_text,
        timeout_seconds=timeout_seconds,
        output_limit=output_limit,
    )
    try:
        answer = cast(object, json.loads(output)) if output is not None else None
    except ValueError:
        return None
    return cast(dict[str, object], answer) if isinstance(answer, dict) else None
