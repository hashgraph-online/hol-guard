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
    request: Mapping[str, object],
    *,
    timeout_seconds: float,
    output_limit: int,
) -> dict[str, object] | None:
    """The runtime's JSON object answer to one request.

    `None` when no compatible runtime offers `feature` or its answer is not a
    JSON object. A request that cannot be encoded raises, so each caller keeps
    its own error for it.
    """

    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status(deadline_monotonic=time.monotonic() + _STATUS_TIMEOUT_SECONDS)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or feature not in status.capabilities.features
    ):
        return None
    output = _run_native_process(
        status.identity.path,
        (command, "--stdin"),
        input_text=json.dumps(request, sort_keys=True),
        timeout_seconds=timeout_seconds,
        output_limit=output_limit,
    )
    try:
        answer = cast(object, json.loads(output)) if output is not None else None
    except ValueError:
        return None
    return cast(dict[str, object], answer) if isinstance(answer, dict) else None
