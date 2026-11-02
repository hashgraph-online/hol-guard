"""One JSON request to a native runtime command on behalf of an MDM module."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from typing import cast

_STATUS_TIMEOUT_SECONDS = 10.0


def runtime_answer(
    feature: str,
    command: str,
    request: Mapping[str, object] | str | Callable[[], Mapping[str, object] | None],
    *,
    output_limit: int,
    timeout_seconds: float | None = None,
    deadline: float | None = None,
    status_timeout_seconds: float = _STATUS_TIMEOUT_SECONDS,
    extra_features: tuple[str, ...] = (),
    stop_event: threading.Event | None = None,
) -> dict[str, object] | None:
    """The runtime's JSON object answer to one request.

    `None` when no compatible runtime offers `feature` or its answer is not a
    JSON object. A caller that maps an unencodable request to its own error
    passes the encoded text, so runtime faults never read as bad input. A
    `deadline` bounds the status check and the command together; without one
    the command gets `timeout_seconds` of its own. The status check alone
    never takes longer than `status_timeout_seconds`. A callable request is
    built after the status check, so it can size itself to what is left of
    the deadline; it returns `None` to send nothing. Setting `stop_event`
    kills the command and answers `None`.
    """

    from ..native_runtime import _run_native_process, native_runtime_status

    status_deadline = time.monotonic() + status_timeout_seconds
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
    if callable(request):
        built = request()
        if built is None:
            return None
        request = built
    input_text = request if isinstance(request, str) else json.dumps(request, sort_keys=True)
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
        **({"stop_event": stop_event} if stop_event is not None else {}),
    )
    try:
        answer = cast(object, json.loads(output)) if output is not None else None
    except ValueError:
        return None
    return cast(dict[str, object], answer) if isinstance(answer, dict) else None


def runtime_offers(feature: str, *, status_timeout_seconds: float = _STATUS_TIMEOUT_SECONDS) -> bool:
    """Whether a compatible runtime offers `feature`, without asking it anything."""

    from ..native_runtime import native_runtime_status

    status = native_runtime_status(deadline_monotonic=time.monotonic() + status_timeout_seconds)
    return bool(
        status.available
        and status.compatible
        and status.identity is not None
        and status.capabilities is not None
        and feature in status.capabilities.features
    )
