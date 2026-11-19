"""Owner-private Windows state ops answered by the resident runtime.

A process that already holds a live resident client stream for a Guard home
sends each private-state request inside that home over that stream to the
resident, which runs the same held handles and owner/DACL checks as the
one-shot ``windows-private-state`` command without starting a process per op.
Only a stream this process already holds is borrowed, waiting briefly for one
in use to be parked: asking never starts a client stream, so it never brings
back a resident that was stopped.
``None`` means the resident is not this request's route (no idle stream here
for the home, a runtime without the operation, or a resident or transport
failure), and the caller starts the one-shot command.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Mapping
from pathlib import Path

RESIDENT_FEATURE = "native-windows-private-state-resident-v1"
_OPERATION = "windows_private_state"
_SCHEMA = "windows-private-state-resident.v1"
_TIMEOUT_SECONDS = 10.0
# A busy stream frees up within one resident round trip; this bounds the wait
# for it so an op that lands mid-request does not start a one-shot process.
_IDLE_WAIT_SECONDS = 1.0


def resident_private_state_answer(request: Mapping[str, object], *, output_limit: int) -> dict[str, object] | None:
    """The resident's answer to one private-state request, or ``None`` to use the command."""

    if os.name != "nt":
        return None
    from .native_resident_client import native_resident_client_request, native_resident_guard_home_containing
    from .native_runtime import _isolated_environment, native_runtime_status

    deadline = time.monotonic() + _TIMEOUT_SECONDS
    status = native_runtime_status(deadline_monotonic=deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or RESIDENT_FEATURE not in status.capabilities.features
    ):
        return None
    paths = tuple(Path(str(request[field])) for field in ("directory", "private_root") if field in request)
    guard_home = native_resident_guard_home_containing(status.identity.path, paths)
    if guard_home is None:
        return None
    envelope = {"operation": _OPERATION, "request": {"guard_home": str(guard_home), "state": dict(request)}}
    response = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        deadline_monotonic=deadline,
        idle_only=True,
        idle_wait_seconds=_IDLE_WAIT_SECONDS,
    )
    if response is None or len(response) > output_limit:
        return None
    try:
        decoded = json.loads(response)
    except ValueError:
        return None
    if not isinstance(decoded, dict) or decoded.get("schema") != _SCHEMA:
        return None
    answer = decoded.get("answer")
    return answer if isinstance(answer, dict) else None


__all__ = ["RESIDENT_FEATURE", "resident_private_state_answer"]
