"""Ask an idle resident for an answer a one-shot runtime command would give.

Loading the Guard configuration and composing the effective policy are each a
fresh runtime process. On a loaded Windows host every spawn costs over a
second, and the first workspace policy publish needs both, so a prompt waiting
on that publish can miss the hook deadline. The resident runs the same Rust
code for these operations, so a caller first borrows an idle resident stream
and only spawns the command when none is free or the resident cannot answer.

The resident answer is the command's own response bytes. Anything else -- no
idle stream, a framed resident refusal, an oversized or malformed reply --
returns ``None`` and the caller spawns the command, which stays the authority.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

# A borrowed stream waits this long for another caller to release one; past
# it, spawning the command is the faster answer.
_IDLE_WAIT_SECONDS = 0.05


def resident_command_answer(
    *,
    operation: str,
    feature: str,
    guard_home: Path,
    request: Mapping[str, object],
    deadline_monotonic: float,
) -> dict[str, Any] | None:
    """The resident's response to ``request``, or ``None`` to spawn the command."""

    if not guard_home.is_absolute() or deadline_monotonic - time.monotonic() <= 0:
        return None
    from .native_resident_client import native_resident_client_request
    from .native_runtime import _isolated_environment, native_runtime_status

    status = native_runtime_status(deadline_monotonic=deadline_monotonic)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or feature not in status.capabilities.features
    ):
        return None
    try:
        payload = json.dumps({"operation": operation, "request": dict(request)}, separators=(",", ":"))
    except (TypeError, ValueError):
        return None
    response = native_resident_client_request(
        executable=status.identity.path,
        guard_home=Path(os.path.abspath(guard_home)),
        environment=_isolated_environment(),
        payload=payload.encode("utf-8"),
        deadline_monotonic=deadline_monotonic,
        idle_only=True,
        idle_wait_seconds=_IDLE_WAIT_SECONDS,
    )
    if response is None:
        return None
    try:
        decoded = json.loads(response)
    except ValueError:
        return None
    # A command response always says whether it succeeded; a framed resident
    # refusal is ``{"error": code}`` alone and goes back to the command.
    if not isinstance(decoded, dict) or not isinstance(decoded.get("ok"), bool):
        return None
    return decoded
