"""Settle the live native decision a contained run re-asks for."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping

# A contained run re-asks native authority from its own short-lived process.
# That process starts its own policy publisher and waits for the resident to
# acknowledge the snapshot, so a loaded host can leave it without an answer
# for a moment. These reason codes say the runtime never reached a decision;
# they are not a verdict on the command. A missing resident edge answers
# PreToolUse with native_pre_tool_unavailable.
AUTHORITY_UNAVAILABLE_REASONS = frozenset(
    {
        "native_hook_worker_exception",
        "native_hook_worker_unavailable",
        "native_hook_render_unavailable",
        "native_pre_tool_unavailable",
    }
)
_SETTLE_ATTEMPTS = 3
_SETTLE_PAUSE_SECONDS = 0.75


def authority_unavailable(response: object) -> bool:
    """Whether the runtime failed to decide rather than deciding against the run."""
    return isinstance(response, Mapping) and response.get("reason_code") in AUTHORITY_UNAVAILABLE_REASONS


def settled_authority(
    authorize: Callable[[dict[str, object]], object],
    payload: dict[str, object],
    *,
    pause: Callable[[float], None] | None = None,
) -> object:
    """The live decision for `payload`, re-asked while the runtime cannot answer.

    The command reaching here already carries a PreToolUse decision that sent
    it to a contained profile, so a missing answer here cancels work Guard
    itself asked to run contained. A real decision is deterministic and
    arrives on the first ask; only an unavailable runtime is asked again.
    """
    wait = time.sleep if pause is None else pause
    response = authorize(payload)
    for _ in range(_SETTLE_ATTEMPTS - 1):
        if not authority_unavailable(response):
            return response
        wait(_SETTLE_PAUSE_SECONDS)
        response = authorize(payload)
    return response
