"""Carry the resident's Muse hook document to Muse's stdout.

The document and its exit status come from the native runtime
(``hook_responses::muse``); nothing here reads a verdict. A resident that
cannot answer leaves the call blocked.

Muse hooks speak the Claude-Code-shaped JSON contract, verified
against Muse 1.4.14 with ``muse plugins hook test`` and a live
``muse exec`` run:

- An allow is empty stdout with exit 0. An explicit
  ``permissionDecision: "allow"`` without ``updatedInput`` is rejected by
  Muse, so Guard never emits a bare allow.
- A ``PreToolUse`` block is ``hookSpecificOutput.permissionDecision:
  "deny"`` with a reason, or exit 2 with the reason on stderr. Guard uses
  the JSON form on exit 0 so the reason reaches the model.
- A ``UserPromptSubmit`` block is ``{"decision": "block", "reason": ...}``.
- ``PostToolUse`` and ``SessionStart`` cannot undo or block; Guard adds
  ``additionalContext`` and otherwise stays silent.
- ``PermissionRequest`` defers to Muse's own prompt (no decision)
  unless Guard's final answer is a block.

Approval resume: when the daemon queues a ``review`` for a ``PreToolUse``
call, the native bounded bridge waits for the approval inside the hook
(``bounded_hook_bridge_muse``), so the user approves once and the work
continues without a manual retry.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from .hook_failure_bridge import native_stderr_hook_failure
from .native_hook_render import native_muse_bridge

_UNAVAILABLE_REASON = "HOL Guard blocked this action."


def muse_bridge_response(
    daemon_response: Mapping[str, object],
    *,
    event_name: str,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> tuple[str, str, int]:
    """Print the resident's Muse document for this daemon answer.

    Reading an answer is a verdict about a verdict, so the resident does it
    and this returns what it rendered. A resident that cannot answer leaves a
    deciding call blocked: Muse reads exit 2 with a reason on stderr as a
    refusal. An observation event has nothing to refuse, so it stays silent;
    the event name comes from the caller, not from the unread answer.
    """

    rendered = native_muse_bridge(daemon_response, event_name=event_name, guard_home=guard_home, deadline=deadline)
    if rendered is None:
        # The runtime's table says which events decide whether something runs.
        return native_stderr_hook_failure("muse", event_name, _UNAVAILABLE_REASON)
    document, exit_code = rendered
    if document is None:
        return "", "", exit_code
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")), "", exit_code


__all__ = ["muse_bridge_response"]
