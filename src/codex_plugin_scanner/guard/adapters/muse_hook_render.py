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
call, the bounded bridge waits for the approval inside the hook (the
Oh My Pi model: the user approves once and the work continues without a
manual retry). An approval rewrites the answer to an allow for the
identical call; a denial keeps it blocked. The one-time approval binding
still rejects any call whose arguments changed while waiting.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..native_hook_render import native_muse_bridge
from . import hook_approval_wait

if TYPE_CHECKING:
    from ..store import GuardStore

# Only these events decide whether something runs. The rest report on work
# that already happened or on the session itself, so a resident that cannot
# answer has nothing to refuse there -- and exit 2 on ``Stop`` would keep the
# agent from stopping.
_DECIDING_EVENTS = frozenset({"pretooluse", "permissionrequest", "userpromptsubmit"})
_UNAVAILABLE_REASON = "HOL Guard blocked this action."


def _compact(event_name: str) -> str:
    return event_name.replace("_", "").replace("-", "").lower()


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
        if _compact(event_name) not in _DECIDING_EVENTS:
            return "", "", 0
        return "", _UNAVAILABLE_REASON, 2
    document, exit_code = rendered
    if document is None:
        return "", "", exit_code
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")), "", exit_code


def apply_muse_pretool_approval_wait(
    response: dict[str, object],
    *,
    event_name: str,
    store: GuardStore,
    timeout_seconds: int,
) -> dict[str, object]:
    """Wait for a queued Muse approval and rewrite the answer in place.

    Mirrors ``apply_grok_pretool_approval_wait``: the native runtime
    (``hook_approval_wait``) names the requests to wait on and reads the
    settled wait. An approval lets the original ``PreToolUse`` call proceed
    unchanged (approval resume); a denial keeps it blocked; a still-pending
    approval returns the review unchanged so Muse shows the block and the
    saved approval answers the retry.
    """

    request_ids, seconds = hook_approval_wait.plan_wait(
        "muse", event_name=event_name, response=response, timeout_seconds=timeout_seconds
    )
    if not request_ids:
        return response
    from ..approvals import wait_for_approval_requests

    wait_result = wait_for_approval_requests(store=store, request_ids=request_ids, timeout_seconds=seconds)
    response["approval_wait"] = wait_result
    _, fields, edits = hook_approval_wait.settle_wait("muse", wait_result=wait_result, request_id=request_ids[0])
    answer = hook_approval_wait.rewrite_answer(edits, response) or response
    answer.update(fields)
    return answer


__all__ = [
    "apply_muse_pretool_approval_wait",
    "muse_bridge_response",
]
