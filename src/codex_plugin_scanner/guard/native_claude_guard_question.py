"""Claude AskUserQuestion approval answers settled by the native runtime.

The resident's ``claude_question_settle`` authority-state op loads the
session's single pending approval, decides whether a PostToolUse hook answers
its HOL Guard prompt, and plans what the answer saves, in one transaction.
This module forwards the hook fields as JSON text and checks the reply
shape. Any native failure or malformed reply reads as "not an approval
question", so nothing is persisted from it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from .native_hook_authority_state import HOOK_AUTHORITY_STATE_QUESTION_PAYLOAD_FEATURE, hook_authority_state
from .native_hook_decision import NativeHookDecisionError, _tilde_home, validated_permission_persist_plan

if TYPE_CHECKING:
    from .store import GuardStore

_BARE_OUTCOMES = frozenset({"none", "unseen", "unanswered"})
_SAVE_FIELDS = frozenset({"outcome", "artifact_id", "pending_artifact_hash", "pending_id", "reason", "source", "plan"})


def settle_claude_guard_question(
    store: GuardStore,
    *,
    session_id: str,
    payload: Mapping[str, object],
    event: str | None,
    now: str,
) -> dict[str, Any] | None:
    """The resident's settlement of the hook against the session's pending approval.

    ``None`` when the hook is not the question or the resident cannot say;
    otherwise ``{"outcome": "unseen" | "unanswered"}`` or the ``save`` reply
    with its validated plan.
    """

    tool_name = payload.get("tool_name")
    # Bound forwarding to the Claude question route so unrelated tool output
    # never travels on this RPC. The resident checks the event and tool again.
    if event != "PostToolUse" or not isinstance(tool_name, str) or tool_name.strip().lower() != "askuserquestion":
        return None
    try:
        # A JSON object in the outer wire frame would sort the answer keys
        # before the resident had a chance to read their hook order.
        question = json.dumps(
            {
                "event": event,
                "tool_name": tool_name,
                "tool_input": payload.get("tool_input"),
                "tool_response": payload.get("tool_response"),
            },
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        return None
    reply = hook_authority_state(
        store,
        "claude_question_settle_hook",
        now=now,
        required_feature=HOOK_AUTHORITY_STATE_QUESTION_PAYLOAD_FEATURE,
        session_id=session_id,
        payload=question,
        tilde_home=_tilde_home(),
    )
    if reply is None:
        return None
    outcome = reply.get("outcome")
    if not isinstance(outcome, str):
        return None
    if outcome in _BARE_OUTCOMES and set(reply) == {"outcome"}:
        return None if outcome == "none" else {"outcome": outcome}
    if (
        outcome != "save"
        or not set(reply) <= _SAVE_FIELDS
        or not {"outcome", "artifact_id", "reason", "source", "plan"} <= set(reply)
    ):
        return None
    if not all(isinstance(reply[name], str) and reply[name] for name in ("artifact_id", "reason", "source")):
        return None
    pending_id = reply.get("pending_id")
    if pending_id is not None and (not isinstance(pending_id, str) or not pending_id):
        return None
    pending_artifact_hash = reply.get("pending_artifact_hash")
    if pending_artifact_hash is not None and (not isinstance(pending_artifact_hash, str) or not pending_artifact_hash):
        return None
    try:
        plan = validated_permission_persist_plan(reply["plan"])
    except NativeHookDecisionError:
        return None
    return {**reply, "plan": plan}


__all__ = ["settle_claude_guard_question"]
