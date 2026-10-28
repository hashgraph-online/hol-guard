"""Claude AskUserQuestion approval answers settled by the native runtime.

The resident's ``claude_question_settle`` authority-state op loads the
session's single pending approval, decides whether a PostToolUse hook answers
its HOL Guard prompt, and plans what the answer saves, in one transaction.
This module only projects the hook fields the op reads and checks the reply
shape. Any native failure or malformed reply reads as "not an approval
question", so nothing is persisted from it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from .native_hook_authority_state import HOOK_AUTHORITY_STATE_QUESTION_SETTLE_FEATURE, hook_authority_state
from .native_hook_decision import NativeHookDecisionError, _tilde_home, validated_permission_persist_plan

if TYPE_CHECKING:
    from .store import GuardStore

_BARE_OUTCOMES = frozenset({"none", "unseen", "unanswered"})
_SAVE_FIELDS = frozenset({"outcome", "artifact_id", "reason", "source", "plan"})


def claude_guard_question_request(payload: Mapping[str, object], *, event: str | None) -> dict[str, object] | None:
    """The question fields the resident reads, or ``None`` when the hook cannot be the question."""

    tool_name = payload.get("tool_name")
    normalized_tool = tool_name.strip().lower() if isinstance(tool_name, str) else ""
    if event != "PostToolUse" or normalized_tool != "askuserquestion":
        # Only narrows: other tools' PostToolUse never ship their (possibly
        # large) input and response to the resident.
        return None
    response = payload.get("tool_response")
    answers = None
    if isinstance(response, dict):
        raw_answers = response.get("answers")
        if isinstance(raw_answers, dict):
            # Ordered pairs: the first matching question wins.
            answers = [[question, answer] for question, answer in raw_answers.items()]
        response = {key: value for key, value in response.items() if key != "answers"}
    return {
        "event": event,
        "tool_name": tool_name,
        "tool_input": payload.get("tool_input"),
        "tool_response": response,
        "response_answers": answers,
    }


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

    question = claude_guard_question_request(payload, event=event)
    if question is None:
        # Only an AskUserQuestion answer can settle a pending approval; the
        # resident answers ``none`` for any other call, so it is not asked.
        return None
    reply = hook_authority_state(
        store,
        "claude_question_settle",
        now=now,
        required_feature=HOOK_AUTHORITY_STATE_QUESTION_SETTLE_FEATURE,
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
    if outcome != "save" or set(reply) != _SAVE_FIELDS:
        return None
    if not all(isinstance(reply[name], str) and reply[name] for name in ("artifact_id", "reason", "source")):
        return None
    try:
        plan = validated_permission_persist_plan(reply["plan"])
    except NativeHookDecisionError:
        return None
    return {**reply, "plan": plan}


__all__ = ["claude_guard_question_request", "settle_claude_guard_question"]
