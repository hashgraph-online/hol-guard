"""Claude AskUserQuestion approval answers from the native runtime.

The resident's ``claude_guard_question`` kind decides whether a PostToolUse
hook answers the pending HOL Guard approval prompt and maps the chosen option
to ``allow`` or ``block``. This module only projects the hook fields the kind
reads. Any native failure or malformed answer reads as "not an approval
question", so nothing is persisted from it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import NamedTuple

from .native_context import _resolve_digest_home, native_context_digest

_PENDING_KEYS = ("approval_code", "approval_header", "approval_question", "approval_options")
_ACTIONS = frozenset({"allow", "block"})


class ClaudeGuardQuestionVerdict(NamedTuple):
    is_question: bool
    action: str | None


_NOT_A_QUESTION = ClaudeGuardQuestionVerdict(False, None)


def claude_guard_question_request(
    payload: Mapping[str, object], pending: Mapping[str, object], *, event: str | None
) -> dict[str, object]:
    """The request fields for one hook and its pending approval."""

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
        "tool_name": payload.get("tool_name"),
        "tool_input": payload.get("tool_input"),
        "tool_response": response,
        "response_answers": answers,
        "pending": {key: pending[key] for key in _PENDING_KEYS if key in pending},
    }


def claude_guard_question_verdict(
    payload: Mapping[str, object], pending: Mapping[str, object], *, event: str | None
) -> ClaudeGuardQuestionVerdict:
    """Whether ``payload`` answers the pending HOL Guard prompt, and with what."""

    tool_name = payload.get("tool_name")
    normalized_tool = tool_name.strip().lower() if isinstance(tool_name, str) else ""
    if event != "PostToolUse" or normalized_tool != "askuserquestion":
        # Only narrows: other tools' PostToolUse never reach the resident or
        # ship their (possibly large) input and response.
        return _NOT_A_QUESTION
    result = native_context_digest(
        "claude_guard_question",
        claude_guard_question_request(payload, pending, event=event),
        guard_home=_resolve_digest_home(None),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        return _NOT_A_QUESTION
    verdict = result.get("claude_guard_question")
    if not isinstance(verdict, dict) or set(verdict) != {"is_question", "action"}:
        return _NOT_A_QUESTION
    is_question = verdict["is_question"]
    action = verdict["action"]
    if not isinstance(is_question, bool) or not (action is None or (isinstance(action, str) and action in _ACTIONS)):
        return _NOT_A_QUESTION
    if not is_question and action is not None:
        return _NOT_A_QUESTION
    return ClaudeGuardQuestionVerdict(is_question, action)


__all__ = ["ClaudeGuardQuestionVerdict", "claude_guard_question_request", "claude_guard_question_verdict"]
