"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_runtime_artifacts import _hook_event_name, _optional_string


from ..native_claude_guard_question import question_json, settle_claude_guard_question
from ..native_claude_question_save import save_claude_guard_question
from ._commands_shared import *
from .commands_parser_helpers import *


def _settle_claude_guard_question(
    store: GuardStore, payload: dict[str, object], *, deadline: float | None = None
) -> bool | None:
    """Save the user's answer to the HOL Guard approval question.

    ``None`` when the call is not that question for the session's single
    pending review (or the resident cannot say); otherwise whether a decision
    was saved. The resident records an unseen prompt itself.
    """

    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    event = _hook_event_name(payload)
    settled = settle_claude_guard_question(
        store,
        session_id=session_id,
        payload=payload,
        event=event,
        now=_now(),
    )
    if settled is None:
        return None
    if settled["outcome"] != "save":
        return False
    question = question_json(payload, event)
    if question is None:
        return False
    return save_claude_guard_question(
        store,
        session_id=session_id,
        question=question,
        settlement=settled,
        now=_now(),
        deadline=deadline,
    )


__all__ = ["_settle_claude_guard_question"]
