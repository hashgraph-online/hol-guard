"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_hook_state import _remove_claude_pending_permission
    from .commands_support_permission_store import _write_claude_native_permission_plan
    from .commands_support_runtime_artifacts import _hook_event_name, _optional_string


from ..native_claude_guard_question import settle_claude_guard_question
from ._commands_shared import *
from .commands_parser_helpers import *


def _settle_claude_guard_question(store: GuardStore, payload: dict[str, object]) -> bool | None:
    """Save the user's answer to the HOL Guard approval question.

    ``None`` when the call is not that question for the session's single
    pending review (or the resident cannot say); otherwise whether a decision
    was saved. The resident records an unseen prompt itself.
    """

    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return None
    settled = settle_claude_guard_question(
        store,
        session_id=session_id,
        payload=payload,
        event=_hook_event_name(payload),
        now=_now(),
    )
    if settled is None:
        return None
    if settled["outcome"] != "save":
        return False
    artifact_id = settled["artifact_id"]
    saved = _write_claude_native_permission_plan(
        store=store,
        plan=settled["plan"],
        artifact_id=artifact_id,
        reason=settled["reason"],
        source=settled["source"],
        now=_now(),
    )
    if saved:
        _remove_claude_pending_permission(store, session_id=session_id, artifact_id=artifact_id)
    return saved


__all__ = ["_settle_claude_guard_question"]
