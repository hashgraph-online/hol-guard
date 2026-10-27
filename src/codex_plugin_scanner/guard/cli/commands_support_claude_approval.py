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

# The copy for a render the resident could not answer. Every piece of Claude
# approval text below says Guard is holding the request, so an unreachable
# resident never leaves a prompt reading as though Guard allowed the action.
_CLAUDE_COPY_UNAVAILABLE = (
    "HOL Guard is holding this Claude request for review. The HOL Guard runtime could not render "
    "the full notice, so nothing in this prompt should be read as HOL Guard allowing the action."
)


def _claude_approval_copy(
    which: str,
    *,
    payload: dict[str, object] | None = None,
    notice: dict[str, object] | None = None,
    reason: str = "",
) -> object | None:
    from ..native_hook_render import native_claude_approval_copy

    return native_claude_approval_copy(which, payload=payload, notice=notice, reason=reason)


def _claude_approval_text(
    which: str,
    *,
    payload: dict[str, object] | None = None,
    notice: dict[str, object] | None = None,
    reason: str = "",
) -> str:
    rendered = _claude_approval_copy(which, payload=payload, notice=notice, reason=reason)
    return rendered if isinstance(rendered, str) else _CLAUDE_COPY_UNAVAILABLE


def _claude_guard_approval_question_message(notice: dict[str, object] | None) -> str:
    return _claude_approval_text("approval_question_message", notice=notice)


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


def _claude_permission_notice_prefers_ask_user_question(notice: dict[str, object]) -> bool:
    # A render the resident cannot answer falls back to the Guard approval
    # question, which denies Claude's own dialog; the deferring branch is the
    # one that would hand the decision back to Claude.
    rendered = _claude_approval_copy("notice_prefers_ask_user_question", notice=notice)
    return rendered if isinstance(rendered, bool) else True


def _claude_permission_request_system_message(
    *,
    payload: dict[str, object],
    native_reason: str,
) -> str:
    return _claude_approval_text("permission_request_system_message", payload=payload, reason=native_reason)


def _claude_permission_prompt_system_message(
    *,
    payload: dict[str, object],
    notice: dict[str, object] | None,
) -> str:
    return _claude_approval_text("permission_prompt_system_message", payload=payload, notice=notice)


def _claude_permission_prompt_additional_context(notice: dict[str, object] | None) -> str:
    return _claude_approval_text("permission_prompt_additional_context", notice=notice)


__all__ = [
    "_claude_guard_approval_question_message",
    "_claude_permission_notice_prefers_ask_user_question",
    "_claude_permission_prompt_additional_context",
    "_claude_permission_prompt_system_message",
    "_claude_permission_request_system_message",
    "_settle_claude_guard_question",
]
