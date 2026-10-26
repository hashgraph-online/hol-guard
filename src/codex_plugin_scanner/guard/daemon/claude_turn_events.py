"""Claude Code turn state the resident daemon settles before its review."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..store import GuardStore


def claude_guard_question_answer(store: GuardStore, payload: dict[str, object]) -> dict[str, object] | None:
    """Record the user's answer to the HOL Guard approval question.

    The permission dialog and notification direct Claude to ask one HOL Guard
    question through AskUserQuestion. Its PostToolUse carries the answer; the
    resident decides whether the call is that question for the single pending
    review and what the answer saves. ``None`` means the call is not the
    question, so the ordinary post-tool review applies.
    """
    from ..cli.commands_support_claude_approval import (
        _claude_guard_question_verdict,
        _persist_claude_guard_question_decision,
    )
    from ..cli.commands_support_hook_state import _load_single_claude_pending_permission

    pending_pair = _load_single_claude_pending_permission(store, payload)
    if pending_pair is None:
        return None
    verdict = _claude_guard_question_verdict(payload, pending_pair[1])
    if not verdict.is_question:
        return None
    _persist_claude_guard_question_decision(store, payload, pending_pair=pending_pair, verdict=verdict)
    return {}


def claude_turn_stop(store: GuardStore, payload: dict[str, object]) -> None:
    """Drop the session's unanswered prompts when Claude ends its turn.

    A native cancel stays transient: the next turn reviews the call again
    instead of inheriting a block nobody chose. The Stop event itself still
    goes to the native edge for its answer.
    """
    from ..cli._commands_shared import _now
    from ..cli.commands_support_permission_store import _discard_claude_pending_permissions

    discarded = _discard_claude_pending_permissions(store, payload)
    store.add_event(
        "claude/turn_stop",
        {"session_id": payload.get("session_id"), "discarded_pending_permissions": discarded},
        _now(),
    )


__all__ = ["claude_guard_question_answer", "claude_turn_stop"]
