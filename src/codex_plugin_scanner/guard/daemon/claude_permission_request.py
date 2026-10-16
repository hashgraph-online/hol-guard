"""Claude Code PermissionRequest presentation for the resident daemon."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..adapters.claude_hook_config import CLAUDE_GUARD_PERMISSION_PASSTHROUGH_KEY

if TYPE_CHECKING:
    from ..store import GuardStore


def claude_permission_request_response(store: GuardStore, payload: dict[str, object]) -> dict[str, object]:
    """Present a Claude permission dialog without granting approval.

    Claude raises this event only after PreToolUse let the call continue. A
    pending Guard review that expects an explicit answer keeps its gate: the
    dialog is denied and Claude is directed to the Guard approval question.
    Otherwise Guard shows any review reason and defers to Claude's dialog.
    """
    from ..cli.commands_support_claude_approval import (
        _claude_guard_approval_question_message,
        _claude_permission_notice_prefers_ask_user_question,
        _claude_permission_prompt_system_message,
        _claude_permission_request_system_message,
    )
    from ..cli.commands_support_hook_state import (
        _mark_claude_pending_permission_prompt_seen,
        _peek_claude_permission_notice,
    )

    response: dict[str, object] = {
        CLAUDE_GUARD_PERMISSION_PASSTHROUGH_KEY: True,
        "hookSpecificOutput": {"hookEventName": "PermissionRequest"},
    }
    notice = _peek_claude_permission_notice(store, payload)
    if notice is None:
        return response
    _mark_claude_pending_permission_prompt_seen(store=store, payload=payload, notice=notice)
    if _claude_permission_notice_prefers_ask_user_question(notice):
        return {
            "systemMessage": _claude_permission_prompt_system_message(payload=payload, notice=notice),
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": _claude_guard_approval_question_message(notice),
                    "interrupt": False,
                },
            },
        }
    reason = str(notice.get("reason") or "HOL Guard requires review before this action can execute.")
    # PermissionRequest has no model-context field; the user sees the reason.
    response["systemMessage"] = _claude_permission_request_system_message(payload=payload, native_reason=reason)
    return response
