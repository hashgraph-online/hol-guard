"""Claude Code PermissionRequest presentation for the resident daemon."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..adapters.claude_hook_config import CLAUDE_GUARD_PERMISSION_PASSTHROUGH_KEY

if TYPE_CHECKING:
    from ..store import GuardStore


def claude_permission_request_response(store: GuardStore, payload: dict[str, object]) -> dict[str, object]:
    """Defer Claude's permission dialog to the user, with any pending Guard context.

    Claude raises this event only after PreToolUse let the call continue. The
    native PreToolUse verdict already decided the action, so this response
    presents Guard context and never supplies a decision.
    """
    from ..cli.commands_support_claude_approval import (
        _claude_permission_request_additional_context,
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
    reason = str(notice.get("reason") or "HOL Guard requires review before this action can execute.")
    response["systemMessage"] = _claude_permission_request_system_message(payload=payload, native_reason=reason)
    response["hookSpecificOutput"] = {
        "hookEventName": "PermissionRequest",
        "additionalContext": _claude_permission_request_additional_context(reason),
    }
    return response
