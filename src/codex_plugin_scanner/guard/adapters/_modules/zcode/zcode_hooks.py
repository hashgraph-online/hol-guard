"""z.ai ZCode hook payload and response helpers for HOL Guard.

ZCode speaks the same JSON stdin/stdout wire protocol as Claude Code: hook
events arrive as a JSON object on stdin, and Guard replies on stdout with a
``hookSpecificOutput.permissionDecision`` envelope. The current ZCode runtime
accepts ``permissionDecision`` values ``allow`` / ``ask`` / ``deny``:

* ``allow`` — the tool call proceeds.
* ``ask`` — ZCode opens its native permission prompt; the human decides.
* ``deny`` — the tool call is refused.

Guard maps its review tier (``review`` / ``require-reapproval``) to ``ask`` so
a human can approve through ZCode's own permission surface instead of every
review becoming a terminal denial. Hard denials (``block`` /
``sandbox-required``) and ``UserPromptSubmit`` blocks are emitted with exit
code ``2`` plus a human-readable reason on stderr, which ZCode treats as a
blocking error. ``ask`` responses must exit ``0`` because ZCode only parses
stdout JSON for successful hook processes.
"""

from __future__ import annotations

from collections.abc import Mapping

# Review-tier actions become ZCode's ``ask`` so the native permission prompt
# (allow once / always / deny) can satisfy them; hard denials stay ``deny``.
_ZCODE_ASK_ACTIONS = frozenset({"review", "require-reapproval"})
_ZCODE_BLOCKING_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})

# Reason text emitted by the native command control floor when the local
# authority is degraded, tampered, or pending recovery. ZCode sessions see
# this on every tool call until the control floor is restored, so the
# remediation command must travel with the message.
_AUTHORITY_BLOCK_REASON_MARKER = "native command extension policy"
_AUTHORITY_BLOCK_REMEDIATION = (
    " Run `hol-guard command controls recover-authority` in a terminal to restore the protected control floor."
)


def _raw_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _canonical_zcode_event_name(raw_event: str) -> str:
    normalized = raw_event.replace("_", "").replace("-", "").lower()
    mapping = {
        "pretooluse": "PreToolUse",
        "userpromptsubmit": "UserPromptSubmit",
        "posttooluse": "PostToolUse",
        "posttoolusefailure": "PostToolUseFailure",
        "sessionstart": "SessionStart",
        "notification": "Notification",
        "permissionrequest": "PermissionRequest",
        "stop": "Stop",
    }
    return mapping.get(normalized, raw_event or "PreToolUse")


def _event_name_for_response(payload: Mapping[str, object]) -> str:
    raw_event = _raw_hook_event_name(payload)
    return _canonical_zcode_event_name(raw_event) if raw_event else "PreToolUse"


def zcode_authority_block_reason(reason: str) -> str:
    """Append the control-floor remediation hint to authority block reasons.

    ZCode surfaces the deny reason directly to the user; without the hint a
    degraded control floor reads as an unactionable brick on every tool call.
    """

    text = reason if isinstance(reason, str) else ""
    if _AUTHORITY_BLOCK_REASON_MARKER in text and "hol-guard command controls" not in text:
        return text + _AUTHORITY_BLOCK_REMEDIATION
    return text


def zcode_hook_process_exit(
    *,
    policy_action: str,
    event_name: str | None = None,
    payload: Mapping[str, object] | None = None,
) -> int:
    """Return the hook process exit code ZCode expects for a policy action.

    Exit code ``2`` makes ZCode treat the hook as a blocking error and deny the
    call outright, discarding stdout JSON. Review-tier PreToolUse decisions
    therefore must exit ``0`` so ZCode parses the ``permissionDecision: "ask"``
    envelope and opens its native permission prompt; the user, not the exit
    code, decides whether the action proceeds.
    """

    resolved_event = event_name
    if resolved_event is None and payload is not None:
        resolved_event = _event_name_for_response(payload)
    compact = (resolved_event or "PreToolUse").replace("_", "").replace("-", "").lower()
    if compact == "pretooluse" and policy_action in _ZCODE_ASK_ACTIONS:
        return 0
    return 2 if policy_action in _ZCODE_BLOCKING_ACTIONS else 0


__all__ = [
    "zcode_authority_block_reason",
    "zcode_hook_process_exit",
]
