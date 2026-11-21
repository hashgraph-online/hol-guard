"""Static input corpus for the hook-route parity oracle."""

from __future__ import annotations

from collections.abc import Mapping

HARNESSES = ("codex", "claude-code", "claude", "copilot", "cursor", "devin", "zcode", "grok", "unknown-harness")
EDGE_EVENTS = frozenset({"PreToolUse", "PostToolUse", "UserPromptSubmit"})
PASSTHROUGH_HARNESSES = frozenset({"devin", "zcode"})
PRE_EVENTS = frozenset(
    {
        "pretool",
        "pretooluse",
        "pretoolcall",
        "beforeshellexecution",
        "beforereadfile",
        "beforewritefile",
        "beforemcpexecution",
    }
)
POST_EVENTS = frozenset(
    {
        "posttool",
        "posttooluse",
        "posttoolcall",
        "aftershellexecution",
        "afterreadfile",
        "afterwritefile",
        "aftermcpexecution",
    }
)
SESSION = "session-1"
PERMISSION_PROMPT = {"hook_event_name": "Notification", "notification_type": "permission_prompt"}


def fixture_event_name(payload: Mapping[str, object]) -> str:
    """Project fixture labels for the retired Python route oracle."""

    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        raw = value.strip()
        compact = raw.lower().replace("_", "").replace("-", "")
        if compact in PRE_EVENTS:
            return "PreToolUse"
        if compact in POST_EVENTS:
            return "PostToolUse"
        if compact in {"permissionrequest", "permissionrequestv2"}:
            return "PermissionRequest"
        if compact in {"prompt", "userpromptsubmit", "userpromptsubmitted"}:
            return "UserPromptSubmit"
        return raw
    return "PreToolUse"


# Payload shapes as the harnesses send them.
PAYLOADS: tuple[dict[str, object], ...] = (
    {},
    {"hook_event_name": "PreToolUse"},
    {"hook_event_name": "pretooluse"},
    {"hook_name": "preToolUse"},
    {"event": "PostToolUse"},
    {"hookEventName": "PostToolUse"},
    {"hook_event_name": "UserPromptSubmit"},
    {"hook_event_name": "UserPromptSubmitted"},
    {"hook_event_name": "PermissionRequest"},
    {"hook_event_name": "PermissionRequestV2"},
    {"hook_name": "permission_request"},
    {"eventName": "PermissionRequest"},
    {"hook_event_name": "copilotPermissionRequest"},
    {"hook_event_name": "Stop"},
    {"hook_event_name": "Stop", "notification_type": "permission_prompt"},
    PERMISSION_PROMPT,
    {"hook_event_name": "Notification", "notification_type": "idle_prompt"},
    {"hook_event_name": "Notification"},
    {"hook_event_name": "SessionStart"},
    {"hook_event_name": "beforeShellExecution"},
    {"hookName": "afterShellExecution"},
)
REWRITTEN: tuple[tuple[dict[str, object], dict[str, object]], ...] = (
    ({"hookEventName": "preToolUse"}, {"hook_event_name": "PreToolUse"}),
    ({"eventName": "PermissionRequest"}, {"hook_event_name": "PermissionRequest"}),
    ({"hook_event_name": "PermissionRequest"}, {"hook_event_name": "PreToolUse"}),
    ({"hook_event_name": "PreToolUse"}, {"hook_event_name": "PermissionRequest"}),
)
COPILOT_STAGES = ("", "pretooluse", "permissionrequest", "posttooluse")
