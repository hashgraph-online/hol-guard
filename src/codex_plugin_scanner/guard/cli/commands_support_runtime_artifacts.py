"""Guard CLI helper definitions."""

from __future__ import annotations


def _optional_string(value: object | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


_HOOK_EVENT_NAME_MAP = {
    "userpromptsubmitted": "UserPromptSubmit",
    "pretooluse": "PreToolUse",
    "posttooluse": "PostToolUse",
    "permissionrequest": "PermissionRequest",
    "permissionrequestv2": "PermissionRequest",
}


def _hook_event_name(payload: dict[str, object]) -> str | None:
    for key in ("event", "hook_event_name", "hookEventName", "hook_name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            normalized = value.strip()
            return _HOOK_EVENT_NAME_MAP.get(normalized.lower(), normalized)
    return None


def _string_list(value: object | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


_CODEX_PROMPT_SECRET_KEY_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "PASS", "API_KEY", "API-KEY", "AUTH", "CREDENTIAL")


__all__ = [
    "_CODEX_PROMPT_SECRET_KEY_MARKERS",
    "_HOOK_EVENT_NAME_MAP",
    "_hook_event_name",
    "_optional_string",
    "_string_list",
]
