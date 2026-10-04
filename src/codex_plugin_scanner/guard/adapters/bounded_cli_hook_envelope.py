"""Normalize and validate bounded hook event envelopes."""

import json
from typing import cast

_EVENT_ALIASES = {
    "permissionrequest": "PermissionRequest",
    "permissionrequestv2": "PermissionRequest",
    "pretooluse": "PreToolUse",
    "pretoolcall": "PreToolUse",
    "userpromptsubmit": "UserPromptSubmit",
    "userpromptsubmitted": "UserPromptSubmit",
    "posttooluse": "PostToolUse",
    "sessionstart": "SessionStart",
    "notification": "Notification",
    "stop": "Stop",
}

_EVENT_NAME_KEYS = ("hook_event_name", "hookEventName", "event", "eventName", "hook_name", "hookName")


def _grok_pretool_event_conflict(input_text: str) -> bool:
    payload = _json_object(input_text) or {}
    events = {
        value.strip().lower().replace("_", "").replace("-", "")
        for key in _EVENT_NAME_KEYS
        if isinstance(value := payload.get(key), str)
    }
    if "pretoolcall" in events:
        events.discard("pretoolcall")
        events.add("pretooluse")
    return "pretooluse" in events and len(events) > 1


def _json_object(text: str) -> dict[str, object] | None:
    try:
        raw = cast(object, json.loads(text))
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    payload: dict[str, object] = {}
    for key, value in cast(dict[object, object], raw).items():
        if isinstance(key, str):
            payload[key] = value
    return payload


def _canonical_event_token(value: str) -> str | None:
    stripped = value.strip()
    if not stripped:
        return None
    normalized = stripped.replace("_", "").replace("-", "").lower()
    return _EVENT_ALIASES.get(normalized, stripped)


def _event_name(input_text: str) -> str:
    payload = _json_object(input_text or "{}")
    if payload is not None:
        for key in _EVENT_NAME_KEYS:
            value = payload.get(key)
            if isinstance(value, str):
                named = _canonical_event_token(value)
                if named is not None:
                    return named
    for key in _EVENT_NAME_KEYS:
        token = f'"{key}"'
        start = input_text.find(token)
        colon = input_text.find(":", start + len(token)) if start >= 0 else -1
        quote = input_text.find('"', colon + 1) if colon >= 0 else -1
        end = input_text.find('"', quote + 1) if quote >= 0 else -1
        if 0 <= quote < end:
            named = _canonical_event_token(input_text[quote + 1 : end])
            if named is not None:
                return named
    return "PreToolUse"


def _has_json_object_line(output: str) -> bool:
    stripped = output.strip()
    if stripped and _json_object(stripped) is not None:
        return True
    for line in reversed(output.splitlines()):
        if not line.strip():
            continue
        return _json_object(line.strip()) is not None
    return False
