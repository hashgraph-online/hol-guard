"""Exact port of Codex's hook trust hash, used to detect stale trust for Guard hooks.

Codex (codex-rs/hooks/src/engine/discovery.rs ``hook_hash`` and
codex-rs/config/src/fingerprint.rs ``version_for_toml``) only runs a user-layer hook
when ``[hooks.state."<key>"].trusted_hash`` equals the hash of the hook's normalized
identity. Guard's frozen runtime binds hook commands to a versioned executable, so every
install or update invalidates trust until the user trusts the hooks again in Codex.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping
from pathlib import Path

from .codex_hook_registration import _is_live_guard_codex_hook_command

_EVENT_LABELS = {
    "PreToolUse": "pre_tool_use",
    "PermissionRequest": "permission_request",
    "PostToolUse": "post_tool_use",
    "PreCompact": "pre_compact",
    "PostCompact": "post_compact",
    "SessionStart": "session_start",
    "SessionEnd": "session_end",
    "UserPromptSubmit": "user_prompt_submit",
    "SubagentStart": "subagent_start",
    "SubagentStop": "subagent_stop",
    "Stop": "stop",
    "Interrupt": "interrupt",
}
_MATCHERLESS_EVENTS = frozenset({"UserPromptSubmit", "Stop", "Interrupt"})
_SHORT_TIMEOUT_EVENTS = frozenset({"SessionEnd", "Interrupt"})
_DEFAULT_TIMEOUT_SEC = 600
_SHORT_DEFAULT_TIMEOUT_SEC = 1
_SHORT_MAX_TIMEOUT_SEC = 3
_DEFAULT_CONTEXT_LIMIT = 2500


def codex_event_label(event_name: str) -> str | None:
    return _EVENT_LABELS.get(event_name)


def codex_command_hook_hash(event_name: str, matcher: object, handler: Mapping[str, object]) -> str | None:
    """Return Codex's ``current_hash`` for one command handler, or None if not hashable."""

    label = _EVENT_LABELS.get(event_name)
    command = handler.get("command")
    if handler.get("type") != "command" or label is None or not isinstance(command, str):
        return None
    if sys.platform == "win32" and isinstance(handler.get("commandWindows"), str):
        command = str(handler["commandWindows"])
    if not command.strip():
        return None
    timeout = handler.get("timeout")
    if isinstance(timeout, bool) or (not isinstance(timeout, int) and timeout is not None):
        return None
    if event_name in _SHORT_TIMEOUT_EVENTS:
        normalized_timeout = min(
            max(timeout if timeout is not None else _SHORT_DEFAULT_TIMEOUT_SEC, 1), _SHORT_MAX_TIMEOUT_SEC
        )
    else:
        normalized_timeout = max(timeout if timeout is not None else _DEFAULT_TIMEOUT_SEC, 1)
    normalized: dict[str, object] = {
        "type": "command",
        "command": command,
        "timeout": normalized_timeout,
        "async": handler.get("async") is True,
    }
    status_message = handler.get("statusMessage")
    if isinstance(status_message, str):
        normalized["statusMessage"] = status_message
    limit = handler.get("additionalContextLimit")
    allows_limit = event_name in {"PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit", "SubagentStart"}
    if allows_limit and isinstance(limit, int) and not isinstance(limit, bool) and limit != _DEFAULT_CONTEXT_LIMIT:
        normalized["additionalContextLimit"] = limit
    identity: dict[str, object] = {"event_name": label, "hooks": [normalized]}
    if event_name not in _MATCHERLESS_EVENTS and isinstance(matcher, str):
        identity["matcher"] = matcher
    serialized = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def stale_guard_hook_coordinates(payload: Mapping[str, object], config_path: Path) -> list[str]:
    """Return state keys of Guard-managed hooks whose stored trust is missing or stale."""

    hooks = payload.get("hooks")
    if not isinstance(hooks, Mapping):
        return []
    state = hooks.get("state")
    state_map = state if isinstance(state, Mapping) else {}
    stale: list[str] = []
    for event_name, groups in hooks.items():
        label = codex_event_label(str(event_name))
        if label is None or not isinstance(groups, list):
            continue
        for group_index, group in enumerate(groups):
            handlers = group.get("hooks") if isinstance(group, Mapping) else None
            if not isinstance(handlers, list):
                continue
            for handler_index, handler in enumerate(handlers):
                if not isinstance(handler, Mapping) or not _is_guard_handler(handler):
                    continue
                expected = codex_command_hook_hash(str(event_name), group.get("matcher"), handler)
                if expected is None:
                    continue
                key = f"{config_path}:{label}:{group_index}:{handler_index}"
                entry = state_map.get(key)
                trusted = entry.get("trusted_hash") if isinstance(entry, Mapping) else None
                if trusted != expected:
                    stale.append(key)
    return stale


def _is_guard_handler(handler: Mapping[str, object]) -> bool:
    command = handler.get("command")
    return isinstance(command, str) and _is_live_guard_codex_hook_command(command)
