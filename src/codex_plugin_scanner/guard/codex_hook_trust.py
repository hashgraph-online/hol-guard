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
from collections.abc import Iterator, Mapping
from pathlib import Path

from .codex_hook_registration import _hook_entry_is_active, _is_live_guard_codex_hook_command

CODEX_HOOK_TRUST_WARNING = (
    "Codex has not trusted the current HOL Guard hooks, so Codex skips them. "
    "Open Codex, run /hooks, and press t to trust them."
)

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


def _guard_hook_coordinates(
    hooks: Mapping[str, object], config_path: Path
) -> Iterator[tuple[list[str], str, Mapping[str, object]]]:
    """Yield the state keys, expected hash and handler for each live Guard hook."""

    # Codex keys hook state by the canonical config path.
    prefixes = dict.fromkeys((str(_resolved(config_path)), str(config_path)))
    for event_name, groups in hooks.items():
        label = codex_event_label(str(event_name))
        if label is None or not isinstance(groups, list):
            continue
        for group_index, group in enumerate(groups):
            handlers = group.get("hooks") if isinstance(group, Mapping) else None
            if not isinstance(handlers, list) or not _hook_entry_is_active(group):
                continue
            for handler_index, handler in enumerate(handlers):
                if not isinstance(handler, Mapping) or not _is_guard_handler(handler):
                    continue
                if not _hook_entry_is_active(handler):
                    continue
                expected = codex_command_hook_hash(str(event_name), group.get("matcher"), handler)
                if expected is None:
                    continue
                yield [f"{prefix}:{label}:{group_index}:{handler_index}" for prefix in prefixes], expected, handler


def _handler_coordinates(hooks: Mapping[str, object]) -> dict[str, str]:
    """Every command handler's ``<label>:<group>:<handler>`` coordinate and hash."""

    found: dict[str, str] = {}
    for event_name, groups in hooks.items():
        label = codex_event_label(str(event_name))
        if label is None or not isinstance(groups, list):
            continue
        for group_index, group in enumerate(groups):
            handlers = group.get("hooks") if isinstance(group, Mapping) else None
            if not isinstance(handlers, list):
                continue
            for handler_index, handler in enumerate(handlers):
                if not isinstance(handler, Mapping):
                    continue
                digest = codex_command_hook_hash(str(event_name), group.get("matcher"), handler)
                if digest is not None:
                    found[f"{label}:{group_index}:{handler_index}"] = digest
    return found


def _guard_coordinates(hooks: Mapping[str, object]) -> dict[str, str]:
    """Each Guard handler's ``<label>:<group>:<handler>`` coordinate, by event label.

    Unlike :func:`_guard_hook_coordinates` this does not skip a handler a user
    switched off: that choice is exactly what the remap has to carry.
    """

    found: dict[str, str] = {}
    for event_name, groups in hooks.items():
        label = codex_event_label(str(event_name))
        if label is None or not isinstance(groups, list):
            continue
        for group_index, group in enumerate(groups):
            handlers = group.get("hooks") if isinstance(group, Mapping) else None
            if not isinstance(handlers, list):
                continue
            for handler_index, handler in enumerate(handlers):
                if isinstance(handler, Mapping) and _is_guard_handler(handler):
                    found[f"{label}:{group_index}:{handler_index}"] = label
    return found


def remap_hook_state(before: Mapping[str, object], hooks: dict[str, object], config_path: Path) -> None:
    """Follow each hook's state to the coordinate its handler now occupies.

    Codex keys ``[hooks.state]`` by position, so removing Guard's own groups
    and appending their replacements after the ones Guard leaves alone moves
    every later hook up. Another hook's state then sits on the key a Guard
    handler has just taken, and a ``enabled = false`` a user set there in
    ``/hooks`` switches the new Guard hook off. Neither the install nor the
    doctor sees it, because both read that key as the Guard hook's own
    choice: the machine looks protected and runs none of Guard's hooks.

    A handler that moved carries its state with it, one that is gone leaves
    its state behind, and a key naming no handler this function can hash is
    left exactly as it was.

    An upgrade rewrites Guard's own handler, and the command path, status
    message, timeout and matcher all feed its hash, so the replacement matches
    no hash the old state knew. That is still the same hook to the user, and a
    dropped ``enabled = false`` would be re-trusted as a fresh install and
    switch a hook the user turned off back on. So a Guard handler replaced by
    exactly one Guard handler on the same event hands over that one choice,
    without the stale trust the install records again anyway.
    """

    state = hooks.get("state")
    if not isinstance(state, dict) or not state:
        return
    was = _handler_coordinates(before)
    now = _handler_coordinates(hooks)
    was_guard = _guard_coordinates(before)
    now_guard = _guard_coordinates(hooks)
    prefixes = tuple(dict.fromkeys((str(_resolved(config_path)), str(config_path))))
    kept: dict[str, object] = {}
    moves: list[tuple[str, object]] = []
    for key, entry in state.items():
        prefix = next((value for value in prefixes if key.startswith(f"{value}:")), None)
        coordinate = key[len(prefix) + 1 :] if prefix is not None else None
        digest = was.get(coordinate) if coordinate is not None else None
        if coordinate is None or digest is None or now.get(coordinate) == digest:
            kept[key] = entry
            continue
        moved = [name for name, value in now.items() if value == digest]
        # Only an unambiguous move can carry the user's choice with it. A
        # handler that is gone, or that now matches several coordinates,
        # leaves its state behind rather than landing on the wrong hook.
        if len(moved) == 1:
            moves.append((f"{prefix}:{moved[0]}", entry))
            continue
        if moved or coordinate not in was_guard or not isinstance(entry, Mapping):
            continue
        if entry.get("enabled") is not False:
            continue
        label = was_guard[coordinate]
        targets = [name for name, event in now_guard.items() if event == label]
        if len(targets) == 1:
            moves.append((f"{prefix}:{targets[0]}", {"enabled": False}))
    for key, entry in moves:
        kept.setdefault(key, entry)
    hooks["state"] = kept


def stale_guard_hook_coordinates(payload: Mapping[str, object], config_path: Path) -> list[str]:
    """Return state keys of Guard-managed hooks whose stored trust is missing or stale."""

    hooks = payload.get("hooks")
    if not isinstance(hooks, Mapping):
        return []
    state = hooks.get("state")
    state_map = state if isinstance(state, Mapping) else {}
    stale: list[str] = []
    for keys, expected, _handler in _guard_hook_coordinates(hooks, config_path):
        entries = [entry for key in keys if isinstance(entry := state_map.get(key), Mapping)]
        # A handler switched off in Codex's /hooks never runs, so its trust is irrelevant.
        if any(entry.get("enabled") is False for entry in entries):
            continue
        if not any(entry.get("trusted_hash") == expected for entry in entries):
            stale.append(keys[0])
    return stale


def record_guard_hook_trust(payload: dict[str, object], config_path: Path) -> list[str]:
    """Trust the Guard hooks this install just wrote, and return the keys recorded.

    Codex runs a user-layer hook only when ``[hooks.state]`` records a trusted
    hash for it, so hooks Guard writes without one are skipped silently and the
    machine runs unprotected with nothing said at the time. Guard writes those
    hook entries into the user's own config as an explicit, user-invoked
    install, and anything able to write the hooks table can write the state
    table beside it, so recording trust claims no authority the install did not
    already exercise.

    It stays narrow on purpose. Only Guard's own live handlers are touched,
    only with the hash computed from the entry being written, and a handler the
    user switched off in ``/hooks`` keeps that choice.
    """

    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return []
    state = hooks.get("state")
    state_map: dict[str, object] = state if isinstance(state, dict) else {}
    recorded: list[str] = []
    for keys, expected, _handler in _guard_hook_coordinates(hooks, config_path):
        key = keys[0]
        existing = next((entry for entry in (state_map.get(name) for name in keys) if isinstance(entry, Mapping)), None)
        if existing is not None and existing.get("enabled") is False:
            continue
        entry: dict[str, object] = {**existing} if existing is not None else {}
        # An alias key answers whether the user switched the hook off, but
        # Codex reads trust under the canonical path alone: a hash recorded
        # only under the alias leaves the hook untrusted and silently skipped.
        canonical = state_map.get(key)
        if isinstance(canonical, Mapping) and canonical.get("trusted_hash") == expected:
            continue
        entry["trusted_hash"] = expected
        state_map[key] = entry
        recorded.append(key)
    if recorded or isinstance(state, dict):
        hooks["state"] = state_map
    return recorded


def codex_hook_trust_stale(payload: object, config_path: Path) -> bool:
    return isinstance(payload, Mapping) and bool(stale_guard_hook_coordinates(payload, config_path))


def apply_codex_hook_trust_doctor(payload: dict[str, object], hook_state: Mapping[str, object]) -> None:
    """Warn about untrusted Guard hooks and stop doctor from calling them active."""

    if not hook_state.get("hook_trust_stale"):
        return
    warnings = payload.get("warnings")
    payload["warnings"] = [*(warnings if isinstance(warnings, list) else []), CODEX_HOOK_TRUST_WARNING]
    if payload.get("setup_status") == "active":
        payload["setup_status"] = "partial"


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path


def _is_guard_handler(handler: Mapping[str, object]) -> bool:
    command = handler.get("command")
    return isinstance(command, str) and _is_live_guard_codex_hook_command(command)
