"""Preserve user TOML while owning only Guard's durable protection settings."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any

import tomlkit
from tomlkit.items import AoT

from .grok_config import (
    FOREIGN_HOOK_COMPAT_VENDORS,
    GROK_PRETOOL_HOOK_TIMEOUT_SECONDS,
    MANAGED_DENY_RULES,
    OBSERVE_HOOK_EVENTS,
)


def _table(parent: Any, key: str) -> Any:
    value = parent.get(key)
    if value is None:
        parent[key] = tomlkit.table()
        return parent[key]
    if not isinstance(value, Mapping):
        raise ValueError(f"Grok {key} must be a TOML table.")
    return value


def _owned_hook(group: object, command: str) -> bool:
    if not command or not isinstance(group, Mapping) or group.get("matcher") not in {None, ""}:
        return False
    handlers = group.get("hooks")
    return (
        isinstance(handlers, list)
        and len(handlers) == 1
        and isinstance(handlers[0], Mapping)
        and handlers[0].get("type") == "command"
        and handlers[0].get("command") == command
    )


def _remove_owned(document: Any, state: Mapping[str, object]) -> None:
    permission = document.get("permission")
    added_rules = state.get("added_deny_rules")
    if isinstance(permission, Mapping) and isinstance(added_rules, list):
        denied = permission.get("deny")
        if isinstance(denied, list):
            for rule in added_rules:
                if rule in denied:
                    denied.remove(rule)
    hooks = document.get("hooks")
    command = state.get("hook_command")
    owned_events = state.get("added_hook_events")
    if isinstance(hooks, Mapping) and isinstance(command, str) and isinstance(owned_events, list):
        for event in owned_events:
            groups = hooks.get(event) if isinstance(event, str) else None
            if isinstance(groups, list):
                for index in range(len(groups)):
                    if _owned_hook(groups[index], command):
                        del groups[index]
                        break
    compat = document.get("compat")
    prior = state.get("prior_compat_hooks")
    if isinstance(compat, Mapping) and isinstance(prior, Mapping):
        for vendor in FOREIGN_HOOK_COMPAT_VENDORS:
            table = compat.get(vendor)
            if not isinstance(table, MutableMapping) or table.get("hooks") is not False or vendor not in prior:
                continue
            previous = prior[vendor]
            if isinstance(previous, bool):
                table["hooks"] = previous
            elif previous is None:
                table.pop("hooks", None)
    created = state.get("created_keys")
    allowed = {
        "permission",
        "permission.deny",
        "compat",
        "hooks",
        *(f"compat.{vendor}" for vendor in FOREIGN_HOOK_COMPAT_VENDORS),
        *(f"hooks.{event}" for event in ("PreToolUse", *OBSERVE_HOOK_EVENTS)),
    }
    if isinstance(created, list):
        for key in reversed(created):
            if not isinstance(key, str) or key not in allowed:
                continue
            parts = key.split(".")
            parent = document if len(parts) == 1 else document.get(parts[0])
            if isinstance(parent, MutableMapping):
                value = parent.get(parts[-1])
                if isinstance(value, (Mapping, list)) and not value:
                    parent.pop(parts[-1], None)


def prepare_user_config_text(
    existing_text: str, hook_command: str, *, previous_state: Mapping[str, object]
) -> tuple[str, dict[str, object]]:
    """Merge permissions, compatibility and identical backup hooks without table duplication."""
    document = tomlkit.parse(existing_text)
    _remove_owned(document, previous_state)
    created_keys: list[str] = []
    for key in ("permission", "compat", "hooks"):
        if key not in document:
            created_keys.append(key)
    permission = _table(document, "permission")
    if "deny" not in permission:
        created_keys.append("permission.deny")
        permission["deny"] = tomlkit.array()
    denied = permission["deny"]
    if not isinstance(denied, list) or not all(isinstance(rule, str) for rule in denied):
        raise ValueError("Grok permission.deny must be an array of strings.")
    added_rules = []
    for rule in MANAGED_DENY_RULES:
        if rule not in denied:
            denied.append(rule)
            added_rules.append(rule)
    compat = _table(document, "compat")
    prior: dict[str, object] = {}
    for vendor in FOREIGN_HOOK_COMPAT_VENDORS:
        if vendor not in compat:
            created_keys.append(f"compat.{vendor}")
        table = _table(compat, vendor)
        previous = table.get("hooks")
        if previous is not None and not isinstance(previous, bool):
            raise ValueError("Grok compat hooks must be boolean.")
        prior[vendor] = previous
        table["hooks"] = False
    hooks = _table(document, "hooks")
    added_events = []
    for event in ("PreToolUse", *OBSERVE_HOOK_EVENTS):
        if event not in hooks:
            created_keys.append(f"hooks.{event}")
            hooks[event] = tomlkit.aot()
        groups = hooks[event]
        if not isinstance(groups, list):
            raise ValueError(f"Grok hooks.{event} must be an array of tables.")
        if any(_owned_hook(group, hook_command) for group in groups):
            continue
        group = tomlkit.table() if isinstance(groups, AoT) else tomlkit.inline_table()
        handler = tomlkit.inline_table()
        handler.update(
            type="command",
            command=hook_command,
            timeout=GROK_PRETOOL_HOOK_TIMEOUT_SECONDS if event == "PreToolUse" else 15,
        )
        group["hooks"] = [handler]
        groups.append(group)
        added_events.append(event)
    merged = tomlkit.dumps(document)
    validated = tomlkit.parse(merged)
    if validated.unwrap() != document.unwrap():
        raise ValueError("Grok settings did not survive TOML serialization.")
    if tomlkit.parse(existing_text).unwrap() == document.unwrap():
        merged = existing_text
    return merged, {
        "added_deny_rules": added_rules,
        "added_hook_events": added_events,
        "hook_command": hook_command,
        "prior_compat_hooks": prior,
        "created_keys": created_keys,
    }


def remove_user_config_settings(existing_text: str, state: Mapping[str, object]) -> str:
    document = tomlkit.parse(existing_text)
    _remove_owned(document, state)
    return tomlkit.dumps(document)
