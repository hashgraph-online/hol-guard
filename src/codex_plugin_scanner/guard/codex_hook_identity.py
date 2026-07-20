"""Canonical, serialization-independent identities for Codex hooks."""

from __future__ import annotations

import hashlib
import json
import math
import re
import shlex
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from typing import Any

CODEX_HOOK_IDENTITY_SCHEMA = "codex-hook-identity-v1"

_SHELL_SENSITIVE_COMMAND_RE = re.compile(r"[\\'\"`$|&;<>(){}\[\]*?!~#\r\n]")


def canonical_codex_hook_identity(
    *,
    source_scope: str,
    source_hooks_enabled: bool,
    event_name: str,
    group: Mapping[str, object],
    handler: Mapping[str, object],
) -> str:
    """Return one format- and coordinate-independent handler identity."""

    payload = {
        "schema": CODEX_HOOK_IDENTITY_SCHEMA,
        "source_scope": source_scope,
        "source_hooks_enabled": source_hooks_enabled,
        "event": event_name,
        "matcher": _canonical_value(group.get("matcher")),
        "group": _canonical_mapping(group, excluded_keys=frozenset({"hooks", "matcher"})),
        "handler": _canonical_handler(handler),
    }
    return _canonical_digest(payload)


def canonical_codex_hook_group_identity(
    *,
    source_scope: str,
    source_hooks_enabled: bool,
    event_name: str,
    group: Mapping[str, object],
) -> str:
    """Return a canonical identity for one complete matcher group."""

    raw_handlers = group.get("hooks")
    if isinstance(raw_handlers, list):
        canonical_handlers: list[object] = []
        for handler in raw_handlers:
            if isinstance(handler, Mapping):
                canonical_handlers.append(_canonical_handler(handler))
            else:
                canonical_handlers.append(_canonical_value(handler))
        handlers: object = canonical_handlers
    else:
        handlers = _canonical_value(raw_handlers)
    payload = {
        "schema": f"{CODEX_HOOK_IDENTITY_SCHEMA}:group",
        "source_scope": source_scope,
        "source_hooks_enabled": source_hooks_enabled,
        "event": event_name,
        "matcher": _canonical_value(group.get("matcher")),
        "group": _canonical_mapping(group, excluded_keys=frozenset({"hooks", "matcher"})),
        "handlers": handlers,
    }
    return _canonical_digest(payload)


def canonical_codex_hook_conflict_keys(
    *,
    source_scope: str,
    source_hooks_enabled: bool,
    event_name: str,
    group: Mapping[str, object],
) -> tuple[str, ...]:
    """Identify handler slots whose differing definitions must not be collapsed."""

    raw_handlers = group.get("hooks")
    if not isinstance(raw_handlers, list):
        return ()
    keys: list[str] = []
    for handler in raw_handlers:
        if not isinstance(handler, Mapping):
            continue
        raw_command = handler.get("command")
        if isinstance(raw_command, str):  # noqa: SIM108 - keep identity branches explicit
            command = _canonical_command(raw_command)
        else:
            command = _canonical_value(raw_command)
        payload = {
            "schema": f"{CODEX_HOOK_IDENTITY_SCHEMA}:conflict",
            "source_scope": source_scope,
            "source_hooks_enabled": source_hooks_enabled,
            "event": event_name,
            "matcher": _canonical_value(group.get("matcher")),
            "handler_type": _canonical_value(handler.get("type")),
            "command": command,
        }
        keys.append(_canonical_digest(payload))
    return tuple(keys)


def canonical_codex_command_argv(command: str | None) -> tuple[str, ...] | None:
    """Normalize only commands whose shell tokenization is provably uncomplicated."""

    if command is None or _SHELL_SENSITIVE_COMMAND_RE.search(command):
        return None
    try:
        argv = tuple(shlex.split(command, posix=True))
    except ValueError:
        return None
    return argv or None


def _canonical_handler(handler: Mapping[str, object]) -> dict[str, object]:
    values = _canonical_mapping(handler, excluded_keys=frozenset({"command"}))
    raw_command = handler.get("command")
    if isinstance(raw_command, str):
        values["command"] = _canonical_command(raw_command)
    else:
        values["command"] = _canonical_value(raw_command)
    return values


def _canonical_command(command: str) -> dict[str, object]:
    argv = canonical_codex_command_argv(command)
    if argv is not None:
        return {"mode": "argv", "argv": list(argv)}
    return {"mode": "shell", "text": command}


def _canonical_mapping(
    value: Mapping[Any, Any],
    *,
    excluded_keys: frozenset[str] = frozenset(),
) -> dict[str, object]:
    items: list[tuple[str, object]] = []
    for key, item in value.items():
        if isinstance(key, str) and key in excluded_keys:
            continue
        canonical_key = key if isinstance(key, str) else f"<{type(key).__name__}>:{key!r}"
        items.append((canonical_key, _canonical_value(item)))
    return {key: item for key, item in sorted(items, key=lambda pair: pair[0])}


def _canonical_value(value: object) -> object:
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return {"type": "float", "value": repr(value)}
        return int(value) if value.is_integer() else value
    if isinstance(value, Mapping):
        return _canonical_mapping(value)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical_value(item) for item in value]
    if isinstance(value, datetime | date | time):
        return {"type": type(value).__name__, "value": value.isoformat()}
    return {"type": type(value).__name__, "value": repr(value)}


def _canonical_digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "CODEX_HOOK_IDENTITY_SCHEMA",
    "canonical_codex_command_argv",
    "canonical_codex_hook_conflict_keys",
    "canonical_codex_hook_group_identity",
    "canonical_codex_hook_identity",
]
