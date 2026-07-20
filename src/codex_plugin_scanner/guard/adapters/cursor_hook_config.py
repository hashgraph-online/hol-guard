"""Cursor managed-hook configuration helpers."""

from __future__ import annotations

import json
import shlex
import stat
from hashlib import sha256
from pathlib import Path

from .base import HarnessContext

HOOK_SCRIPT_NAME = "hol-guard-cursor-hook.py"
_BLOCKING_MANAGED_HOOK_EVENTS = (
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
)
_OBSERVER_MANAGED_HOOK_EVENTS = ("afterShellExecution", "afterMCPExecution")
_MANAGED_HOOK_EVENTS = _BLOCKING_MANAGED_HOOK_EVENTS + _OBSERVER_MANAGED_HOOK_EVENTS
_MANAGED_HOOK_TIMEOUT_SECONDS = 45


def _managed_hook_entry(
    context: HarnessContext,
    *,
    script_path: Path,
    event_name: str,
) -> dict[str, object]:
    del context
    entry: dict[str, object] = {
        "command": str(script_path.resolve()),
        "timeout": _MANAGED_HOOK_TIMEOUT_SECONDS,
        "failClosed": event_name in _BLOCKING_MANAGED_HOOK_EVENTS,
    }
    return entry


def _strip_managed_hook_entries(entries: object, *, script_path: Path) -> list[object]:
    if not isinstance(entries, list):
        return []
    command = str(script_path.resolve())
    return [entry for entry in entries if not _is_managed_hook_entry(entry, command=command)]


def _merge_hook_entries(entries: object, hook_entry: dict[str, object], *, event_name: str) -> list[object]:
    del event_name
    normalized = list(entries) if isinstance(entries, list) else []
    command = str(hook_entry.get("command", ""))
    preserved = [entry for entry in normalized if not _is_managed_hook_entry(entry, command=command)]
    return [*preserved, hook_entry]


def _is_managed_hook_entry(entry: object, *, command: str) -> bool:
    if not isinstance(entry, dict):
        return False
    entry_command = entry.get("command")
    if isinstance(entry_command, str) and entry_command == command:
        return True
    return _is_managed_hook_command(entry_command)


def _is_managed_hook_command(command: object) -> bool:
    if not isinstance(command, str):
        return False
    lowered = command.lower()
    if "hol-guard-cursor-hook" in lowered:
        return True
    if HOOK_SCRIPT_NAME.lower() in lowered:
        return True
    if "hol_guard_hook_argv" not in lowered.replace("-", "_"):
        return False
    if "--harness" not in lowered or "cursor" not in lowered:
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if tokens and Path(tokens[0]).name == HOOK_SCRIPT_NAME:
        return True
    return Path(tokens[0]).name.lower().startswith("python") if tokens else False


def _is_managed_hook_script(source: str) -> bool:
    return "Managed by HOL Guard" in source and HOOK_SCRIPT_NAME in source


def _managed_hooks_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized: dict[str, object] = {"version": 1, "hooks": {}}
    version = payload.get("version")
    if isinstance(version, int):
        normalized["version"] = version
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        normalized["hooks"] = {
            str(name): list(entries) if isinstance(entries, list) else entries for name, entries in hooks.items()
        }
        return normalized
    normalized["hooks"] = {
        str(name): list(entries) for name, entries in payload.items() if name != "version" and isinstance(entries, list)
    }
    return normalized


def _inline_hooks(payload: dict[str, object]) -> dict[str, object]:
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        normalized = {
            str(hook_name): list(entries) if isinstance(entries, list) else entries
            for hook_name, entries in hooks.items()
        }
        payload["hooks"] = normalized
        return normalized
    normalized: dict[str, object] = {}
    payload["hooks"] = normalized
    return normalized


def _json_object(path: Path, *, recover_missing: bool) -> dict[str, object]:
    if not path.is_file():
        if recover_missing:
            return {}
        raise RuntimeError(f"Guard refused to overwrite missing Cursor hooks config at {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Guard refused to overwrite unreadable Cursor hooks config at {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Guard refused to overwrite non-object Cursor hooks config at {path}")
    return payload


def _hooks_backup_path(target_path: Path, context: HarnessContext) -> Path:
    digest = sha256(str(target_path.resolve()).encode("utf-8")).hexdigest()[:12]
    return context.guard_home / "managed" / "cursor" / f"hooks-{digest}.backup.json"


def _hooks_state_path(target_path: Path, context: HarnessContext) -> Path:
    digest = sha256(str(target_path.resolve()).encode("utf-8")).hexdigest()[:12]
    return context.guard_home / "managed" / "cursor" / f"hooks-{digest}.state.json"


def _backup_payload(backup_path: Path) -> dict[str, str | bool | None]:
    try:
        payload = json.loads(backup_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"readable": False, "existed": False, "content": None}
    if not isinstance(payload, dict):
        return {"readable": False, "existed": False, "content": None}
    existed = payload.get("existed") is True
    content = payload.get("content")
    return {"readable": True, "existed": existed, "content": content if isinstance(content, str) else None}


def _make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
