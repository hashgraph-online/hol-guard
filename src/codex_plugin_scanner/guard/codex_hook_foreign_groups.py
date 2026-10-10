"""Recognise Guard Codex hook groups bound to another Guard home."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path

from .codex_hook_command_line import hook_command_tokens
from .codex_hook_owner_commands import has_codex_harness_tokens

_STATE_PATH_RE = re.compile(r'"state_path"\s*:\s*"([^"]+)"')
_GUARD_HOME_QUERY_RE = re.compile(r"guard-home=([^&\"'\s]+)")


def _hook_group_command_blob(group: object) -> str:
    if not isinstance(group, Mapping):
        return ""
    parts: list[str] = []
    command = group.get("command")
    if isinstance(command, str):
        parts.append(command)
    hooks = group.get("hooks")
    if isinstance(hooks, list):
        for hook in hooks:
            if isinstance(hook, Mapping):
                hook_command = hook.get("command")
                if isinstance(hook_command, str):
                    parts.append(hook_command)
    return "\n".join(parts)


def _looks_like_guard_codex_hook(blob: str) -> bool:
    if "codex_daemon_hook_bridge.py" in blob:
        return True
    if not has_codex_harness_tokens(hook_command_tokens(blob)):
        return False
    if "hol-guard hook" in blob:
        return True
    return "codex_plugin_scanner.cli" in blob and "guard hook" in blob


def _normalize_guard_home_path(value: str) -> Path | None:
    stripped = value.strip().strip("'\"")
    if not stripped:
        return None
    return Path(stripped).expanduser()


def _extract_guard_home_flags(command: str) -> list[Path]:
    homes: list[Path] = []
    tokens = hook_command_tokens(command)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--guard-home" and index + 1 < len(tokens):
            parsed = _normalize_guard_home_path(tokens[index + 1])
            if parsed is not None:
                homes.append(parsed)
            index += 2
            continue
        if token.startswith("--guard-home="):
            parsed = _normalize_guard_home_path(token.split("=", 1)[1])
            if parsed is not None:
                homes.append(parsed)
        index += 1
    return homes


def _extract_guard_homes_from_hook_blob(blob: str) -> tuple[Path, ...]:
    decoded = blob.replace('\\"', '"')
    homes: list[Path] = []
    for command in decoded.split("\n"):
        homes.extend(_extract_guard_home_flags(command))
    for match in _STATE_PATH_RE.finditer(decoded):
        state_path = Path(match.group(1))
        if state_path.name == "daemon-state.json":
            homes.append(state_path.parent)
    for match in _GUARD_HOME_QUERY_RE.finditer(decoded):
        token = match.group(1)
        if token.startswith("/") or token.startswith("~"):
            parsed = _normalize_guard_home_path(token)
            if parsed is not None:
                homes.append(parsed)
    return tuple(homes)


def _resolved_guard_home(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def is_foreign_guard_codex_hook_group(group: object, *, current_guard_home: Path) -> bool:
    """Return True when a Guard Codex hook is bound to a different Guard home."""

    blob = _hook_group_command_blob(group)
    if not _looks_like_guard_codex_hook(blob):
        return False
    extracted = _extract_guard_homes_from_hook_blob(blob)
    if not extracted:
        return False
    current = _resolved_guard_home(current_guard_home.expanduser())
    return all(_resolved_guard_home(home) != current for home in extracted)


def prune_foreign_guard_codex_hook_groups(
    groups: Sequence[object],
    *,
    current_guard_home: Path,
) -> list[object]:
    """Preserve unproven handlers; a different state-home path is not ownership.

    Kept for caller compatibility. Authenticated replacement uses
    ``remove_manifest_bound_hook_events`` instead of path-based pruning.
    """
    return deepcopy(list(groups))


__all__ = ["is_foreign_guard_codex_hook_group", "prune_foreign_guard_codex_hook_groups"]
