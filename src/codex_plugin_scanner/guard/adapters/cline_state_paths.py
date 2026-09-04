"""Validated persisted-path and launcher handling for managed Cline hooks."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..windows_paths import trusted_windows_system_executable
from .base import HarnessContext
from .cline_paths import cline_hook_roots, ensure_safe_cline_destination

_EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "TaskStart", "TaskError", "SessionShutdown")
_MARKER = "HOL_GUARD_MANAGED_CLINE_HOOK_V1"


def canonical_cline_state_path(
    context: HarnessContext,
    event: str,
    value: object,
    *,
    worker: bool = False,
    saved_root: object | None = None,
) -> Path | None:
    """Bind one persisted path to a Cline slot derived from trusted context."""

    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    recorded = Path(value)
    if not recorded.is_absolute():
        return None
    if worker:
        candidates = (context.guard_home / "managed" / "cline" / "hook-workers" / f"{event}.py",)
    else:
        suffix = ".ps1" if os.name == "nt" else ""
        roots = list(cline_hook_roots(context))
        persisted_root = _canonical_saved_hook_root(context, saved_root)
        if persisted_root is not None and persisted_root not in roots:
            roots.append(persisted_root)
        candidates = tuple(root / f"{event}{suffix}" for root in roots)
    try:
        recorded_resolved = recorded.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    for candidate in candidates:
        try:
            ensure_safe_cline_destination(context, candidate)
            candidate_resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if recorded_resolved == candidate_resolved:
            return candidate_resolved
    return None


def _canonical_saved_hook_root(context: HarnessContext, value: object) -> Path | None:
    """Recover an installed custom hook root after its environment override changes."""

    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    recorded = Path(value)
    if not recorded.is_absolute() or recorded.name.lower() != "hooks":
        return None
    probe = recorded / ("PreToolUse.ps1" if os.name == "nt" else "PreToolUse")
    try:
        ensure_safe_cline_destination(context, probe)
        resolved = recorded.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    home = context.home_dir.resolve(strict=False)
    if resolved != home and not resolved.is_relative_to(home):
        return None
    return resolved


def cline_hook_command(path: Path) -> list[str]:
    """Build a hook command without resolving an interpreter from ambient PATH."""

    if path.suffix.lower() != ".ps1":
        return [str(path)]
    try:
        shell = trusted_windows_system_executable("WindowsPowerShell", "v1.0", "powershell.exe")
    except OSError:
        return []
    return [str(shell), "-NoProfile", "-File", str(path)]


def uninstall_persisted_cline_hooks(context: HarnessContext) -> dict[str, object]:
    """Remove only managed hooks still bound to their persisted canonical slots."""

    state_path = context.guard_home / "managed" / "cline" / "native-hooks-state.json"
    try:
        loaded = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        loaded = {}
    state = loaded if isinstance(loaded, dict) else {}
    removed: list[str] = []
    retained: list[str] = []
    for group, worker in ((state.get("paths"), False), (state.get("workers"), True)):
        if not isinstance(group, dict):
            continue
        for event in _EVENTS:
            value = group.get(event)
            if not isinstance(value, str):
                continue
            path = canonical_cline_state_path(
                context,
                event,
                value,
                worker=worker,
                saved_root=state.get("root"),
            )
            if path is None:
                try:
                    exists = Path(value).exists()
                except (OSError, ValueError):
                    exists = False
                if exists:
                    retained.append(value)
                continue
            try:
                managed = path.is_file() and not path.is_symlink() and _MARKER in path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                managed = False
            if not managed:
                retained.append(str(path))
                continue
            try:
                path.unlink()
                removed.append(str(path))
            except OSError:
                retained.append(str(path))
    if not retained and state_path.is_file():
        state_path.unlink()
    return {
        "transport": "hooks",
        "removed": removed,
        "retained_modified_or_unowned": retained,
        "complete": not retained,
    }


__all__ = ["canonical_cline_state_path", "cline_hook_command", "uninstall_persisted_cline_hooks"]
