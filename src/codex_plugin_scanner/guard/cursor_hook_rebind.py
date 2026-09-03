"""Rewrite Guard-managed Cursor hooks that still bake a pruneable Core path."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .adapters.base import HarnessContext
from .adapters.cursor_hook_config import _is_managed_hook_script
from .adapters.cursor_hooks import cursor_hook_script_path, install_cursor_hooks, managed_hook_script_path
from .stable_guard_cli import argv0_is_ephemeral_desktop_cli, frozen_launcher_is_prune_safe, resolve_frozen_guard_cli


def _assignment_argv(source: str, name: str) -> list[str] | None:
    prefix = f"{name} = "
    for line in source.splitlines():
        if not line.startswith(prefix):
            continue
        try:
            payload = json.loads(line[len(prefix) :])
        except json.JSONDecodeError:
            return None
        if isinstance(payload, list) and all(isinstance(item, str) for item in payload):
            return payload
        return None
    return None


def cursor_hook_script_bakes_ephemeral_cli(source: str) -> bool:
    """Return whether a managed Cursor hook script still bakes a versions/ Core path."""

    if not _is_managed_hook_script(source):
        return False
    for name in ("GUARD_CLI", "GUARD_RECOVERY_COMMAND"):
        argv = _assignment_argv(source, name)
        if argv and argv0_is_ephemeral_desktop_cli(argv[0]):
            return True
    return False


def can_rebind_to_stable_frozen_cli() -> bool:
    """Return whether this process would bake a prune-safe frozen launcher."""

    if not bool(getattr(sys, "frozen", False)):
        return False
    return frozen_launcher_is_prune_safe(resolve_frozen_guard_cli())


def rebind_stale_cursor_hooks(guard_home: Path, *, home_dir: Path) -> dict[str, object]:
    """Rewrite managed Cursor hook scripts that still bake a versions/ Core path."""

    if not can_rebind_to_stable_frozen_cli():
        return {"rebound": False, "reason": "stable_frozen_cli_unavailable"}
    context = HarnessContext(home_dir=home_dir, guard_home=guard_home, workspace_dir=None)
    candidates = [
        path for path in (cursor_hook_script_path(context), managed_hook_script_path(context)) if path.is_file()
    ]
    if not candidates:
        return {"rebound": False, "reason": "cursor_hook_script_absent"}
    needs_rebind = False
    for path in candidates:
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as error:
            return {"rebound": False, "reason": "cursor_hook_script_unreadable", "error": str(error)}
        if cursor_hook_script_bakes_ephemeral_cli(source):
            needs_rebind = True
            break
    if not needs_rebind:
        return {"rebound": False, "reason": "cursor_hook_script_current"}
    try:
        install_cursor_hooks(context)
    except (OSError, RuntimeError) as error:
        return {"rebound": False, "reason": "cursor_hook_script_rebind_failed", "error": str(error)}
    return {"rebound": True, "reason": "cursor_hook_script_rebound"}


__all__ = [
    "can_rebind_to_stable_frozen_cli",
    "cursor_hook_script_bakes_ephemeral_cli",
    "rebind_stale_cursor_hooks",
]
