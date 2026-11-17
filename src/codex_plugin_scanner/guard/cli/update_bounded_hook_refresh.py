"""Move bounded hooks that still run a managed client script onto the native runtime."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..harness.base import HarnessContext
from ..harness.bounded_cli_hook_bridge import bounded_hook_script_path
from ..store import GuardStore

# Harnesses older releases installed with a stable client script under
# ``managed/bounded-hooks``. Grok is repaired by its own path.
_BOUNDED_HOOK_HARNESSES: tuple[tuple[str, str], ...] = (
    ("zcode", "ZCode"),
    ("devin", "Devin"),
    ("kimi", "Kimi"),
    ("copilot", "Copilot"),
    ("openclaw", "OpenClaw"),
    ("hermes", "Hermes"),
    ("muse", "Muse"),
)


def _crosses_symlink(guard_home: Path, script_path: Path) -> bool:
    """Return whether any path component below the Guard home is a symlink."""

    current = guard_home
    for part in script_path.relative_to(guard_home).parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def refresh_bounded_hook_clients(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[list[dict[str, object]], list[str]]:
    """Reinstall active hooks that still name a client script; return reinstalled installs and warnings."""

    from .install_commands import apply_managed_install
    from .managed_install_context import managed_install_context

    refreshed: list[dict[str, object]] = []
    warnings: list[str] = []
    for harness, display_name in _BOUNDED_HOOK_HARNESSES:
        try:
            managed_install = store.get_managed_install(harness)
        except (json.JSONDecodeError, sqlite3.Error):
            continue
        if managed_install is None or not bool(managed_install.get("active")):
            continue
        script_path = bounded_hook_script_path(context.guard_home, harness)
        if script_path is None or _crosses_symlink(context.guard_home, script_path) or not script_path.is_file():
            continue
        try:
            repair_context, repair_workspace = managed_install_context(context, managed_install)
            payload = apply_managed_install(
                "install", harness, False, repair_context, store, repair_workspace or workspace, now
            )
            script_path.unlink(missing_ok=True)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError, sqlite3.Error) as error:
            warnings.append(f"Could not move {display_name} hooks to the native runtime during update: {error}")
            continue
        repaired = payload.get("managed_install")
        refreshed.append(dict(repaired) if isinstance(repaired, dict) else dict(managed_install))
    return refreshed, warnings


__all__ = ["refresh_bounded_hook_clients"]
