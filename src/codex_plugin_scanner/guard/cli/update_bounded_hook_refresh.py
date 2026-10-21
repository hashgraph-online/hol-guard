"""Refresh managed bounded hook clients after a Guard package update."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..adapters import copilot, devin, hermes, kimi, openclaw_support, zcode
from ..adapters.base import HarnessContext
from ..adapters.bounded_cli_hook_bridge import _render_bounded_hook_script, bounded_hook_script_path
from ..store import GuardStore

# Harnesses whose managed hook command points at a stable client script under
# ``managed/bounded-hooks``. The command line never changes across releases, so
# reinstall checks that compare commands miss a stale client body. Grok is
# refreshed by its own repair path.
_BOUNDED_HOOK_TIMEOUTS: tuple[tuple[str, str, float], ...] = (
    ("zcode", "ZCode", zcode._GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS),
    ("devin", "Devin", devin._GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS),
    ("kimi", "Kimi", kimi._GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS),
    ("copilot", "Copilot", copilot._GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS),
    ("openclaw", "OpenClaw", openclaw_support._GUARD_PRETOOL_INTERNAL_TIMEOUT_SECONDS),
    ("hermes", "Hermes", hermes._GUARD_PRETOOL_INTERNAL_TIMEOUT_SECONDS),
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
) -> tuple[list[dict[str, object]], list[str]]:
    """Rewrite stale bounded hook clients for active installs; return refreshed installs and warnings."""

    refreshed: list[dict[str, object]] = []
    warnings: list[str] = []
    for harness, display_name, timeout_seconds in _BOUNDED_HOOK_TIMEOUTS:
        try:
            managed_install = store.get_managed_install(harness)
        except (json.JSONDecodeError, sqlite3.Error):
            continue
        if managed_install is None or not bool(managed_install.get("active")):
            continue
        script_path = bounded_hook_script_path(context.guard_home, harness)
        if script_path is None or _crosses_symlink(context.guard_home, script_path) or not script_path.is_file():
            continue
        expected = _render_bounded_hook_script(
            guard_home=context.guard_home,
            harness=harness,
            timeout_seconds=timeout_seconds,
        )
        try:
            if script_path.read_text(encoding="utf-8") == expected:
                continue
            from ..adapters.adapter_safe_output import write_text_at_authorized_path

            write_text_at_authorized_path(script_path, expected)
        except (OSError, RuntimeError, ValueError) as error:
            warnings.append(f"Could not refresh {display_name} hook client during update: {error}")
            continue
        refreshed.append(dict(managed_install))
    return refreshed, warnings


__all__ = ["refresh_bounded_hook_clients"]
