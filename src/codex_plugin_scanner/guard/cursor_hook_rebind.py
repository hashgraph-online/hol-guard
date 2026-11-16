"""Rewrite Guard-managed Cursor hooks that still bake a pruneable Core path."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .adapters._modules.cursor.cursor_hook_native import native_cursor_hook_bridge
from .adapters.base import HarnessContext
from .adapters.cursor_hook_config import (
    _ask,
    _flag,
    _hooks_state_path,
    _is_managed_hook_script,
    _live_managed_commands,
    isolated_cursor_hook_python,
)
from .adapters.cursor_hooks import (
    cursor_hook_script_path,
    cursor_hook_script_source,
    cursor_hooks_path,
    install_cursor_hooks,
    managed_hook_script_path,
)
from .adapters.guard_cli_attestation import resolve_attested_guard_cli
from .stable_guard_cli import (
    frozen_cli_path_is_runnable,
    frozen_launcher_is_prune_safe,
    resolve_frozen_guard_cli,
)

_READ_ERRORS = (OSError, UnicodeError)


def cursor_hook_script_bakes_ephemeral_cli(source: str) -> bool:
    """Return whether a managed Cursor hook script still bakes a versions/ Core path."""

    return _flag(_ask("ephemeral", source=source), "ephemeral")


def can_rebind_to_stable_frozen_cli() -> bool:
    """Return whether this process would bake a prune-safe frozen launcher."""

    if not bool(getattr(sys, "frozen", False)):
        return False
    launcher = Path(resolve_frozen_guard_cli())
    return frozen_launcher_is_prune_safe(str(launcher)) and frozen_cli_path_is_runnable(launcher)


def _read_hook_script(path: Path) -> tuple[str | None, dict[str, object] | None]:
    try:
        return path.read_text(encoding="utf-8"), None
    except _READ_ERRORS as error:
        return None, {
            "rebound": False,
            "reason": "cursor_hook_script_unreadable",
            "error": str(error),
        }


def _state_matches_attested_cli(context: HarnessContext) -> bool:
    state_path = _hooks_state_path(cursor_hooks_path(context), context)
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        attested = resolve_attested_guard_cli(context)
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError):
        return False
    return isinstance(state, dict) and state.get("guard_cli_identity") == attested.manifest_payload()


def rebind_stale_cursor_hooks(guard_home: Path, *, home_dir: Path) -> dict[str, object]:
    """Rewrite managed Cursor hook scripts that still bake a versions/ Core path."""

    if not can_rebind_to_stable_frozen_cli():
        return {"rebound": False, "reason": "stable_frozen_cli_unavailable"}
    context = HarnessContext(home_dir=home_dir, guard_home=guard_home, workspace_dir=None)
    live_path = cursor_hook_script_path(context)
    if not live_path.is_file():
        return {"rebound": False, "reason": "cursor_hook_script_absent"}
    live_source, error = _read_hook_script(live_path)
    if error is not None or live_source is None:
        return error or {"rebound": False, "reason": "cursor_hook_script_unreadable"}
    if not _is_managed_hook_script(live_source):
        return {"rebound": False, "reason": "cursor_hook_script_unmanaged"}
    managed_path = managed_hook_script_path(context)
    managed_source: str | None = None
    if managed_path.is_file():
        managed_source, error = _read_hook_script(managed_path)
        if error is not None or managed_source is None:
            return error or {"rebound": False, "reason": "cursor_hook_script_unreadable"}
        if not _is_managed_hook_script(managed_source):
            return {"rebound": False, "reason": "cursor_hook_script_unmanaged"}
    try:
        expected_source = cursor_hook_script_source(context)
    except RuntimeError as error:
        return {"rebound": False, "reason": "cursor_hook_script_rebind_failed", "error": str(error)}
    try:
        commands = _live_managed_commands(_live_hooks(context))
        needs_rebind = _flag(
            _ask(
                "rebind",
                live=live_source,
                managed=managed_source,
                expected=expected_source,
                commands=[[command, frozen] for command, frozen in commands],
                isolated_python=isolated_cursor_hook_python() is not None,
                native_bridge=native_cursor_hook_bridge(guard_home) is not None,
            ),
            "rebind",
        )
    except RuntimeError as error:
        return {"rebound": False, "reason": "cursor_hook_script_rebind_failed", "error": str(error)}
    if not needs_rebind and _state_matches_attested_cli(context):
        return {"rebound": False, "reason": "cursor_hook_script_current"}
    try:
        install_cursor_hooks(context)
    except (OSError, RuntimeError, UnicodeError) as error:
        return {"rebound": False, "reason": "cursor_hook_script_rebind_failed", "error": str(error)}
    return {"rebound": True, "reason": "cursor_hook_script_rebound"}


def _live_hooks(context: HarnessContext) -> dict[str, object] | None:
    try:
        payload = json.loads(cursor_hooks_path(context).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    nested = payload.get("hooks")
    return nested if isinstance(nested, dict) else payload


__all__ = [
    "can_rebind_to_stable_frozen_cli",
    "cursor_hook_script_bakes_ephemeral_cli",
    "rebind_stale_cursor_hooks",
]
