"""Rewrite Guard-managed Cursor hooks that still bake a pruneable Core path."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .adapters.base import HarnessContext
from .adapters.cursor_hook_config import _hooks_state_path, _is_managed_hook_script
from .adapters.cursor_hooks import (
    cursor_hook_script_path,
    cursor_hook_script_source,
    cursor_hooks_path,
    install_cursor_hooks,
    managed_hook_script_path,
)
from .adapters.guard_cli_attestation import resolve_attested_guard_cli
from .stable_guard_cli import (
    argv0_is_ephemeral_desktop_cli,
    frozen_cli_path_is_runnable,
    frozen_launcher_is_prune_safe,
    resolve_frozen_guard_cli,
)

_READ_ERRORS = (OSError, UnicodeError)


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
    needs_rebind = live_source != expected_source or cursor_hook_script_bakes_ephemeral_cli(live_source)
    if managed_source is not None:
        needs_rebind = (
            needs_rebind or managed_source != expected_source or cursor_hook_script_bakes_ephemeral_cli(managed_source)
        )
    if not needs_rebind and _state_matches_attested_cli(context):
        return {"rebound": False, "reason": "cursor_hook_script_current"}
    try:
        install_cursor_hooks(context)
    except (OSError, RuntimeError, UnicodeError) as error:
        return {"rebound": False, "reason": "cursor_hook_script_rebind_failed", "error": str(error)}
    return {"rebound": True, "reason": "cursor_hook_script_rebound"}


__all__ = [
    "can_rebind_to_stable_frozen_cli",
    "cursor_hook_script_bakes_ephemeral_cli",
    "rebind_stale_cursor_hooks",
]
