"""Validated lifecycle path recovery for Copilot adapter state."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from ...safe_output import write_text_atomic_no_follow
from .adapter_state_integrity import adapter_state_is_authenticated, authenticate_adapter_state
from .base import HarnessContext, _ensure_path_within_root, _json_payload

CopilotStateEntry = tuple[Path, Path, Path, dict[str, object]]
PathFactory = Callable[[Path, HarnessContext], Path]


def write_copilot_state(
    context: HarnessContext,
    *,
    target_path: Path,
    backup_path: Path,
    state_path: Path,
    scope: str,
) -> None:
    payload = authenticate_adapter_state(
        context.guard_home,
        harness="copilot",
        payload={
            "managed_config_path": str(target_path),
            "backup_path": str(backup_path),
            "scope": scope,
            "workspace_dir": str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None,
        },
    )
    write_text_atomic_no_follow(state_path, json.dumps(payload, indent=2) + "\n")


def validated_copilot_state_entries(
    context: HarnessContext,
    *,
    state_path_for: PathFactory,
    backup_path_for: PathFactory,
) -> list[CopilotStateEntry]:
    state_dir = context.guard_home / "managed" / "copilot"
    _ensure_path_within_root(context.guard_home, state_dir, label="Copilot state")
    entries: list[CopilotStateEntry] = []
    for state_path in sorted(state_dir.glob("*.state.json")):
        entry = _validated_entry(
            context,
            state_path,
            _json_payload(state_path),
            state_path_for=state_path_for,
            backup_path_for=backup_path_for,
        )
        if entry is not None:
            entries.append(entry)
    return entries


def _validated_entry(
    context: HarnessContext,
    state_path: Path,
    payload: dict[str, object],
    *,
    state_path_for: PathFactory,
    backup_path_for: PathFactory,
) -> CopilotStateEntry | None:
    authenticated = adapter_state_is_authenticated(
        context.guard_home,
        harness="copilot",
        payload=payload,
    )
    if "state_authentication" in payload and not authenticated:
        return None
    managed_value = payload.get("managed_config_path")
    backup_value = payload.get("backup_path")
    if not isinstance(managed_value, str) or not isinstance(backup_value, str):
        return None
    if not managed_value or not backup_value or "\x00" in managed_value or "\x00" in backup_value:
        return None
    managed_path = Path(managed_value)
    backup_path = Path(backup_value)
    if not managed_path.is_absolute() or not backup_path.is_absolute():
        return None

    global_target = str((context.home_dir / ".copilot" / "mcp-config.json").resolve())
    target_roots = {global_target: context.home_dir}
    workspace_value = payload.get("workspace_dir")
    if authenticated and isinstance(workspace_value, str) and workspace_value and "\x00" not in workspace_value:
        workspace_path = Path(workspace_value)
        if workspace_path.is_absolute():
            workspace = workspace_path.resolve()
            target_roots[str((workspace / ".mcp.json").resolve())] = workspace
            target_roots[str((workspace / ".vscode" / "mcp.json").resolve())] = workspace
    elif context.workspace_dir is not None:
        workspace = context.workspace_dir.resolve()
        target_roots[str((workspace / ".mcp.json").resolve())] = workspace
        target_roots[str((workspace / ".vscode" / "mcp.json").resolve())] = workspace
    managed_root = target_roots.get(str(managed_path.resolve()))
    if managed_root is None:
        return None
    try:
        _ensure_path_within_root(managed_root, managed_path, label="Copilot managed config")
    except ValueError:
        return None

    expected_state = state_path_for(managed_path, context)
    expected_backup = backup_path_for(managed_path, context)
    try:
        _ensure_path_within_root(context.guard_home, expected_state, label="Copilot state")
        _ensure_path_within_root(context.guard_home, expected_backup, label="Copilot backup")
    except ValueError:
        return None
    if state_path.resolve() != expected_state.resolve() or backup_path.resolve() != expected_backup.resolve():
        return None
    return state_path, managed_path, backup_path, payload
