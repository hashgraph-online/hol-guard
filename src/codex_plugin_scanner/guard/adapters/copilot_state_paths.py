"""Validated lifecycle path recovery for Copilot adapter state."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from ...safe_output import write_text_atomic_no_follow
from .adapter_safe_output import write_text_at_authorized_path
from .adapter_state_integrity import (
    adapter_state_is_authenticated,
    authenticate_adapter_state,
    authenticated_adapter_path,
)
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
            "managed_config_path": str(target_path.resolve()),
            "backup_path": str(backup_path.resolve()),
            "scope": scope,
            "workspace_dir": str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None,
        },
    )
    write_text_atomic_no_follow(state_path, json.dumps(payload, indent=2) + "\n")


def commit_copilot_target_and_state(
    context: HarnessContext,
    *,
    target_path: Path,
    target_payload: str,
    original_text: str | None,
    backup_path: Path,
    state_path: Path,
    scope: str,
) -> None:
    """Commit backup, target, and state as one recoverable lifecycle transaction."""

    preserve_existing_backup = backup_path.exists() and copilot_state_authorizes_backup_reuse(
        context,
        target_path=target_path,
        backup_path=backup_path,
        state_path=state_path,
    )
    backup_replaced = False
    target_attempted = False
    try:
        if not preserve_existing_backup:
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_payload = {"existed": original_text is not None, "content": original_text}
            write_text_at_authorized_path(backup_path, json.dumps(backup_payload, indent=2) + "\n")
            backup_replaced = True
        target_attempted = True
        write_text_at_authorized_path(target_path, target_payload)
        write_copilot_state(
            context,
            target_path=target_path,
            backup_path=backup_path,
            state_path=state_path,
            scope=scope,
        )
    except BaseException:
        try:
            if target_attempted:
                if original_text is None:
                    target_path.unlink(missing_ok=True)
                else:
                    write_text_at_authorized_path(target_path, original_text)
        finally:
            if backup_replaced:
                backup_path.unlink(missing_ok=True)
        raise


def copilot_state_authorizes_backup_reuse(
    context: HarnessContext,
    *,
    target_path: Path,
    backup_path: Path,
    state_path: Path,
) -> bool:
    """Return whether authenticated durable state binds this target to this backup."""

    if backup_path.is_symlink() or not backup_path.is_file():
        return False
    payload = _json_payload(state_path)
    if not adapter_state_is_authenticated(context.guard_home, harness="copilot", payload=payload):
        return False
    authenticated_target = authenticated_adapter_path(
        context.guard_home,
        harness="copilot",
        payload=payload,
        field="managed_config_path",
    )
    authenticated_backup = authenticated_adapter_path(
        context.guard_home,
        harness="copilot",
        payload=payload,
        field="backup_path",
    )
    return authenticated_target == target_path.resolve() and authenticated_backup == backup_path.resolve()


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
    if not authenticated:
        return None
    managed_value = payload.get("managed_config_path")
    backup_value = payload.get("backup_path")
    if not isinstance(managed_value, str) or not isinstance(backup_value, str):
        return None
    if not managed_value or not backup_value or "\x00" in managed_value or "\x00" in backup_value:
        return None
    global_target = context.home_dir / ".copilot" / "mcp-config.json"
    target_paths = {
        str(global_target): (global_target, context.home_dir),
        str(global_target.resolve()): (global_target, context.home_dir),
    }
    workspace = authenticated_adapter_path(
        context.guard_home,
        harness="copilot",
        payload=payload,
        field="workspace_dir",
    )
    if workspace is not None:
        target_paths[str(workspace / ".mcp.json")] = (workspace / ".mcp.json", workspace)
        target_paths[str(workspace / ".vscode" / "mcp.json")] = (workspace / ".vscode" / "mcp.json", workspace)
    elif context.workspace_dir is not None:
        for workspace in {context.workspace_dir, context.workspace_dir.resolve()}:
            target_paths[str(workspace / ".mcp.json")] = (workspace / ".mcp.json", context.workspace_dir)
            target_paths[str(workspace / ".vscode" / "mcp.json")] = (
                workspace / ".vscode" / "mcp.json",
                context.workspace_dir,
            )
    managed_entry = target_paths.get(managed_value)
    if managed_entry is None:
        return None
    managed_path, managed_root = managed_entry
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
    if state_path.resolve() != expected_state.resolve() or backup_value not in {
        str(expected_backup),
        str(expected_backup.resolve()),
    }:
        return None
    return state_path, managed_path, expected_backup, payload
