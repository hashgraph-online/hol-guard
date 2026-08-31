"""Workspace binding checks for remote package-shim audits."""

from __future__ import annotations

from pathlib import Path

from ..adapters.base import HarnessContext


def audit_workspace_is_bound_to_context(payload: dict[str, object], context: HarnessContext) -> bool:
    requested = payload.get("workspace_dir") if payload.get("workspace_dir") is not None else payload.get("workspace")
    if requested is None:
        return True
    if not isinstance(requested, str) or context.workspace_dir is None:
        return False
    try:
        requested_path = Path(requested).expanduser()
        if not requested_path.is_absolute():
            requested_path = context.workspace_dir / requested_path
        return requested_path.resolve(strict=True) == context.workspace_dir.resolve(strict=True)
    except (OSError, RuntimeError):
        return False


def bind_relative_audit_workspace(payload: dict[str, object], context: HarnessContext) -> dict[str, object]:
    key = "workspace_dir" if payload.get("workspace_dir") is not None else "workspace"
    requested = payload.get(key)
    if not isinstance(requested, str) or Path(requested).expanduser().is_absolute() or context.workspace_dir is None:
        return payload
    bound = (context.workspace_dir / Path(requested).expanduser()).resolve(strict=True)
    return {**payload, key: str(bound)}
