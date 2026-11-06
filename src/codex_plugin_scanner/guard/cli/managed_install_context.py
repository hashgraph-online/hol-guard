"""Context reconstruction for persisted managed harness installations."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ..adapters.base import HarnessContext


def managed_install_context(
    context: HarnessContext,
    managed_install: dict[str, object],
) -> tuple[HarnessContext, str | None]:
    """Rebind a harness context without discarding caller-specific fields."""

    managed_workspace = managed_install.get("workspace")
    if not isinstance(managed_workspace, str) or not managed_workspace.strip():
        return replace(context, workspace_dir=None), None
    try:
        workspace_path = Path(managed_workspace).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("managed install workspace path is invalid") from exc
    return replace(context, workspace_dir=workspace_path), str(workspace_path)


__all__ = ["managed_install_context"]
