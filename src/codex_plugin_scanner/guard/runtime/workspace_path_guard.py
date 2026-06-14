"""Contain workspace-relative manifest and lockfile reads."""

from __future__ import annotations

from pathlib import Path


def resolve_path_within_workspace(workspace_dir: Path, relative_path: str) -> Path | None:
    """Resolve a workspace-relative path and ensure it remains inside the workspace."""

    if not relative_path:
        return None
    candidate = Path(relative_path)
    if candidate.is_absolute():
        return None
    workspace_root = workspace_dir.expanduser().resolve()
    try:
        resolved = (workspace_root / candidate).resolve()
        resolved.relative_to(workspace_root)
    except (OSError, ValueError):
        return None
    return resolved


def read_text_within_workspace(workspace_dir: Path, relative_path: str) -> str | None:
    resolved = resolve_path_within_workspace(workspace_dir, relative_path)
    if resolved is None or not resolved.is_file():
        return None
    try:
        return resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def read_bytes_within_workspace(workspace_dir: Path, relative_path: str) -> bytes | None:
    resolved = resolve_path_within_workspace(workspace_dir, relative_path)
    if resolved is None or not resolved.is_file():
        return None
    try:
        return resolved.read_bytes()
    except OSError:
        return None


def existing_paths_within_workspace(
    workspace: Path | None,
    candidates: tuple[str, ...] | list[str],
) -> tuple[str, ...]:
    """Return workspace-contained relative paths that exist on disk."""

    if workspace is None:
        return ()
    workspace_root = workspace.expanduser().resolve()
    resolved_paths: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        disk_path = resolve_path_within_workspace(workspace_root, candidate)
        if disk_path is None or not disk_path.exists():
            continue
        try:
            normalized = disk_path.relative_to(workspace_root).as_posix()
        except ValueError:
            continue
        if normalized not in resolved_paths:
            resolved_paths.append(normalized)
    return tuple(resolved_paths)
