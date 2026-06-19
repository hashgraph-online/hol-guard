"""Derived approval-scope support for pending Guard review requests."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .models import DecisionScope

_SCOPED_APPROVAL_FAMILIES = frozenset(
    {
        "file-read",
        "mcp",
        "mcp-tool",
        "package-request",
        "prompt",
        "prompt-env-read",
        "prompt-file",
        "tool-action",
    }
)


def supported_request_scopes(request: Mapping[str, object]) -> tuple[DecisionScope, ...]:
    scopes: list[DecisionScope] = ["artifact"]
    if _string_or_none(request.get("publisher")) is not None:
        scopes.append("publisher")
    if _derived_workspace_scope_target(request) is not None:
        scopes.append("workspace")
    if _request_scoped_family_key(request) is not None:
        scopes.extend(("harness", "global"))
    return tuple(scopes)


def resolve_request_workspace_scope(
    request: Mapping[str, object],
    selected_workspace: str | None,
) -> str:
    workspace = _derived_workspace_scope_target(request)
    if workspace is None:
        raise ValueError("workspace_scope_unavailable")
    bound_selected = _string_or_none(selected_workspace)
    if bound_selected is not None and _normalized_workspace_path(bound_selected) != _normalized_workspace_path(
        workspace
    ):
        raise ValueError("workspace_scope_mismatch")
    return workspace


def _derived_workspace_scope_target(request: Mapping[str, object]) -> str | None:
    stored_workspace = _string_or_none(request.get("workspace"))
    if stored_workspace is not None:
        return stored_workspace
    config_path = _string_or_none(request.get("config_path"))
    if config_path is None:
        return None
    try:
        config_file = Path(config_path).resolve()
    except Exception:
        config_file = Path(config_path)
    parent = config_file.parent
    workspace_root = parent.parent if parent.name.startswith(".") else parent
    workspace_value = str(workspace_root)
    return workspace_value or None


def _request_scoped_family_key(request: Mapping[str, object]) -> str | None:
    return _artifact_family_key(_string_or_none(request.get("artifact_id")))


def _artifact_family_key(artifact_id: str | None) -> str | None:
    if artifact_id is None or not artifact_id.strip():
        return None
    if artifact_id.startswith("family:"):
        family = artifact_id.removeprefix("family:").strip().lower()
        return f"family:{family}" if family in _SCOPED_APPROVAL_FAMILIES else None
    parts = artifact_id.split(":")
    if len(parts) < 3:
        return None
    family = parts[2].strip().lower()
    if family not in _SCOPED_APPROVAL_FAMILIES:
        return None
    return f"family:{family}"


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _normalized_workspace_path(value: str) -> str:
    try:
        resolved = str(Path(value).resolve())
    except Exception:
        resolved = value
    normalized = resolved.strip().replace("\\", "/")
    while len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized.lower()
    return normalized
