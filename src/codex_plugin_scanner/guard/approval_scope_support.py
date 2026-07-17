"""Derived approval-scope support for pending Guard review requests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from .models import DecisionScope
from .package_execution_context import (
    PACKAGE_EXECUTION_CONTEXT_VERSION,
    PackageExecutionContext,
    package_execution_context_from_scanner_evidence,
)

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
    if _is_package_request_artifact(
        artifact_id=_string_or_none(request.get("artifact_id")),
        artifact_type=_string_or_none(request.get("artifact_type")),
    ):
        package_context = package_execution_context_from_scanner_evidence(request.get("scanner_evidence"))
        if package_context is not None and package_context.portable and _derived_workspace_scope_target(request):
            return ("artifact", "workspace")
        return ("artifact",)
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


def package_request_portable_workspace_scope(
    *,
    artifact_id: str | None,
    artifact_hash: str | None,
    artifact_type: str | None = None,
    execution_context: PackageExecutionContext | None = None,
) -> str | None:
    if not _is_package_request_artifact(artifact_id=artifact_id, artifact_type=artifact_type):
        return None
    if artifact_hash is None or not artifact_hash.strip() or artifact_hash == "unknown":
        return None
    if execution_context is None or not execution_context.portable:
        return None
    if execution_context.version != PACKAGE_EXECUTION_CONTEXT_VERSION:
        return None
    material = {
        "artifact_hash": artifact_hash.strip(),
        "artifact_id": artifact_id.strip() if artifact_id is not None else None,
        "execution_context": execution_context.digest,
        "scope": "package-request-workspace",
        "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"package-request-workspace:v{PACKAGE_EXECUTION_CONTEXT_VERSION}:{digest}"


def package_request_runtime_workspace_scope(
    *,
    artifact_id: str | None,
    artifact_hash: str | None,
    artifact_type: str | None = None,
    execution_context: PackageExecutionContext | None,
) -> str | None:
    """Return the only workspace identity valid for a package-policy lookup.

    Non-portable contexts receive an exact, context-bound sentinel.  It keeps
    artifact-once decisions functional while ensuring legacy path-only and v1
    workspace approvals cannot match.
    """

    if not _is_package_request_artifact(artifact_id=artifact_id, artifact_type=artifact_type):
        return None
    if artifact_hash is None or not artifact_hash.strip() or artifact_hash == "unknown":
        return None
    portable = package_request_portable_workspace_scope(
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        artifact_type=artifact_type,
        execution_context=execution_context,
    )
    if portable is not None:
        return portable
    if execution_context is None or execution_context.version != PACKAGE_EXECUTION_CONTEXT_VERSION:
        return None
    material = {
        "artifact_hash": artifact_hash.strip(),
        "artifact_id": artifact_id.strip() if artifact_id is not None else None,
        "execution_context": execution_context.digest,
        "scope": "package-request-workspace-exact",
        "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"package-request-workspace-exact:v{PACKAGE_EXECUTION_CONTEXT_VERSION}:{digest}"


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
    return str(workspace_root)


def _is_package_request_artifact(*, artifact_id: str | None, artifact_type: str | None) -> bool:
    if artifact_type == "package_request":
        return True
    return isinstance(artifact_id, str) and ":package-request:" in artifact_id


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
