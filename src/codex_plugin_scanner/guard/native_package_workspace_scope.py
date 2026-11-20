"""Resident bridge for the ``package_workspace_scope`` op.

A saved package approval is stored and matched under a workspace scope derived
from the artifact identity and the package execution context.  The resident
owns that derivation.  Deriving it a second time in Python lets the two drift,
and a drifted key silently stops a saved "Always allow" from matching, so the
user is asked again for a package they already approved.

This module transports one request and strictly validates the reply.  There is
no Python fallback: an unavailable resident raises
:class:`NativePackageWorkspaceScopeError` rather than guessing a key.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_package_authority import _request_id, _resident_request

_REQUEST_SCHEMA = "guard-package-workspace-scope-request.v1"
_RESULT_SCHEMA = "guard-package-workspace-scope-result.v1"
_WORKSPACE_SCOPE_FEATURE = "package-workspace-scope-v1"
_MAX_REQUEST_BYTES = 1024 * 1024


class NativePackageWorkspaceScopeError(RuntimeError):
    """No authoritative native workspace-scope result was available."""


def _scope_value(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise NativePackageWorkspaceScopeError("Native package workspace scope payload invalid")
    return value


def native_package_workspace_scopes(
    *,
    artifact_id: str | None,
    artifact_hash: str | None,
    artifact_type: str | None,
    execution_context: Any | None,
    guard_home: Path | None = None,
) -> tuple[str | None, str | None]:
    """Return the resident's ``(portable, runtime)`` workspace scopes."""

    if execution_context is None:
        # Both scopes bind a context, so a caller without one has no scope to
        # look up and nothing for the resident to derive.  Approvals saved
        # against an MCP artifact reach this path through
        # ``package_execution_context_from_scanner_evidence``, and asking the
        # resident for two nulls would make every one of them wait on a round
        # trip, and fail where the resident is down.
        return None, None

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "artifact_type": artifact_type,
        "execution_context": execution_context.to_evidence(),
    }
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as cause:
        raise NativePackageWorkspaceScopeError("Native package workspace scope request invalid") from cause
    resolved_home = _resolve_digest_home(guard_home)
    if not ensure_resident_prerequisite(resolved_home):
        raise NativePackageWorkspaceScopeError("Native package workspace scope unavailable")
    response = _resident_request(
        operation="package_workspace_scope",
        request=request,
        guard_home=resolved_home,
        timeout_seconds=2.0,
        required_features=(_WORKSPACE_SCOPE_FEATURE,),
        max_request_bytes=_MAX_REQUEST_BYTES,
        result_schema=_RESULT_SCHEMA,
    )
    if (
        not isinstance(response, dict)
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != request_sha256
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        raise NativePackageWorkspaceScopeError("Native package workspace scope unavailable or invalid")
    payload = response.get("payload")
    if not isinstance(payload, dict):
        raise NativePackageWorkspaceScopeError("Native package workspace scope payload invalid")
    return _scope_value(payload, "portable"), _scope_value(payload, "runtime")
