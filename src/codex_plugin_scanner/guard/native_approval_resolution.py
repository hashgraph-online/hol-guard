"""Resident bridge for the ``approval_resolution_plan`` op.

Rust owns what resolving an approval request writes: the policy decision
identity (runtime-exact and browser keys included), how it is persisted, the
local-once fallback row, the sibling-request selector and the expiry. This
module only narrows the stored request to the fields the plan reads, binds the
reply by ``request_id`` plus ``request_sha256`` and decodes it. A missing,
malformed or mismatched reply raises; nothing is ever recomputed in Python.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_execution import _resident_request
from .native_store_policy import _payload

APPROVAL_RESOLUTION_PLAN_FEATURE = "approval-resolution-plan-v1"
_REQUEST_SCHEMA = "guard-approval-resolution-plan-request.v1"
_RESULT_SCHEMA = "guard-approval-resolution-plan-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 256 * 1024
UNAVAILABLE = "native_approval_resolution_plan_unavailable"
INTEGRITY_UNAVAILABLE = "native_approval_resolution_plan_integrity_unavailable"
_PERSISTENCE_MODES = frozenset({"none", "persisted", "once", "exact_once"})


class ApprovalResolutionPlanUnavailableError(ValueError):
    """The resident could not plan the resolution; nothing was recomputed."""

    def __init__(self, code: str = UNAVAILABLE) -> None:
        super().__init__(code)


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _sequence(value: object) -> list[object] | None:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return None


def _chain(value: object) -> list[str | None] | None:
    items = _sequence(value)
    if items is None:
        return None
    return [item if isinstance(item, str) else None for item in items]


def _envelope(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    payload = value.get("raw_payload_redacted")
    mode = payload if isinstance(payload, Mapping) else {}
    return {
        "raw_command_text": _text(value.get("raw_command_text")),
        "command": _text(value.get("command")),
        "wrapper_chain": _chain(value.get("wrapper_chain")),
        "permission_mode": _text(mode.get("permission_mode")),
        "permission_mode_camel": _text(mode.get("permissionMode")),
    }


def _browser_intent(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    flags = value.get("sensitive_surface_flags")
    return {
        "intent": _text(value.get("intent")),
        "operation": _text(value.get("operation")),
        "target_origin": _text(value.get("target_origin")),
        "target_path_prefix": _text(value.get("target_path_prefix")),
        "profile_mode": _text(value.get("profile_mode")),
        "mcp_server_identity_hash": _text(value.get("mcp_server_identity_hash")),
        "mcp_tool_identity_hash": _text(value.get("mcp_tool_identity_hash")),
        "mcp_schema_hash": _text(value.get("mcp_schema_hash")),
        "sensitive_surface_flags": [str(flag) for flag in flags] if isinstance(flags, (list, tuple)) else None,
    }


def _config_path(value: object) -> str | None:
    return str(Path(value).expanduser()) if isinstance(value, str) and value else None


def build_plan_request(
    request: Mapping[str, object],
    *,
    action: str,
    scope: str,
    persist_policy: bool | None,
    temporary_mcp: bool,
    local_tool: bool,
    resolve_scope_matches: bool,
    requires_local_once: bool,
    resolved_workspace: str | None,
    native_exact_token: str | None,
    resolved_at: str,
    request_id: str = "",
) -> dict[str, object]:
    """Narrow a stored approval request and the resolution inputs to the wire form."""

    harness = request.get("harness")
    return {
        "schema": _REQUEST_SCHEMA,
        "request_id": request_id,
        "action": action,
        "scope": scope,
        "persist_policy": persist_policy,
        "temporary_mcp": temporary_mcp,
        "local_tool": local_tool,
        "resolve_scope_matches": resolve_scope_matches,
        "requires_local_once": requires_local_once,
        "resolved_workspace": resolved_workspace,
        "native_exact_token": native_exact_token,
        "resolved_at": resolved_at,
        "approval": {
            "harness": str(harness) if harness is not None else None,
            "artifact_id": _text(request.get("artifact_id")),
            "artifact_hash": _text(request.get("artifact_hash")),
            "artifact_type": _text(request.get("artifact_type")),
            "publisher": _text(request.get("publisher")),
            "config_path": _config_path(request.get("config_path")),
            "source_scope": _text(request.get("source_scope")),
            "raw_command_text": _text(request.get("raw_command_text")),
            "wrapper_chain": _chain(request.get("wrapper_chain")),
            "envelope": _envelope(request.get("action_envelope_json")),
            "browser_intent": _browser_intent(request.get("browser_intent")),
        },
    }


def native_approval_resolution_plan(
    request: Mapping[str, object],
    *,
    guard_home: Path,
    action: str,
    scope: str,
    persist_policy: bool | None,
    temporary_mcp: bool,
    local_tool: bool,
    resolve_scope_matches: bool,
    requires_local_once: bool,
    resolved_workspace: str | None,
    native_exact_token: str | None,
    resolved_at: str,
) -> dict[str, object]:
    """Plan one approval resolution in the resident; raise when it cannot."""

    wire = build_plan_request(
        request,
        action=action,
        scope=scope,
        persist_policy=persist_policy,
        temporary_mcp=temporary_mcp,
        local_tool=local_tool,
        resolve_scope_matches=resolve_scope_matches,
        requires_local_once=requires_local_once,
        resolved_workspace=resolved_workspace,
        native_exact_token=native_exact_token,
        resolved_at=resolved_at,
        request_id=f"approval-resolution-plan-{uuid4().hex}",
    )
    try:
        response = _resident_request(
            operation="approval_resolution_plan",
            request=wire,
            guard_home=guard_home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=APPROVAL_RESOLUTION_PLAN_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError):
        raise ApprovalResolutionPlanUnavailableError from None
    payload = _payload(response, wire, Path(guard_home))
    if payload is None or payload.get("persistence") not in _PERSISTENCE_MODES:
        raise ApprovalResolutionPlanUnavailableError
    decision = payload.get("decision")
    if not isinstance(decision, dict) or not isinstance(decision.get("harness"), str):
        raise ApprovalResolutionPlanUnavailableError
    return payload
