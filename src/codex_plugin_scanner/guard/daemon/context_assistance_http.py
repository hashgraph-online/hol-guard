"""HTTP framing for native context assistance; availability stays in Rust."""

from __future__ import annotations

from typing import Any

from ..approval_gate import ApprovalGateError, input_from_mapping, require_high_risk, require_settings_write
from ..native_context_assistance import ContextAssistanceError, control, workspace
from .context_assistance_versions_http import READ_PATHS as VERSION_READ_PATHS
from .context_assistance_versions_http import respond as respond_versions

READ_PATHS = {
    "/v1/context-assistance": "status",
    "/v1/context-assistance/installations": "installations",
    **VERSION_READ_PATHS,
}
WRITE_PATHS = {
    "/v1/context-assistance/versions": "versions",
    "/v1/context-assistance/recheck": "recheck",
    "/v1/context-assistance/activate": "activate",
    "/v1/context-assistance/stop": "stop",
    "/v1/context-assistance/workspace": "workspace",
    "/v1/context-assistance/workspace-access": "workspace_access",
    "/v1/context-assistance/workspace-grant": "workspace_grant",
}
_REFUSAL_STATUS = {
    "native_context_assistance_control_input_invalid": 400,
    "native_context_assistance_workspace_input_invalid": 400,
    "native_context_assistance_request_invalid": 400,
    "native_context_assistance_context_request_invalid": 400,
    "native_context_assistance_context_scope_denied": 403,
    "native_context_assistance_context_stale": 409,
    "native_context_assistance_context_conflict": 409,
    "native_context_assistance_context_resource_limit": 429,
    "native_context_assistance_disabled": 409,
    "native_context_assistance_busy": 409,
    "native_context_assistance_context_busy": 409,
}


def _refusal(handler: Any, error: ContextAssistanceError) -> None:
    # HTTP presentation only. Eligibility and every reason remain native.
    handler._write_json(
        {"error": "context_assistance_unavailable", "code": error.code},
        status=_REFUSAL_STATUS.get(error.code, 503),
        extra_headers={"Cache-Control": "no-store"},
    )


def respond(handler: Any, kind: str, payload: dict[str, object] | None = None) -> None:
    if kind == "versions" or kind.startswith("versions_"):
        respond_versions(handler, kind, payload or {})
        return
    if kind in {"workspace", "workspace_access", "workspace_grant"}:
        _respond_workspace(handler, kind, payload or {})
        return
    try:
        state = control(kind, guard_home=handler.server.store.guard_home, payload=payload)
    except ContextAssistanceError as error:
        _refusal(handler, error)
        return
    handler._write_json(state, extra_headers={"Cache-Control": "no-store"})


def _respond_workspace(handler: Any, kind: str, payload: dict[str, object]) -> None:
    body = payload.get("input")
    if not isinstance(body, dict):
        handler._write_json({"error": "invalid_context_input"}, status=400)
        return
    home = handler.server.store.guard_home
    try:
        if kind == "workspace_grant":
            # Reuse the native approval gate before expanding source access.
            # Proof credentials never enter the SDK/native context envelope.
            grant = require_high_risk(home, purpose="settings_write", approval_gate_input=input_from_mapping(payload))
            require_settings_write(home, approval_gate_grant=grant)
        data = workspace(kind, guard_home=home, payload=body)
    except ApprovalGateError as error:
        handler._write_approval_gate_error(error)
        return
    except ContextAssistanceError as error:
        _refusal(handler, error)
        return
    handler._write_json(data, extra_headers={"Cache-Control": "no-store"})
