"""Authenticated framing for native CIGAR administration, never SDK policy."""

from __future__ import annotations

from typing import Any

from ..approval_gate import ApprovalGateError, input_from_mapping, require_high_risk, require_settings_write
from ..native_context_assistance import ContextAssistanceError, versions

READ_PATHS = {
    "/v1/context-assistance/versions": "versions_releases",
    "/v1/context-assistance/jobs": "versions_jobs",
    "/v1/context-assistance/interpreters": "versions_interpreters",
    "/v1/context-assistance/catalog": "versions_catalog",
}
_READ_ACTIONS = {
    "versions_releases": "releases",
    "versions_jobs": "jobs",
    "versions_interpreters": "interpreters",
    "versions_catalog": "catalog",
}
_NO_EXPANSION = {"releases", "interpreters", "jobs", "job", "cancel", "catalog", "preferences"}


def respond(handler: Any, kind: str, payload: dict[str, object]) -> None:
    # Fail closed even if a running route table predates version administration.
    if not handler._header_token_is_valid(payload=payload):
        handler._write_json({"error": "unauthorized"}, status=401)
        return
    if kind in _READ_ACTIONS:
        body: object = {"action": _READ_ACTIONS[kind]}
    elif kind == "versions":
        body = payload.get("input")
    else:
        body = None
    if not isinstance(body, dict) or not isinstance(body.get("action"), str):
        handler._write_json({"error": "invalid_context_input"}, status=400)
        return
    home = handler.server.store.guard_home
    try:
        if body.get("action") not in _NO_EXPANSION:
            grant = require_high_risk(home, purpose="settings_write", approval_gate_input=input_from_mapping(payload))
            require_settings_write(home, approval_gate_grant=grant)
        result = versions(guard_home=home, payload=body)
    except ApprovalGateError as error:
        handler._write_approval_gate_error(error)
        return
    except ContextAssistanceError as error:
        status = 503
        if error.code.endswith(("request_invalid", "idempotency_conflict")):
            status = 400
        elif error.code.endswith(
            (
                "disabled",
                "switch_busy",
                "context_stale",
                "install_busy",
                "cigar_catalog_busy",
                "selection_conflict",
                "recovery_required",
                "acknowledgement_required",
                "update_preferences_conflict",
                "update_preferences_locked",
                "update_pin_conflict",
                "config_write_busy",
            )
        ):
            status = 409
        handler._write_json(
            {"error": "context_assistance_unavailable", "code": error.code},
            status=status,
            extra_headers={"Cache-Control": "no-store"},
        )
        return
    handler._write_json(result, extra_headers={"Cache-Control": "no-store"})


def request_body_limit(path: str, default_bytes: int) -> int:
    """Bound JSON escaping around the 1 MiB signed-catalog transport envelope."""
    return 4 * 1024 * 1024 if path == "/v1/context-assistance/versions" else default_bytes
