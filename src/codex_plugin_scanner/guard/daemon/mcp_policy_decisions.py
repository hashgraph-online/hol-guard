"""Local dashboard decisions for staged MCP policy imports."""

from __future__ import annotations

from typing import Any, Protocol

from ..approval_gate import ApprovalGateError, require_high_risk
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping


class PolicyDecisionHandler(Protocol):
    server: Any

    def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None: ...

    def _write_approval_gate_error(self, error: ApprovalGateError) -> None: ...


def handle_mcp_policy_decision(handler: PolicyDecisionHandler, request_id: str, payload: dict[str, object]) -> None:
    """Resolve an MCP policy creation request via human approval.

    POST /v1/mcp-policy/requests/<id>/decision
    Body: {"action": "approve" | "decline", ...approval_gate_input}

    On approve: obtains the ApprovalGateGrant via require_high_risk
    (purpose="policy_import"), then calls apply_pending_policy_request
    with the grant.  On decline: calls decline_pending_policy_request.
    """

    from codex_plugin_scanner.guard.mcp.policy_errors import PolicyToolError
    from codex_plugin_scanner.guard.mcp.policy_tools import (
        apply_pending_policy_request,
        decline_pending_policy_request,
        pending_policy_import_approval_binding,
    )

    action = payload.get("action")
    if not isinstance(action, str) or action.strip() not in {"approve", "decline"}:
        handler._write_json(
            {"resolved": False, "error": "missing_required_fields"},
            status=400,
        )
        return
    action = action.strip()
    store = handler.server.store  # type: ignore[attr-defined]
    guard_home = store.guard_home

    if action == "decline":
        try:
            decline_result = decline_pending_policy_request(store, request_id)
        except PolicyToolError as error:
            _write_policy_error(handler, store, request_id, error)
            return
        handler._write_json({"resolved": True, **decline_result})
        return

    # action == "approve" — obtain the grant and apply.
    try:
        approval_gate_grant = require_high_risk(
            guard_home,
            purpose="policy_import",
            **pending_policy_import_approval_binding(store, request_id),
            approval_gate_input=approval_gate_input_from_mapping(payload),
        )
    except ApprovalGateError as error:
        handler._write_approval_gate_error(error)
        return
    except PolicyToolError as error:
        _write_policy_error(handler, store, request_id, error)
        return

    try:
        apply_result = apply_pending_policy_request(
            store,
            request_id,
            approval_gate_grant=approval_gate_grant,
        )
    except ApprovalGateError as error:
        handler._write_approval_gate_error(error)
        return
    except PolicyToolError as error:
        _write_policy_error(handler, store, request_id, error)
        return
    handler._write_json({"resolved": True, **apply_result})


def _write_policy_error(handler: PolicyDecisionHandler, store, request_id: str, error) -> None:
    from ..mcp.policy_store import MCPolicyRequestRepository

    if error.code == "approval_already_resolved":
        current = MCPolicyRequestRepository(store).get_request(request_id)
        if current is not None and current.is_terminal:
            handler._write_json(
                {
                    "resolved": True,
                    "requestId": current.request_id,
                    "status": current.status,
                    "resolvedAt": current.resolved_at,
                }
            )
            return
    handler._write_json({"resolved": False, "error": error.code, "message": error.message}, status=400)
