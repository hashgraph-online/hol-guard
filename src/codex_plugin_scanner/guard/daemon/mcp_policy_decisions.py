"""Local dashboard decisions for staged MCP policy imports."""

from __future__ import annotations

from typing import Any, Protocol

from ..approval_gate import ApprovalGateError, require_high_risk
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..native_policy_snapshot_constants import NativePolicySnapshotError


class PolicyDecisionHandler(Protocol):
    server: Any

    def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None: ...

    def _write_approval_gate_error(self, error: ApprovalGateError) -> None: ...


def handle_mcp_policy_decision(handler: PolicyDecisionHandler, request_id: str, payload: dict[str, object]) -> None:
    """Resolve an MCP policy creation request via human approval.

    POST /v1/mcp-policy/requests/<id>/decision
    Body: {"action": "approve" | "decline" | "recover", ...approval_gate_input}

    On approve: obtains the ApprovalGateGrant via require_high_risk
    (purpose="policy_import"), then calls apply_pending_policy_request
    with the grant.  On decline: calls decline_pending_policy_request.
    Recovery is a separate freshly approved import of the exact saved source;
    it does not resolve or replay the old request.
    """

    from codex_plugin_scanner.guard.mcp.policy_errors import PolicyToolError
    from codex_plugin_scanner.guard.mcp.policy_tools import (
        apply_pending_policy_request,
        decline_pending_policy_request,
        pending_policy_import_approval_binding,
    )

    action = payload.get("action")
    if not isinstance(action, str) or action.strip() not in {"approve", "decline", "recover", "inspect-recovery"}:
        handler._write_json(
            {"resolved": False, "error": "missing_required_fields"},
            status=400,
        )
        return
    action = action.strip()
    store = handler.server.store  # type: ignore[attr-defined]
    guard_home = store.guard_home

    if action in {"recover", "inspect-recovery"}:
        from .business_policy_recovery import handle_business_policy_recovery

        handle_business_policy_recovery(handler, request_id, payload)
        return

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

    except (NativePolicySnapshotError, TimeoutError) as error:
        _write_source_error(handler, error)
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
    except (NativePolicySnapshotError, TimeoutError) as error:
        _write_source_error(handler, error)
        return
    handler._write_json({"resolved": True, **apply_result})


def _write_source_error(handler: PolicyDecisionHandler, error: Exception) -> None:
    # Never copy an arbitrary exception/path into the dashboard response.
    codes = {
        "native_business_source_approval_required",
        "native_business_source_installation_incoherent",
        "native_business_source_current_fence_unavailable",
        "native_business_source_transaction_not_committed",
        "native_business_source_codec_refused",
        "native_business_policy_removal_requires_authority",
        "native_business_source_retention_unavailable",
        "native_business_source_retention_conflict",
        "native_business_source_recovery_required",
        "native_business_source_recovery_identity_mismatch",
        "native_business_source_installation_key_unavailable",
    }
    code = str(error)
    if isinstance(error, TimeoutError):
        code = "policy_authority_busy"
    elif code not in codes:
        code = "native_business_source_unavailable"
    handler._write_json(
        {
            "resolved": False,
            "error": code,
            "message": "Policy source operation failed. Check its installation state before retrying.",
        },
        status=503,
    )


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
