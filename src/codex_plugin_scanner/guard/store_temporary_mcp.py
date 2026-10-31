"""Atomic persistence for temporary MCP approval grants."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false
# ruff: noqa: F403,F405
from .store_base import *
from .temporary_mcp_approvals import TemporaryMcpGrantSelection


class StoreTemporaryMcpMixin:
    @serialize_policy_integrity_generation
    def apply_temporary_mcp_grant_resolution(
        self,
        *,
        request_id: str,
        decision: PolicyDecision,
        selection: TemporaryMcpGrantSelection,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> tuple[dict[str, object], list[str]]:
        validate_policy_write_authority(decision, remote_write_authorized=False)
        require_policy_write(
            self.guard_home,
            decision=decision,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        _validate_scoped_policy_artifact_target(decision.scope, decision.artifact_id)
        require_request_resolution(
            self.guard_home,
            resolution_action="allow",
            resolution_scope="artifact",
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        fields, integrity = self._policy_write_args(decision, resolved_at)
        # The resident holds the write lock across the grant, the request that
        # asked for it and the requests it covers, so the sweep and the queue
        # answer come back from the same transaction.
        payload = self._native_store_call(
            "apply_temporary_mcp_grant_resolution",
            {
                "request_id": request_id,
                "resolved_at": resolved_at,
                "reason": reason,
                "grant_target": selection.target,
                "grant_server_identity_hash": selection.eligibility.server_identity_hash,
                "grant_category": selection.eligibility.category,
                "decision": fields,
                **integrity,
            },
        )
        if not isinstance(payload, dict):
            raise RuntimeError("Guard temporary MCP grant was not written.")
        blocked = payload.get("blocked")
        if isinstance(blocked, str) and blocked:
            # A request no approval can lift is a caller contract error, not a
            # queue answer, so it is raised rather than returned.
            raise ValueError(blocked)
        self._finalize_native_control_state(payload.get("next_control_state"))
        result = payload.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("Guard temporary MCP grant returned no queue result.")
        covered = payload.get("covered_request_ids")
        covered_ids = [str(item) for item in covered] if isinstance(covered, list) else []
        return result, covered_ids
