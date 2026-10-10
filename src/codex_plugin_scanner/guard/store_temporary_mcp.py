"""Atomic persistence for temporary MCP approval grants."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false
# ruff: noqa: F403,F405
from .approval_resolution import require_resolvable_approval_request
from .store_approvals import _begin_immediate, _unresolved_queue_result
from .store_base import *
from .temporary_mcp_approvals import TemporaryMcpGrantSelection, temporary_mcp_grant_covers_request


class StoreTemporaryMcpMixin:
    def apply_temporary_mcp_grant_resolution(
        self,
        *,
        request_id: str,
        decisions: list[PolicyDecision],
        selection: TemporaryMcpGrantSelection,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
        commit_resolution: bool = True,
    ) -> tuple[dict[str, object], list[str]]:
        for decision in decisions:
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
        secret_material = self._policy_integrity_secret_material(create=True)
        next_control_state: dict[str, object] | None = None
        covered_ids: list[str] = []
        with self._connect() as connection:
            _begin_immediate(connection)
            source = load_approval_request(connection, request_id)
            if source is None:
                result = _unresolved_queue_result(connection, error="not_found")
            elif source.get("status") != "pending":
                result = _unresolved_queue_result(connection, error="already_resolved", item=source)
            else:
                require_resolvable_approval_request(source)
                if selection.target != "exact":
                    covered_ids = self._covered_pending_request_ids_locked(
                        connection,
                        source=source,
                        request_id=request_id,
                        selection=selection,
                    )
                for decision in decisions:
                    next_control_state = self._upsert_policy_locked(
                        connection,
                        decision=decision,
                        now=resolved_at,
                        secret_material=secret_material,
                    )
                if commit_resolution:
                    result = persist_queue_resolution(
                        connection,
                        request_id,
                        resolution_action="allow",
                        resolution_scope="artifact",
                        reason=reason,
                        resolved_at=resolved_at,
                    )
                    persist_bulk_resolution(
                        connection,
                        covered_ids,
                        resolution_action="allow",
                        resolution_scope="artifact",
                        reason=reason,
                        resolved_at=resolved_at,
                    )
                else:
                    result: dict[str, object] = {"resolved": False, "policy_written": True}
        if next_control_state is not None:
            self._finalize_policy_integrity_control_state(next_control_state)
        return result, covered_ids

    @staticmethod
    def _covered_pending_request_ids_locked(
        connection: sqlite3.Connection,
        *,
        source: dict[str, object],
        request_id: str,
        selection: TemporaryMcpGrantSelection,
    ) -> list[str]:
        covered_ids: list[str] = []
        for item in load_approval_requests(
            connection,
            status="pending",
            harness=str(source["harness"]),
            limit=None,
        ):
            candidate_id = str(item["request_id"])
            if candidate_id == request_id or not temporary_mcp_grant_covers_request(selection, item):
                continue
            try:
                require_resolvable_approval_request(item)
            except ValueError:
                continue
            covered_ids.append(candidate_id)
        return covered_ids
