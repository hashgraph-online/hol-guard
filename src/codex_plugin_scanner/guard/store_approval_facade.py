"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

# ruff: noqa: F403,F405
from .store_base import *


class StoreApprovalsMixin:
    def add_approval_request(self, request: GuardApprovalRequest, now: str) -> str:
        with self._connect() as connection:
            request_id = persist_approval_request(
                connection,
                request,
                now,
                oauth_source=self._guard_source,
            )
            bind_review_events_for_request(
                connection,
                request_id=request_id,
                oauth_source=self._guard_source,
            )
            return request_id

    def resolve_harness_native_approval_request(
        self,
        request_id: str,
        *,
        reason: str | None,
        resolved_at: str,
        expected_harness: str,
        expected_artifact_id: str | None = None,
        expected_artifact_hash: str | None = None,
    ) -> bool:
        """Close an inbox request after a verified harness-native Accept.

        Cursor (and similar) native prompts are the user's approval. Requiring
        the local approval-gate password/MFA a second time left the request
        inbox pending after Accept. This path is artifact-scoped allow-only.
        """

        if not request_id.strip():
            return False
        with self._connect() as connection:
            connection.execute("begin immediate")
            request = load_approval_request(connection, request_id)
            if request is None:
                return False
            if str(request.get("status") or "") != "pending":
                return False
            if str(request.get("harness") or "") != expected_harness:
                return False
            request_artifact_id = str(request.get("artifact_id") or "")
            if expected_artifact_id is not None and request_artifact_id != expected_artifact_id:
                return False
            request_artifact_hash = str(request.get("artifact_hash") or "")
            if expected_artifact_hash is not None and request_artifact_hash != expected_artifact_hash:
                return False
            try:
                require_resolvable_approval_request(request)
            except ValueError:
                return False
            persist_approval_resolution(
                connection,
                request_id,
                resolution_action="allow",
                resolution_scope="artifact",
                reason=reason,
                resolved_at=resolved_at,
            )
        return True

    def resolve_approval_request(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> None:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        with self._connect() as connection:
            connection.execute("begin immediate")
            request = load_approval_request(connection, request_id)
            if request is not None:
                require_resolvable_approval_request(request)
            persist_approval_resolution(
                connection,
                request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def resolve_one_request_only(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> bool:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        with self._connect() as connection:
            connection.execute("begin immediate")
            request = load_approval_request(connection, request_id)
            if request is not None:
                require_resolvable_approval_request(request)
            return persist_one_resolution(
                connection,
                request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def resolve_matching_duplicate_requests(
        self,
        *,
        queue_group_id: str | None,
        request_id: str,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> list[str]:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        with self._connect() as connection:
            return persist_duplicate_resolutions(
                connection,
                queue_group_id=queue_group_id,
                oauth_source=self._guard_source,
                request_id=request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def resolve_request_with_queue_result(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> dict[str, object]:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        with self._connect() as connection:
            return persist_queue_resolution(
                connection,
                request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def resolve_request_with_signed_remote_result(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
    ) -> dict[str, object]:
        with self._connect() as connection:
            request = load_approval_request(connection, request_id)
            if request is not None:
                require_resolvable_approval_request(request)
            return persist_queue_resolution(
                connection,
                request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def resolve_matching_approval_requests(
        self,
        *,
        harness: str | None,
        scope: str,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> list[str]:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        if scope == "workspace":
            if harness is None or workspace is None:
                return []
            return self._resolve_workspace_matching_approval_requests(
                harness=harness,
                artifact_id=artifact_id,
                workspace=workspace,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )
        conditions, params = self._approval_scope_conditions(
            harness=harness,
            scope=scope,
            artifact_id=artifact_id,
            workspace=workspace,
            publisher=publisher,
        )
        if conditions is None:
            return []
        where_clause = " and ".join(["status = 'pending'", *conditions])
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                select request_id, policy_action, decision_v2_json, action_envelope_json
                from approval_requests
                where {where_clause}
                order by last_seen_at desc, request_id desc
                """,
                params,
            ).fetchall()
            matching_ids = [
                str(row["request_id"])
                for row in rows
                if approval_request_surfaces_are_resolvable(
                    row["policy_action"],
                    row["decision_v2_json"],
                    row["action_envelope_json"],
                )
            ]
            self._resolve_approval_request_ids(
                connection,
                matching_ids,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )
        return matching_ids[:_MAX_RESOLVED_SCOPE_IDS]

    @staticmethod
    def _approval_scope_conditions(
        *,
        harness: str | None,
        scope: str,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
    ) -> tuple[list[str] | None, tuple[object, ...]]:
        if scope == "global":
            if _runtime_scoped_exact_match_key(artifact_id) is not None:
                return ["artifact_id = ?"], (artifact_id,)
            return [], ()
        if scope == "harness":
            if harness is None:
                return None, ()
            if _runtime_scoped_exact_match_key(artifact_id) is not None:
                return ["harness = ?", "artifact_id = ?"], (harness, artifact_id)
            family_key = _artifact_family_key(artifact_id)
            if family_key is None:
                return ["harness = ?"], (harness,)
            return ["harness = ?", "artifact_id like ?"], (harness, f"%:{_family_key_value(family_key)}:%")
        if scope == "artifact":
            if harness is None or artifact_id is None:
                return None, ()
            return ["harness = ?", "artifact_id = ?"], (harness, artifact_id)
        if scope == "publisher":
            if harness is None or publisher is None:
                return None, ()
            return ["harness = ?", "publisher = ?"], (harness, publisher)
        if scope == "workspace":
            return None, ()
        return None, ()

    def _resolve_workspace_matching_approval_requests(
        self,
        *,
        harness: str,
        artifact_id: str | None,
        workspace: str,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
    ) -> list[str]:
        with self._connect() as connection:
            connection.execute("begin immediate")
            rows = connection.execute(
                """
                select request_id, artifact_id, config_path, policy_action,
                       decision_v2_json, action_envelope_json
                from approval_requests
                where status = 'pending'
                  and harness = ?
                order by last_seen_at desc, request_id desc
                """,
                (harness,),
            ).fetchall()
            matching_ids = [
                str(row["request_id"])
                for row in rows
                if _path_within_workspace(str(row["config_path"]), workspace)
                and (artifact_id is None or row["artifact_id"] == artifact_id)
                and approval_request_surfaces_are_resolvable(
                    row["policy_action"],
                    row["decision_v2_json"],
                    row["action_envelope_json"],
                )
            ]
            self._resolve_approval_request_ids(
                connection,
                matching_ids,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )
        return matching_ids[:_MAX_RESOLVED_SCOPE_IDS]

    @staticmethod
    def _resolve_approval_request_ids(
        connection: sqlite3.Connection,
        request_ids: list[str],
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
    ) -> None:
        for chunk in _chunks(request_ids, _SQLITE_ID_BATCH_SIZE):
            placeholders = ", ".join("?" for _ in chunk)
            connection.execute(
                f"""
                update approval_requests
                set status = 'resolved',
                    resolution_action = ?,
                    resolution_scope = ?,
                    reason = ?,
                    resolved_at = ?
                where request_id in ({placeholders})
                  and status = 'pending'
                """,
                (resolution_action, resolution_scope, reason, resolved_at, *chunk),
            )

    @staticmethod
    def _matches_scope(
        item: dict[str, object],
        *,
        scope: str,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
    ) -> bool:
        if scope == "global":
            return True
        if scope == "harness":
            return True
        if scope == "artifact":
            return str(item["artifact_id"]) == artifact_id
        if scope == "publisher":
            return isinstance(item.get("publisher"), str) and item.get("publisher") == publisher
        if scope == "workspace" and isinstance(workspace, str):
            config_path = str(item.get("config_path") or "")
            return _path_within_workspace(config_path, workspace)
        return False

    def bulk_resolve_approval_requests(
        self,
        request_ids: list[str],
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> None:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        with self._connect() as connection:
            persist_bulk_resolution(
                connection,
                request_ids,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )
