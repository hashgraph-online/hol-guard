"""GuardStore domain mixin extracted from store.py."""

from __future__ import annotations

# ruff: noqa: F403,F405
from .store_base import *


class StoreApprovalsMixin:
    def add_approval_request(self, request: GuardApprovalRequest, now: str) -> str:
        with self._connect() as connection:
            return persist_approval_request(connection, request, now)

    def list_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        limit: int | None = 50,
        cursor: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, object]]:
        with self._connect() as connection:
            return load_approval_requests(
                connection,
                status=status,
                harness=harness,
                limit=limit,
                cursor=cursor,
                search=search,
            )

    def list_pending_approval_summaries(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
        harness: str | None = None,
        search: str | None = None,
        include_totals: bool = True,
    ) -> dict[str, object]:
        with self._connect() as connection:
            return load_pending_approval_summaries(
                connection,
                limit=limit,
                cursor=cursor,
                harness=harness,
                search=search,
                include_totals=include_totals,
            )

    def list_approval_request_page(
        self,
        *,
        status: str | None = "pending",
        limit: int = 50,
        cursor: str | None = None,
        harness: str | None = None,
        search: str | None = None,
        include_totals: bool = True,
    ) -> dict[str, object]:
        with self._connect() as connection:
            return load_approval_request_page(
                connection,
                status=status,
                limit=limit,
                cursor=cursor,
                harness=harness,
                search=search,
                include_totals=include_totals,
            )

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_approval_request(connection, request_id)

    def approval_desktop_notified_at(self, request_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select desktop_notified_at
                from approval_requests
                where request_id = ?
                """,
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        value = row["desktop_notified_at"]
        return str(value) if isinstance(value, str) and value else None

    def mark_approval_desktop_notified(self, request_id: str, notified_at: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                update approval_requests
                set desktop_notified_at = ?
                where request_id = ?
                  and desktop_notified_at is null
                """,
                (notified_at, request_id),
            )

    def get_next_pending_request(self, *, exclude_ids: set[str] | None = None) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_next_pending_request(connection, exclude_ids=exclude_ids)

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
                select request_id
                from approval_requests
                where {where_clause}
                order by last_seen_at desc, request_id desc
                limit ?
                """,
                (*params, _MAX_RESOLVED_SCOPE_IDS),
            ).fetchall()
            connection.execute(
                f"""
                update approval_requests
                set status = 'resolved',
                    resolution_action = ?,
                    resolution_scope = ?,
                    reason = ?,
                    resolved_at = ?
                where {where_clause}
                """,
                (resolution_action, resolution_scope, reason, resolved_at, *params),
            )
        return [str(row["request_id"]) for row in rows]

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
                select request_id, artifact_id, config_path
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
            ]
            for chunk in _chunks(matching_ids, _SQLITE_ID_BATCH_SIZE):
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
                    """,
                    (resolution_action, resolution_scope, reason, resolved_at, *chunk),
                )
        return matching_ids[:_MAX_RESOLVED_SCOPE_IDS]

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

    def count_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        search: str | None = None,
    ) -> int:
        with self._connect() as connection:
            return count_pending_approval_requests(connection, status=status, harness=harness, search=search)

    def count_pending_requests(self, *, harness: str | None = None, search: str | None = None) -> int:
        return self.count_approval_requests(status="pending", harness=harness, search=search)

    def clear_approval_requests(self, *, harness: str | None = None, status: str | None = None) -> int:
        conditions: list[str] = []
        params: list[object] = []
        if harness is not None:
            conditions.append("harness = ?")
            params.append(harness)
        if status is not None:
            conditions.append("status = ?")
            params.append(status)
        query = "delete from approval_requests"
        if conditions:
            query += " where " + " and ".join(conditions)
        with self._connect() as connection:
            request_rows = connection.execute(
                f"select request_id from approval_requests{' where ' + ' and '.join(conditions) if conditions else ''}",
                tuple(params),
            ).fetchall()
            request_ids = [str(row["request_id"]) for row in request_rows]
            purge_request_resumes(connection, request_ids)
            cursor = connection.execute(query, tuple(params))
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

    def expire_pending_approval_requests(self, *, older_than: str, now: str) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                update approval_requests
                set status = 'expired',
                    reason = 'Expired after waiting for review.',
                    resolved_at = ?
                where status = 'pending'
                  and created_at < ?
                """,
                (now, older_than),
            )
            return int(cursor.rowcount if cursor.rowcount is not None else 0)
