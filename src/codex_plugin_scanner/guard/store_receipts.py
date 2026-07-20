"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from .action_lattice import most_restrictive_guard_action
from .decision_boundaries import (
    CanonicalLinkedApprovalAuthority,
    canonical_linked_approval_authority,
    canonical_receipt_decision,
)
from .runtime.decisions import AUTHORITATIVE_DECISION_INCONSISTENT

# ruff: noqa: F403,F405
from .store_base import *
from .store_receipt_rollups import canonical_receipt_rollup_action, reconcile_dirty_receipt_rollups


def _linked_approval_authority_from_row(row: sqlite3.Row) -> CanonicalLinkedApprovalAuthority:
    return canonical_linked_approval_authority(
        approval_request_id=row["approval_request_id"],
        linked_request_id=row["linked_approval_request_id"],
        status=row["approval_status"],
        resolution_action=row["approval_resolution_action"],
        resolved_at=row["approval_resolved_at"],
        policy_action=row["approval_policy_action"],
        decision_v2_json=row["approval_decision_v2_json"],
        action_envelope_json=row["approval_envelope_json"],
    )


def _update_pending_receipt_event_policy_decision(
    connection: sqlite3.Connection,
    *,
    receipt_id: str,
    policy_decision: str,
) -> None:
    row = connection.execute(
        """
        select payload_json, uploaded_at
        from guard_cloud_events
        where idempotency_key = ?
        """,
        (f"receipt.created:{receipt_id}",),
    ).fetchone()
    if row is None or row["uploaded_at"] is not None:
        raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)
    event = _json_object(row["payload_json"])
    event_payload = event.get("payload") if event is not None else None
    if event is None or not isinstance(event_payload, dict):
        raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)
    event_payload["policyDecision"] = policy_decision
    event["payload"] = event_payload
    connection.execute(
        """
        update guard_cloud_events
        set payload_json = ?
        where idempotency_key = ? and uploaded_at is null
        """,
        (json.dumps(event, sort_keys=True), f"receipt.created:{receipt_id}"),
    )


class StoreReceiptsRuntimeMixin:
    def add_receipt(
        self,
        receipt: GuardReceipt,
        *,
        action_envelope: GuardActionEnvelope | None = None,
    ) -> None:
        canonical_decision = canonical_receipt_decision(
            receipt.policy_decision,
            action_envelope.to_dict() if action_envelope is not None else None,
            reject_contradiction=True,
        )
        redacted_action_envelope: dict[str, object] | None = None
        if action_envelope is not None:
            from .receipts.manager import _redacted_envelope_dict

            redacted_action_envelope = _redacted_envelope_dict(action_envelope)
        with self._connect() as connection:
            approval_row: sqlite3.Row | None = None
            if receipt.approval_request_id is not None:
                approval_row = connection.execute(
                    """
                    select request_id as linked_approval_request_id,
                           status as approval_status,
                           resolution_action as approval_resolution_action,
                           resolved_at as approval_resolved_at,
                           policy_action as approval_policy_action,
                           decision_v2_json as approval_decision_v2_json,
                           action_envelope_json as approval_envelope_json
                    from approval_requests
                    where request_id = ?
                    """,
                    (receipt.approval_request_id,),
                ).fetchone()
            final_policy_decision = canonical_receipt_rollup_action(
                policy_decision=canonical_decision.policy_decision,
                envelope_full_json=canonical_decision.action_envelope_json,
                envelope_redacted_json=redacted_action_envelope,
                approval_request_id=receipt.approval_request_id,
                linked_approval_request_id=(
                    approval_row["linked_approval_request_id"] if approval_row is not None else None
                ),
                approval_status=approval_row["approval_status"] if approval_row is not None else None,
                approval_resolution_action=(
                    approval_row["approval_resolution_action"] if approval_row is not None else None
                ),
                approval_resolved_at=(approval_row["approval_resolved_at"] if approval_row is not None else None),
                approval_policy_action=(approval_row["approval_policy_action"] if approval_row is not None else None),
                approval_decision_v2_json=(
                    approval_row["approval_decision_v2_json"] if approval_row is not None else None
                ),
                approval_envelope_json=(approval_row["approval_envelope_json"] if approval_row is not None else None),
            )
            final_full_envelope = canonical_receipt_decision(
                final_policy_decision,
                canonical_decision.action_envelope_json,
                reject_contradiction=False,
            ).action_envelope_json
            final_redacted_envelope = canonical_receipt_decision(
                final_policy_decision,
                redacted_action_envelope,
                reject_contradiction=False,
            ).action_envelope_json
            canonical_receipt = replace(
                receipt,
                policy_decision=final_policy_decision,
            )
            connection.execute(
                """
                insert into runtime_receipts (
                  receipt_id, harness, artifact_id, artifact_hash, policy_decision, capabilities_summary,
                  changed_capabilities_json,
                  provenance_summary, user_override, artifact_name, source_scope, scanner_evidence_json,
                  diff_summary, approval_source, approval_request_id, timestamp, raw_command_text
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    canonical_receipt.receipt_id,
                    canonical_receipt.harness,
                    canonical_receipt.artifact_id,
                    canonical_receipt.artifact_hash,
                    canonical_receipt.policy_decision,
                    canonical_receipt.capabilities_summary,
                    json.dumps(list(canonical_receipt.changed_capabilities)),
                    canonical_receipt.provenance_summary,
                    canonical_receipt.user_override,
                    canonical_receipt.artifact_name,
                    canonical_receipt.source_scope,
                    json.dumps(list(canonical_receipt.scanner_evidence), sort_keys=True),
                    canonical_receipt.diff_summary,
                    canonical_receipt.approval_source,
                    canonical_receipt.approval_request_id,
                    canonical_receipt.timestamp,
                    canonical_receipt.raw_command_text,
                ),
            )
            if action_envelope is not None:
                connection.execute(
                    """
                    insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
                    values (?, ?, ?)
                    """,
                    (
                        receipt.receipt_id,
                        json.dumps(final_full_envelope, sort_keys=True),
                        json.dumps(final_redacted_envelope, sort_keys=True),
                    ),
                )
            self._ensure_local_device(connection)
            row = connection.execute(
                "select installation_id from guard_devices where device_key = ?",
                (_DEVICE_ROW_KEY,),
            ).fetchone()
            device_id = str(row["installation_id"]) if row is not None else None
            workspace_id = self._cloud_workspace_id_from_connection(connection)
            self._add_guard_event_v1(
                connection,
                build_receipt_event(
                    canonical_receipt,
                    device_id=device_id,
                    workspace_id=workspace_id,
                ),
            )
            record_receipt_insert(connection, canonical_receipt)

    def set_receipt_action_envelope(self, receipt_id: str, action_envelope: dict[str, object]) -> None:
        from .receipts.manager import _redacted_envelope_dict

        with self._connect() as connection:
            row = connection.execute(
                "select policy_decision from runtime_receipts where receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if row is None:
                return
            canonical_decision = canonical_receipt_decision(
                row["policy_decision"],
                action_envelope,
                reject_contradiction=True,
            )
            redacted_decision = canonical_receipt_decision(
                canonical_decision.policy_decision,
                _redacted_envelope_dict(canonical_decision.action_envelope_json or {}),
                reject_contradiction=True,
            )
            connection.execute(
                """
                insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
                values (?, ?, ?)
                on conflict(receipt_id) do update set
                  envelope_full_json = excluded.envelope_full_json,
                  envelope_redacted_json = excluded.envelope_redacted_json
                """,
                (
                    receipt_id,
                    json.dumps(canonical_decision.action_envelope_json, sort_keys=True),
                    json.dumps(redacted_decision.action_envelope_json, sort_keys=True),
                ),
            )

    def update_receipt_policy_decision(self, receipt_id: str, policy_decision: str) -> None:
        with self._connect() as connection:
            if not connection.in_transaction:
                connection.execute("begin immediate")
            row = connection.execute(
                """
                select r.harness, r.artifact_id, r.artifact_name, r.policy_decision, r.timestamp,
                       r.approval_request_id,
                       e.envelope_full_json, e.envelope_redacted_json,
                       a.request_id as linked_approval_request_id,
                       a.status as approval_status,
                       a.resolution_action as approval_resolution_action,
                       a.resolved_at as approval_resolved_at,
                       a.policy_action as approval_policy_action,
                       a.decision_v2_json as approval_decision_v2_json,
                       a.action_envelope_json as approval_envelope_json
                from runtime_receipts r
                left join runtime_receipt_envelopes e on e.receipt_id = r.receipt_id
                left join approval_requests a on a.request_id = r.approval_request_id
                where r.receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()
            if row is None:
                return
            old_policy_decision = str(row["policy_decision"])
            full_envelope = _json_object(row["envelope_full_json"])
            redacted_envelope = _json_object(row["envelope_redacted_json"])
            if (row["envelope_full_json"] is not None and full_envelope is None) or (
                row["envelope_redacted_json"] is not None and redacted_envelope is None
            ):
                raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)
            requested_decision = canonical_receipt_decision(
                policy_decision,
                None,
                reject_contradiction=False,
            )
            full_decision = canonical_receipt_decision(
                requested_decision.policy_decision,
                full_envelope,
                reject_contradiction=False,
            )
            redacted_decision = canonical_receipt_decision(
                requested_decision.policy_decision,
                redacted_envelope,
                reject_contradiction=False,
            )
            approval_authority = _linked_approval_authority_from_row(row)
            authority_actions: list[object] = [
                requested_decision.policy_decision,
                full_decision.policy_decision,
                redacted_decision.policy_decision,
            ]
            if approval_authority.policy_action is not None:
                authority_actions.append(approval_authority.policy_action)
            final_policy_decision = most_restrictive_guard_action(
                *authority_actions,
                unknown_action="require-reapproval",
            )
            final_full_envelope = canonical_receipt_decision(
                final_policy_decision,
                full_decision.action_envelope_json,
                reject_contradiction=False,
            ).action_envelope_json
            final_redacted_envelope = canonical_receipt_decision(
                final_policy_decision,
                redacted_decision.action_envelope_json,
                reject_contradiction=False,
            ).action_envelope_json
            connection.execute(
                "update runtime_receipts set policy_decision = ? where receipt_id = ?",
                (final_policy_decision, receipt_id),
            )
            if row["envelope_full_json"] is not None or row["envelope_redacted_json"] is not None:
                connection.execute(
                    """
                    update runtime_receipt_envelopes
                    set envelope_full_json = ?, envelope_redacted_json = ?
                    where receipt_id = ?
                    """,
                    (
                        json.dumps(final_full_envelope, sort_keys=True) if final_full_envelope is not None else None,
                        (
                            json.dumps(final_redacted_envelope, sort_keys=True)
                            if final_redacted_envelope is not None
                            else None
                        ),
                        receipt_id,
                    ),
                )
            if final_policy_decision != old_policy_decision:
                _update_pending_receipt_event_policy_decision(
                    connection,
                    receipt_id=receipt_id,
                    policy_decision=final_policy_decision,
                )
            record_receipt_policy_decision_change(
                connection,
                receipt_id=receipt_id,
                harness=str(row["harness"]),
                artifact_name=row["artifact_name"],
                artifact_id=str(row["artifact_id"]),
                timestamp=str(row["timestamp"]),
                old_policy_decision=old_policy_decision,
                new_policy_decision=final_policy_decision,
            )

    def update_receipt_approval_context(
        self,
        receipt_id: str,
        *,
        approval_source: str | None,
        approval_request_id: str | None,
    ) -> None:
        with self._connect() as connection:
            if not connection.in_transaction:
                connection.execute("begin immediate")
            row = connection.execute(
                """
                select r.policy_decision, r.approval_request_id,
                       e.envelope_full_json, e.envelope_redacted_json,
                       a.request_id as linked_approval_request_id,
                       a.status as approval_status,
                       a.resolution_action as approval_resolution_action,
                       a.resolved_at as approval_resolved_at,
                       a.policy_action as approval_policy_action,
                       a.decision_v2_json as approval_decision_v2_json,
                       a.action_envelope_json as approval_envelope_json
                from runtime_receipts r
                left join runtime_receipt_envelopes e on e.receipt_id = r.receipt_id
                left join approval_requests a on a.request_id = r.approval_request_id
                where r.receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()
            if row is None:
                return
            current_action = canonical_receipt_rollup_action(
                policy_decision=row["policy_decision"],
                envelope_full_json=row["envelope_full_json"],
                envelope_redacted_json=row["envelope_redacted_json"],
                approval_request_id=row["approval_request_id"],
                linked_approval_request_id=row["linked_approval_request_id"],
                approval_status=row["approval_status"],
                approval_resolution_action=row["approval_resolution_action"],
                approval_resolved_at=row["approval_resolved_at"],
                approval_policy_action=row["approval_policy_action"],
                approval_decision_v2_json=row["approval_decision_v2_json"],
                approval_envelope_json=row["approval_envelope_json"],
            )
            next_approval_row: sqlite3.Row | None = None
            if approval_request_id == row["approval_request_id"]:
                next_approval_row = row
            elif approval_request_id is not None:
                next_approval_row = connection.execute(
                    """
                    select request_id as linked_approval_request_id,
                           status as approval_status,
                           resolution_action as approval_resolution_action,
                           resolved_at as approval_resolved_at,
                           policy_action as approval_policy_action,
                           decision_v2_json as approval_decision_v2_json,
                           action_envelope_json as approval_envelope_json
                    from approval_requests
                    where request_id = ?
                    """,
                    (approval_request_id,),
                ).fetchone()
            next_action = canonical_receipt_rollup_action(
                policy_decision=row["policy_decision"],
                envelope_full_json=row["envelope_full_json"],
                envelope_redacted_json=row["envelope_redacted_json"],
                approval_request_id=approval_request_id,
                linked_approval_request_id=(
                    next_approval_row["linked_approval_request_id"] if next_approval_row is not None else None
                ),
                approval_status=(next_approval_row["approval_status"] if next_approval_row is not None else None),
                approval_resolution_action=(
                    next_approval_row["approval_resolution_action"] if next_approval_row is not None else None
                ),
                approval_resolved_at=(
                    next_approval_row["approval_resolved_at"] if next_approval_row is not None else None
                ),
                approval_policy_action=(
                    next_approval_row["approval_policy_action"] if next_approval_row is not None else None
                ),
                approval_decision_v2_json=(
                    next_approval_row["approval_decision_v2_json"] if next_approval_row is not None else None
                ),
                approval_envelope_json=(
                    next_approval_row["approval_envelope_json"] if next_approval_row is not None else None
                ),
            )
            if next_action != current_action:
                raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)
            connection.execute(
                "update runtime_receipts set approval_source = ?, approval_request_id = ? where receipt_id = ?",
                (approval_source, approval_request_id, receipt_id),
            )

    @staticmethod
    def _receipt_base_query(where_clause: str = "") -> str:
        base = """
            select
              r.rowid as receipt_rowid,
              r.receipt_id,
              r.harness,
              r.artifact_id,
              r.artifact_hash,
              r.policy_decision,
              r.capabilities_summary,
              r.changed_capabilities_json,
              r.provenance_summary,
              r.user_override,
              r.artifact_name,
              r.source_scope,
              r.scanner_evidence_json,
              r.diff_summary,
              r.approval_source,
              r.approval_request_id,
              r.timestamp,
              r.raw_command_text,
              e.envelope_full_json as envelope_full_json,
              e.envelope_redacted_json as envelope_redacted_json,
              a.request_id as linked_approval_request_id,
              a.status as approval_status,
              a.resolution_action as approval_resolution_action,
              a.resolved_at as approval_resolved_at,
              a.policy_action as approval_policy_action,
              a.decision_v2_json as approval_decision_v2_json,
              a.action_envelope_json as approval_envelope_json
            from runtime_receipts r
            left join runtime_receipt_envelopes e on e.receipt_id = r.receipt_id
            left join approval_requests a on a.request_id = r.approval_request_id
            left join receipt_rollup_actions s on s.receipt_id = r.receipt_id
        """
        return f"{base} {where_clause}".strip()

    @staticmethod
    def _receipt_dict_from_row(row: sqlite3.Row, *, include_rowid: bool = True) -> dict[str, object]:
        raw_full_envelope = row["envelope_full_json"]
        full_envelope = _json_object(raw_full_envelope)
        raw_redacted_envelope = row["envelope_redacted_json"]
        redacted_envelope = _json_object(raw_redacted_envelope)
        stored_decision = canonical_receipt_decision(
            row["policy_decision"],
            None,
            reject_contradiction=False,
        )
        full_check = canonical_receipt_decision(
            stored_decision.policy_decision,
            full_envelope if full_envelope is not None else raw_full_envelope,
            reject_contradiction=False,
        )
        redacted_check = canonical_receipt_decision(
            stored_decision.policy_decision,
            redacted_envelope if redacted_envelope is not None else raw_redacted_envelope,
            reject_contradiction=False,
        )
        approval_authority = _linked_approval_authority_from_row(row)
        authority_actions: list[object] = [
            stored_decision.policy_decision,
            full_check.policy_decision,
            redacted_check.policy_decision,
        ]
        if approval_authority.policy_action is not None:
            authority_actions.append(approval_authority.policy_action)
        final_policy_decision = most_restrictive_guard_action(
            *authority_actions,
            unknown_action="require-reapproval",
        )
        output_envelope = full_check.action_envelope_json
        if output_envelope is None:
            output_envelope = approval_authority.action_envelope_json
        envelope = canonical_receipt_decision(
            final_policy_decision,
            output_envelope,
            reject_contradiction=False,
        ).action_envelope_json
        redacted_envelope = canonical_receipt_decision(
            final_policy_decision,
            redacted_check.action_envelope_json,
            reject_contradiction=False,
        ).action_envelope_json
        result: dict[str, object] = {}
        if include_rowid:
            result["receipt_rowid"] = int(row["receipt_rowid"])
        result.update(
            {
                "receipt_id": str(row["receipt_id"]),
                "harness": str(row["harness"]),
                "artifact_id": str(row["artifact_id"]),
                "artifact_hash": str(row["artifact_hash"]),
                "policy_decision": final_policy_decision,
                "capabilities_summary": str(row["capabilities_summary"]),
                "changed_capabilities": json.loads(str(row["changed_capabilities_json"])),
                "provenance_summary": str(row["provenance_summary"]),
                "user_override": row["user_override"],
                "artifact_name": row["artifact_name"],
                "source_scope": row["source_scope"],
                "scanner_evidence": _json_object_list(row["scanner_evidence_json"]),
                "diff_summary": row["diff_summary"],
                "approval_source": row["approval_source"],
                "approval_request_id": row["approval_request_id"],
                "timestamp": str(row["timestamp"]),
                "raw_command_text": row["raw_command_text"],
                "action_envelope_json": envelope,
                "envelope_redacted_json": redacted_envelope,
            }
        )
        contract_error = (
            stored_decision.contract_error
            or full_check.contract_error
            or redacted_check.contract_error
            or approval_authority.contract_error
        )
        if contract_error is not None:
            result["decision_contract_error"] = contract_error
        return result

    def list_receipts(self, limit: int = 50, harness: str | None = None) -> list[dict[str, object]]:
        if harness is not None:
            query = self._receipt_base_query("where r.harness = ? order by r.timestamp desc limit ?")
            params: tuple[object, ...] = (harness, limit)
        else:
            query = self._receipt_base_query("order by r.timestamp desc limit ?")
            params = (limit,)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._receipt_dict_from_row(row) for row in rows]

    def list_receipts_since_rowid(
        self,
        *,
        after_rowid: int | None,
        limit: int = 200,
        harness: str | None = None,
    ) -> list[dict[str, object]]:
        if harness is not None:
            query = self._receipt_base_query("where r.rowid > ? and r.harness = ? order by r.rowid asc limit ?")
            params: tuple[object, ...] = (
                after_rowid if after_rowid is not None else 0,
                harness,
                limit,
            )
        else:
            query = self._receipt_base_query("where r.rowid > ? order by r.rowid asc limit ?")
            params = (after_rowid if after_rowid is not None else 0, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._receipt_dict_from_row(row) for row in rows]

    def list_receipts_for_command_detail_backfill(
        self,
        *,
        limit: int = 2000,
        days: int = 7,
        before_rowid: int | None = None,
    ) -> list[dict[str, object]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(days, 1))).isoformat()
        rowid_clause = "and r.rowid < ?" if before_rowid is not None else ""
        query = self._receipt_base_query(
            f"""
            where r.timestamp >= ?
              and s.policy_decision in ('block', 'review', 'require-reapproval', 'sandbox-required')
              and (e.envelope_full_json is not null or a.action_envelope_json is not null)
              {rowid_clause}
            order by r.rowid desc
            limit ?
            """
        )
        with self._connect() as connection:
            if receipt_rollups_need_backfill(connection):
                backfill_receipt_rollups(connection)
            else:
                reconcile_dirty_receipt_rollups(connection)
            params: tuple[object, ...] = (
                (cutoff, before_rowid, max(limit, 1)) if before_rowid is not None else (cutoff, max(limit, 1))
            )
            rows = connection.execute(query, params).fetchall()
        return [self._receipt_dict_from_row(row) for row in rows]

    def latest_receipt_rowid(self, *, harness: str | None = None) -> int | None:
        query = "select max(rowid) as max_rowid from runtime_receipts"
        params: tuple[object, ...] = ()
        if harness is not None:
            query += " where harness = ?"
            params = (harness,)
        with self._connect() as connection:
            row = connection.execute(query, params).fetchone()
        if row is None:
            return None
        max_rowid = row["max_rowid"]
        if isinstance(max_rowid, int):
            return max_rowid
        if isinstance(max_rowid, str) and max_rowid.isdigit():
            return int(max_rowid)
        return None

    def get_receipt(self, receipt_id: str) -> dict[str, object] | None:
        query = self._receipt_base_query("where r.receipt_id = ?")
        with self._connect() as connection:
            row = connection.execute(query, (receipt_id,)).fetchone()
        if row is None:
            return None
        return self._receipt_dict_from_row(row, include_rowid=False)

    def get_receipt_for_approval_request(
        self,
        request_id: str,
        *,
        policy_decision: str,
    ) -> dict[str, object] | None:
        query = self._receipt_base_query(
            "where r.approval_request_id = ? and r.policy_decision = ? order by r.rowid asc limit 1"
        )
        with self._connect() as connection:
            row = connection.execute(query, (request_id, policy_decision)).fetchone()
        if row is None:
            return None
        return self._receipt_dict_from_row(row, include_rowid=False)

    def get_latest_receipt(self, harness: str, artifact_id: str) -> dict[str, object] | None:
        query = self._receipt_base_query("where r.harness = ? and r.artifact_id = ? order by r.timestamp desc limit 1")
        with self._connect() as connection:
            row = connection.execute(query, (harness, artifact_id)).fetchone()
        if row is None:
            return None
        return self._receipt_dict_from_row(row, include_rowid=False)

    def count_receipts(self, harness: str | None = None) -> int:
        with self._connect() as connection:
            rollup_total = count_receipts_from_rollups(connection, harness=harness)
            if rollup_total is not None:
                return rollup_total
            query = "select count(*) as total from runtime_receipts"
            params: tuple[object, ...] = ()
            if harness is not None:
                query += " where harness = ?"
                params = (harness,)
            row = connection.execute(query, params).fetchone()
        return int(row["total"]) if row is not None else 0

    def receipt_analytics(
        self,
        *,
        activity_days: int = 90,
        trend_days: int = 7,
        top_limit: int = 10,
    ) -> dict[str, object]:
        """Aggregate receipt metrics from incremental rollups."""
        activity_days = max(1, min(activity_days, 366))
        trend_days = max(1, min(trend_days, activity_days))
        top_limit = max(1, min(top_limit, 50))

        with self._connect() as connection:
            if receipt_rollups_need_backfill(connection):
                backfill_receipt_rollups(connection)
            else:
                reconcile_dirty_receipt_rollups(connection)
            return load_receipt_analytics(
                connection,
                activity_days=activity_days,
                trend_days=trend_days,
                top_limit=top_limit,
            )

    def receipt_decision_counts(self, harness: str, artifact_id: str) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select
                  r.policy_decision,
                  e.envelope_full_json,
                  e.envelope_redacted_json,
                  r.approval_request_id,
                  a.request_id as linked_approval_request_id,
                  a.status as approval_status,
                  a.resolution_action as approval_resolution_action,
                  a.resolved_at as approval_resolved_at,
                  a.policy_action as approval_policy_action,
                  a.decision_v2_json as approval_decision_v2_json,
                  a.action_envelope_json as approval_envelope_json
                from runtime_receipts r
                left join runtime_receipt_envelopes e on e.receipt_id = r.receipt_id
                left join approval_requests a on a.request_id = r.approval_request_id
                where r.harness = ? and r.artifact_id = ?
                """,
                (harness, artifact_id),
            ).fetchall()
        counts: dict[str, int] = {}
        for row in rows:
            policy_decision = canonical_receipt_rollup_action(
                policy_decision=row["policy_decision"],
                envelope_full_json=row["envelope_full_json"],
                envelope_redacted_json=row["envelope_redacted_json"],
                approval_request_id=row["approval_request_id"],
                linked_approval_request_id=row["linked_approval_request_id"],
                approval_status=row["approval_status"],
                approval_resolution_action=row["approval_resolution_action"],
                approval_resolved_at=row["approval_resolved_at"],
                approval_policy_action=row["approval_policy_action"],
                approval_decision_v2_json=row["approval_decision_v2_json"],
                approval_envelope_json=row["approval_envelope_json"],
            )
            counts[policy_decision] = counts.get(policy_decision, 0) + 1
        return counts

    def upsert_runtime_state(
        self,
        *,
        session_id: str,
        daemon_host: str,
        daemon_port: int,
        started_at: str,
        last_heartbeat_at: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_runtime_state (
                  state_key, session_id, daemon_host, daemon_port, started_at, last_heartbeat_at
                )
                values ('runtime', ?, ?, ?, ?, ?)
                on conflict(state_key) do update set
                  session_id = excluded.session_id,
                  daemon_host = excluded.daemon_host,
                  daemon_port = excluded.daemon_port,
                  started_at = excluded.started_at,
                  last_heartbeat_at = excluded.last_heartbeat_at
                """,
                (session_id, daemon_host, daemon_port, started_at, last_heartbeat_at),
            )

    def touch_runtime_state(self, *, session_id: str, last_heartbeat_at: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                update guard_runtime_state
                set last_heartbeat_at = ?
                where state_key = 'runtime'
                  and session_id = ?
                """,
                (last_heartbeat_at, session_id),
            )

    def get_runtime_state(self) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select session_id, daemon_host, daemon_port, started_at, last_heartbeat_at
                from guard_runtime_state
                where state_key = 'runtime'
                """
            ).fetchone()
        if row is None:
            return None
        return GuardRuntimeState(
            session_id=str(row["session_id"]),
            daemon_host=str(row["daemon_host"]),
            daemon_port=int(row["daemon_port"]),
            started_at=str(row["started_at"]),
            last_heartbeat_at=str(row["last_heartbeat_at"]),
        ).to_dict()

    def clear_runtime_state(self, *, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                delete from guard_runtime_state
                where state_key = 'runtime'
                  and session_id = ?
                """,
                (session_id,),
            )
