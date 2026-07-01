"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from datetime import datetime, timedelta, timezone

# ruff: noqa: F403,F405
from .store_base import *


class StoreReceiptsRuntimeMixin:
    def add_receipt(
        self,
        receipt: GuardReceipt,
        *,
        action_envelope: GuardActionEnvelope | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into runtime_receipts (
                  receipt_id, harness, artifact_id, artifact_hash, policy_decision, capabilities_summary,
                  changed_capabilities_json,
                  provenance_summary, user_override, artifact_name, source_scope, scanner_evidence_json,
                  diff_summary, approval_source, approval_request_id, timestamp
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id,
                    receipt.harness,
                    receipt.artifact_id,
                    receipt.artifact_hash,
                    receipt.policy_decision,
                    receipt.capabilities_summary,
                    json.dumps(list(receipt.changed_capabilities)),
                    receipt.provenance_summary,
                    receipt.user_override,
                    receipt.artifact_name,
                    receipt.source_scope,
                    json.dumps(list(receipt.scanner_evidence), sort_keys=True),
                    receipt.diff_summary,
                    receipt.approval_source,
                    receipt.approval_request_id,
                    receipt.timestamp,
                ),
            )
            if action_envelope is not None:
                from .receipts.manager import _redacted_envelope_dict

                connection.execute(
                    """
                    insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
                    values (?, ?, ?)
                    """,
                    (
                        receipt.receipt_id,
                        json.dumps(action_envelope.to_dict()),
                        json.dumps(_redacted_envelope_dict(action_envelope)),
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
                    receipt,
                    device_id=device_id,
                    workspace_id=workspace_id,
                ),
            )
            record_receipt_insert(connection, receipt)

    def set_receipt_action_envelope(self, receipt_id: str, action_envelope: dict[str, object]) -> None:
        with self._connect() as connection:
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
                    json.dumps(action_envelope, sort_keys=True),
                    json.dumps(action_envelope, sort_keys=True),
                ),
            )

    def update_receipt_policy_decision(self, receipt_id: str, policy_decision: str) -> None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select harness, artifact_id, artifact_name, policy_decision, timestamp
                from runtime_receipts
                where receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()
            if row is None:
                return
            old_policy_decision = str(row["policy_decision"])
            connection.execute(
                "update runtime_receipts set policy_decision = ? where receipt_id = ?",
                (policy_decision, receipt_id),
            )
            record_receipt_policy_decision_change(
                connection,
                harness=str(row["harness"]),
                artifact_name=row["artifact_name"],
                artifact_id=str(row["artifact_id"]),
                timestamp=str(row["timestamp"]),
                old_policy_decision=old_policy_decision,
                new_policy_decision=policy_decision,
            )

    def update_receipt_approval_context(
        self,
        receipt_id: str,
        *,
        approval_source: str | None,
        approval_request_id: str | None,
    ) -> None:
        with self._connect() as connection:
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
              e.envelope_full_json as envelope_full_json,
              e.envelope_redacted_json as envelope_redacted_json,
              a.action_envelope_json as approval_envelope_json
            from runtime_receipts r
            left join runtime_receipt_envelopes e on e.receipt_id = r.receipt_id
            left join approval_requests a on a.request_id = r.approval_request_id
        """
        return f"{base} {where_clause}".strip()

    @staticmethod
    def _receipt_dict_from_row(row: sqlite3.Row, *, include_rowid: bool = True) -> dict[str, object]:
        envelope = _json_object(row["envelope_full_json"]) or _json_object(row["approval_envelope_json"])
        result: dict[str, object] = {}
        if include_rowid:
            result["receipt_rowid"] = int(row["receipt_rowid"])
        result.update(
            {
                "receipt_id": str(row["receipt_id"]),
                "harness": str(row["harness"]),
                "artifact_id": str(row["artifact_id"]),
                "artifact_hash": str(row["artifact_hash"]),
                "policy_decision": str(row["policy_decision"]),
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
                "action_envelope_json": envelope,
                "envelope_redacted_json": _json_object(row["envelope_redacted_json"]),
            }
        )
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
              and r.policy_decision in ('block', 'review', 'require-reapproval', 'sandbox-required')
              and (e.envelope_full_json is not null or a.action_envelope_json is not null)
              {rowid_clause}
            order by r.rowid desc
            limit ?
            """
        )
        with self._connect() as connection:
            params: tuple[object, ...] = (
                (cutoff, before_rowid, max(limit, 1)) if before_rowid is not None else (cutoff, max(limit, 1))
            )
            rows = connection.execute(query, params).fetchall()
        return [self._receipt_dict_from_row(row) for row in reversed(rows)]

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
            if not receipt_rollups_initialized(connection):
                backfill_receipt_rollups(connection)
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
                select policy_decision, count(*) as total
                from runtime_receipts
                where harness = ? and artifact_id = ?
                group by policy_decision
                """,
                (harness, artifact_id),
            ).fetchall()
        counts: dict[str, int] = {}
        for row in rows:
            counts[str(row["policy_decision"])] = int(row["total"])
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
