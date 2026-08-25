"""Store API for append-only Guard Cloud Review event delivery."""

from __future__ import annotations

# pyright: reportAny=false, reportAttributeAccessIssue=false, reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnusedCallResult=false
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone

from .store_review_event_outbox_binding import (
    explicitly_reassign_quarantined_events,
    load_review_oauth_binding,
    normalized_delivery_binding,
    refresh_same_subject_binding,
)
from .store_review_event_outbox_writes import requeue_pending_request_events


def _retry_at(now: str, attempt_count: int) -> str:
    try:
        base = datetime.fromisoformat(now.replace("Z", "+00:00"))
    except ValueError:
        base = datetime.now(timezone.utc)
    delay_seconds = min(300.0, 0.5 * (2 ** min(attempt_count, 10)))
    return (base + timedelta(seconds=delay_seconds)).isoformat()


class StoreReviewEventOutboxMixin:
    def requeue_pending_review_events(self, *, changed_at: str) -> int:
        with self._connect() as connection:
            return requeue_pending_request_events(connection, source=self._guard_source, changed_at=changed_at)

    def requeue_pending_review_events_with_marker(
        self,
        *,
        changed_at: str,
        marker_key: str,
        marker_payload: Mapping[str, object],
    ) -> int:
        with self._connect() as connection:
            count = requeue_pending_request_events(connection, source=self._guard_source, changed_at=changed_at)
            connection.execute(
                """
                insert into sync_state (state_key, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(state_key) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (marker_key, json.dumps({**marker_payload, "requeued": count}), changed_at),
            )
            return count

    def get_review_event_oauth_binding(self) -> dict[str, str] | None:
        with self._connect() as connection:
            binding = load_review_oauth_binding(connection, self._guard_source)
        return dict(binding) if binding is not None else None

    def refresh_review_event_outbox_binding_for_identity(
        self,
        workspace_id: str,
        *,
        oauth_subject_hash: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        """Refresh an established same-subject binding; never adopt unknown identity."""

        supplied = normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        with self._connect() as connection:
            current = load_review_oauth_binding(connection, self._guard_source)
            if current is None:
                return 0
            expected = (
                current["oauth_subject_hash"],
                current["workspace_id"],
                current["machine_id"],
                current["machine_installation_id"],
            )
            if supplied != expected:
                return 0
            return refresh_same_subject_binding(connection, self._guard_source)

    def refresh_review_event_outbox_binding(self) -> int:
        with self._connect() as connection:
            return refresh_same_subject_binding(connection, self._guard_source)

    def reassign_quarantined_review_events(
        self,
        *,
        approved_source: str,
        approved_workspace_id: str,
    ) -> int:
        with self._connect() as connection:
            connection.execute("begin immediate")
            return explicitly_reassign_quarantined_events(
                connection,
                source=self._guard_source,
                approved_source=approved_source,
                approved_workspace_id=approved_workspace_id,
            )

    def list_ready_review_events(
        self,
        *,
        now: str,
        limit: int,
        workspace_id: str | None = None,
        oauth_subject_hash: str | None = None,
        machine_id: str | None = None,
        machine_installation_id: str | None = None,
        newest_first: bool = False,
    ) -> list[dict[str, object]]:
        """List the oldest unacknowledged events; ordering is never lossy."""

        del newest_first
        query = """
            select stream_sequence, event_id, local_request_id, request_sequence,
                   event_type, event_schema_version, payload_json, payload_hash,
                   occurred_at, oauth_source, oauth_subject_hash, workspace_id,
                   machine_id, machine_installation_id, attempt_count
            from guard_review_outbox_events
            where oauth_source = ? and binding_status = 'ready'
              and acknowledged_at is null
              and (next_attempt_at is null or next_attempt_at <= ?)
        """
        parameters: list[object] = [self._guard_source, now]
        identity = (oauth_subject_hash, workspace_id, machine_id, machine_installation_id)
        if any(value is not None for value in identity):
            if not all(isinstance(value, str) for value in identity):
                raise ValueError("complete Review event OAuth binding is required")
            binding = normalized_delivery_binding(
                oauth_subject_hash=str(oauth_subject_hash),
                workspace_id=str(workspace_id),
                machine_id=str(machine_id),
                machine_installation_id=str(machine_installation_id),
            )
            query += """
              and oauth_subject_hash = ? and workspace_id = ?
              and machine_id = ? and machine_installation_id = ?
            """
            parameters.extend(binding)
        query += " order by stream_sequence asc limit ?"
        parameters.append(max(1, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [
            {
                "sequence": int(row["stream_sequence"]),
                "stream_sequence": int(row["stream_sequence"]),
                "event_id": str(row["event_id"]),
                "local_request_id": str(row["local_request_id"]),
                "request_sequence": row["request_sequence"],
                "event_type": str(row["event_type"]),
                "event_schema_version": row["event_schema_version"],
                "payload_json": str(row["payload_json"]),
                "payload_hash": str(row["payload_hash"]),
                "changed_at": str(row["occurred_at"]),
                "oauth_source": str(row["oauth_source"]),
                "oauth_subject_hash": row["oauth_subject_hash"],
                "workspace_id": row["workspace_id"],
                "machine_id": row["machine_id"],
                "machine_installation_id": row["machine_installation_id"],
                "attempt_count": int(row["attempt_count"]),
            }
            for row in rows
        ]

    def acknowledge_review_events(
        self,
        sequences: Sequence[int],
        *,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        """Compact the acknowledged deliverable prefix; retain quarantined evidence."""

        acknowledged = {int(sequence) for sequence in sequences if int(sequence) > 0}
        if not acknowledged:
            return 0
        binding = normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        with self._connect() as connection:
            connection.execute("begin immediate")
            acknowledged_at = datetime.now(timezone.utc).isoformat()
            placeholders = ",".join("?" for _ in acknowledged)
            connection.execute(
                f"""
                update guard_review_outbox_events set acknowledged_at = ?
                where stream_sequence in ({placeholders})
                  and oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
                  and machine_id = ? and machine_installation_id = ?
                  and binding_status = 'ready' and acknowledged_at is null
                """,
                (acknowledged_at, *sorted(acknowledged), self._guard_source, *binding),
            )
            rows = connection.execute(
                """
                select stream_sequence, acknowledged_at from guard_review_outbox_events
                where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
                  and machine_id = ? and machine_installation_id = ?
                  and binding_status = 'ready'
                order by stream_sequence
                """,
                (self._guard_source, *binding),
            ).fetchall()
            prefix: list[int] = []
            for row in rows:
                if row["acknowledged_at"] is None:
                    break
                prefix.append(int(row["stream_sequence"]))
            if not prefix:
                return 0
            placeholders = ",".join("?" for _ in prefix)
            cursor = connection.execute(
                f"""
                delete from guard_review_outbox_events
                where stream_sequence in ({placeholders}) and binding_status = 'ready'
                """,
                prefix,
            )
            highest = prefix[-1]
            connection.execute(
                """
                insert into guard_review_outbox_cursors (
                  oauth_source, oauth_subject_hash, workspace_id, machine_id,
                  machine_installation_id, acknowledged_stream_sequence, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?)
                on conflict(oauth_source, oauth_subject_hash, workspace_id, machine_id, machine_installation_id)
                do update set acknowledged_stream_sequence = max(
                  guard_review_outbox_cursors.acknowledged_stream_sequence,
                  excluded.acknowledged_stream_sequence
                ), updated_at = excluded.updated_at
                """,
                (self._guard_source, *binding, highest, acknowledged_at),
            )
            return max(0, int(cursor.rowcount or 0))

    def retry_review_events(
        self,
        sequences: Sequence[int],
        *,
        now: str,
        error: str,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        normalized = tuple(sorted({int(sequence) for sequence in sequences if int(sequence) > 0}))
        if not normalized:
            return 0
        binding = normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        updated = 0
        with self._connect() as connection:
            for sequence in normalized:
                row = connection.execute(
                    """
                    select attempt_count from guard_review_outbox_events
                    where stream_sequence = ? and oauth_source = ? and oauth_subject_hash = ?
                      and workspace_id = ? and machine_id = ? and machine_installation_id = ?
                      and acknowledged_at is null
                    """,
                    (sequence, self._guard_source, *binding),
                ).fetchone()
                if row is None:
                    continue
                attempts = int(row["attempt_count"]) + 1
                cursor = connection.execute(
                    """
                    update guard_review_outbox_events
                    set attempt_count = ?, next_attempt_at = ?, last_error = ?
                    where stream_sequence = ?
                    """,
                    (attempts, _retry_at(now, attempts), error[:512], sequence),
                )
                updated += max(0, int(cursor.rowcount or 0))
        return updated

    def quarantine_review_event(
        self,
        sequence: int,
        *,
        reason: str,
        error: str,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        """Dead-letter one invalid event without acknowledging or deleting it."""

        binding = normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        with self._connect() as connection:
            cursor = connection.execute(
                """
                update guard_review_outbox_events
                set binding_status = 'quarantined', quarantine_reason = ?, last_error = ?
                where stream_sequence = ? and oauth_source = ? and oauth_subject_hash = ?
                  and workspace_id = ? and machine_id = ? and machine_installation_id = ?
                  and binding_status = 'ready'
                """,
                (reason[:128], error[:512], int(sequence), self._guard_source, *binding),
            )
            return max(0, int(cursor.rowcount or 0))

    def review_event_outbox_status(
        self,
        *,
        now: str,
        workspace_id: str | None = None,
        oauth_subject_hash: str | None = None,
        machine_id: str | None = None,
        machine_installation_id: str | None = None,
    ) -> dict[str, object]:
        query = """
            select count(*) as depth, min(occurred_at) as oldest_changed_at,
                   max(attempt_count) as max_attempt_count, max(last_error) as last_error
            from guard_review_outbox_events where oauth_source = ? and binding_status = 'ready'
              and acknowledged_at is null
        """
        parameters: list[object] = [self._guard_source]
        identity = (oauth_subject_hash, workspace_id, machine_id, machine_installation_id)
        only_workspace = workspace_id is not None and all(
            value is None for value in (oauth_subject_hash, machine_id, machine_installation_id)
        )
        if only_workspace:
            query += " and workspace_id = ?"
            parameters.append(workspace_id)
        elif any(value is not None for value in identity):
            if not all(isinstance(value, str) for value in identity):
                raise ValueError("complete Review event OAuth binding is required")
            binding = normalized_delivery_binding(
                oauth_subject_hash=str(oauth_subject_hash),
                workspace_id=str(workspace_id),
                machine_id=str(machine_id),
                machine_installation_id=str(machine_installation_id),
            )
            query += """
              and oauth_subject_hash = ? and workspace_id = ?
              and machine_id = ? and machine_installation_id = ?
            """
            parameters.extend(binding)
        diagnostics_query = """
            select
              sum(case when binding_status = 'quarantined' then 1 else 0 end) as quarantined_depth,
              sum(case when binding_status = 'quarantined'
                and (oauth_source is null or workspace_id is null) then 1 else 0 end)
                as unbound_depth,
              0 as other_workspace_depth
            from guard_review_outbox_events
        """
        diagnostics_parameters: list[object] = []
        if workspace_id is not None:
            diagnostics_query = """
                select
                  sum(case when binding_status = 'quarantined'
                    and (oauth_source = ? or (oauth_source is null and (workspace_id is null or workspace_id = ?)))
                    then 1 else 0 end) as quarantined_depth,
                  sum(case when binding_status = 'quarantined'
                    and (oauth_source is null or workspace_id is null)
                    and (workspace_id is null or workspace_id = ?) then 1 else 0 end) as unbound_depth,
                  sum(case when binding_status = 'quarantined' and workspace_id is not null
                    and workspace_id != ? and (oauth_source = ? or oauth_source is null)
                    then 1 else 0 end) as other_workspace_depth
                from guard_review_outbox_events
            """
            diagnostics_parameters = [
                self._guard_source,
                workspace_id,
                workspace_id,
                workspace_id,
                self._guard_source,
            ]
        with self._connect() as connection:
            row = connection.execute(query, parameters).fetchone()
            diagnostics = connection.execute(diagnostics_query, diagnostics_parameters).fetchone()
        quarantined = int(diagnostics["quarantined_depth"] or 0) if diagnostics is not None else 0
        unbound = int(diagnostics["unbound_depth"] or 0) if diagnostics is not None else 0
        other_workspace = int(diagnostics["other_workspace_depth"] or 0) if diagnostics is not None else 0
        return {
            "oauth_source": self._guard_source,
            "oauth_subject_hash": oauth_subject_hash,
            "binding_state": "quarantined" if quarantined else "healthy",
            "binding_hint": "Review events require explicit identity repair." if quarantined else None,
            "depth": int(row["depth"] if row is not None else 0),
            "oldest_changed_at": row["oldest_changed_at"] if row is not None else None,
            "max_attempt_count": int(row["max_attempt_count"] or 0) if row is not None else 0,
            "last_error": row["last_error"] if row is not None else None,
            "unbound_depth": unbound,
            "other_workspace_depth": other_workspace,
            "identity_mismatch_depth": max(0, quarantined - unbound),
            "quarantined_depth": quarantined,
            "checked_at": now,
        }
