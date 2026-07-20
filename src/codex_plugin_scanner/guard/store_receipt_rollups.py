"""Incremental receipt rollups for fast analytics and counts.

Rollups use four tables aligned to analytics query shapes (global totals,
daily trend, per-harness, per-artifact top-N). A single composite-key table
would mix key semantics and widen every upsert on receipt insert; separate
tables keep incremental updates O(1) per dimension.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from .action_lattice import is_action_bearing_key, most_restrictive_guard_action, normalize_guard_action
from .decision_boundaries import canonical_linked_approval_authority, canonical_receipt_decision
from .models import GuardAction, GuardReceipt
from .runtime.decisions import AUTHORITATIVE_DECISION_INCONSISTENT

_RECEIPT_TOTALS_KEY = "global"


def receipt_rollup_schema_statements() -> list[str]:
    return [
        """
        create table if not exists receipt_aggregate_totals (
          totals_key text primary key,
          total integer not null default 0,
          allowed integer not null default 0,
          blocked integer not null default 0,
          reviewed integer not null default 0,
          first_activity_at text,
          last_activity_at text
        )
        """,
        """
        create table if not exists receipt_daily_rollups (
          day_key text primary key,
          total integer not null default 0,
          allowed integer not null default 0,
          blocked integer not null default 0,
          reviewed integer not null default 0
        )
        """,
        """
        create table if not exists receipt_harness_rollups (
          harness text primary key,
          total integer not null default 0,
          allowed integer not null default 0,
          blocked integer not null default 0,
          reviewed integer not null default 0
        )
        """,
        """
        create table if not exists receipt_artifact_rollups (
          artifact_key text primary key,
          total integer not null default 0,
          allowed integer not null default 0,
          blocked integer not null default 0,
          reviewed integer not null default 0
        )
        """,
        """
        create table if not exists receipt_rollup_actions (
          receipt_id text primary key references runtime_receipts(receipt_id) on delete cascade,
          policy_decision text not null,
          dirty integer not null default 0 check (dirty in (0, 1))
        )
        """,
        "drop trigger if exists receipt_rollup_approval_update_dirty",
        """
        create trigger if not exists receipt_rollup_runtime_insert_dirty
        after insert on runtime_receipts
        begin
          insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
          values (new.receipt_id, new.policy_decision, 1)
          on conflict(receipt_id) do update set dirty = 1;
        end
        """,
        """
        create trigger if not exists receipt_rollup_runtime_authority_dirty
        after update of policy_decision, approval_request_id on runtime_receipts
        begin
          insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
          values (new.receipt_id, old.policy_decision, 1)
          on conflict(receipt_id) do update set dirty = 1;
        end
        """,
        """
        create trigger if not exists receipt_rollup_envelope_insert_dirty
        after insert on runtime_receipt_envelopes
        begin
          insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
          select r.receipt_id, r.policy_decision, 1
          from runtime_receipts r
          where r.receipt_id = new.receipt_id
          on conflict(receipt_id) do update set dirty = 1;
        end
        """,
        """
        create trigger if not exists receipt_rollup_envelope_update_dirty
        after update of envelope_full_json, envelope_redacted_json on runtime_receipt_envelopes
        begin
          insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
          select r.receipt_id, r.policy_decision, 1
          from runtime_receipts r
          where r.receipt_id = new.receipt_id
          on conflict(receipt_id) do update set dirty = 1;
        end
        """,
        """
        create trigger if not exists receipt_rollup_envelope_delete_dirty
        after delete on runtime_receipt_envelopes
        begin
          insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
          select r.receipt_id, r.policy_decision, 1
          from runtime_receipts r
          where r.receipt_id = old.receipt_id
          on conflict(receipt_id) do update set dirty = 1;
        end
        """,
        """
        create trigger if not exists receipt_rollup_approval_insert_dirty
        after insert on approval_requests
        begin
          insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
          select r.receipt_id, r.policy_decision, 1
          from runtime_receipts r
          where r.approval_request_id = new.request_id
          on conflict(receipt_id) do update set dirty = 1;
        end
        """,
        """
        create trigger receipt_rollup_approval_update_dirty
        after update of status, resolution_action, resolved_at, policy_action,
                        decision_v2_json, action_envelope_json on approval_requests
        when old.status is not new.status
          or old.resolution_action is not new.resolution_action
          or old.resolved_at is not new.resolved_at
          or old.policy_action is not new.policy_action
          or old.decision_v2_json is not new.decision_v2_json
          or old.action_envelope_json is not new.action_envelope_json
        begin
          insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
          select r.receipt_id, r.policy_decision, 1
          from runtime_receipts r
          where r.approval_request_id = new.request_id
          on conflict(receipt_id) do update set dirty = 1;
        end
        """,
        """
        create trigger if not exists receipt_rollup_approval_delete_dirty
        after delete on approval_requests
        begin
          insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
          select r.receipt_id, r.policy_decision, 1
          from runtime_receipts r
          where r.approval_request_id = old.request_id
          on conflict(receipt_id) do update set dirty = 1;
        end
        """,
    ]


def receipt_rollup_index_statements() -> list[str]:
    return [
        "create index if not exists idx_receipt_daily_rollups_day on receipt_daily_rollups(day_key)",
        "create index if not exists idx_receipt_harness_rollups_total on receipt_harness_rollups(total desc)",
        "create index if not exists idx_receipt_artifact_rollups_total on receipt_artifact_rollups(total desc)",
        (
            "create index if not exists idx_receipt_rollup_actions_dirty "
            "on receipt_rollup_actions(dirty) where dirty = 1"
        ),
    ]


def _json_object(value: object) -> dict[str, object] | None:
    if isinstance(value, Mapping):
        return dict(value)
    if value is None:
        return None
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return dict(parsed) if isinstance(parsed, dict) else None


def canonical_receipt_rollup_action(
    *,
    policy_decision: object,
    envelope_full_json: object = None,
    envelope_redacted_json: object = None,
    approval_request_id: object = None,
    linked_approval_request_id: object = None,
    approval_status: object = None,
    approval_resolution_action: object = None,
    approval_resolved_at: object = None,
    approval_policy_action: object = None,
    approval_decision_v2_json: object = None,
    approval_envelope_json: object = None,
) -> GuardAction:
    """Project every persisted receipt authority to the action used by read APIs."""

    full_envelope = _json_object(envelope_full_json)
    redacted_envelope = _json_object(envelope_redacted_json)
    stored_decision = canonical_receipt_decision(
        policy_decision,
        None,
        reject_contradiction=False,
    )
    full_decision = canonical_receipt_decision(
        stored_decision.policy_decision,
        full_envelope if full_envelope is not None else envelope_full_json,
        reject_contradiction=False,
    )
    redacted_decision = canonical_receipt_decision(
        stored_decision.policy_decision,
        redacted_envelope if redacted_envelope is not None else envelope_redacted_json,
        reject_contradiction=False,
    )
    approval_authority = canonical_linked_approval_authority(
        approval_request_id=approval_request_id,
        linked_request_id=linked_approval_request_id,
        status=approval_status,
        resolution_action=approval_resolution_action,
        resolved_at=approval_resolved_at,
        policy_action=approval_policy_action,
        decision_v2_json=approval_decision_v2_json,
        action_envelope_json=approval_envelope_json,
    )
    actions: list[object] = [
        stored_decision.policy_decision,
        full_decision.policy_decision,
        redacted_decision.policy_decision,
    ]
    if approval_authority.policy_action is not None:
        actions.append(approval_authority.policy_action)
    return most_restrictive_guard_action(*actions, unknown_action="require-reapproval")


def _receipt_action_query(where_clause: str = "") -> str:
    return f"""
        select
          r.receipt_id,
          r.harness,
          r.artifact_id,
          r.artifact_name,
          r.policy_decision,
          r.timestamp,
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
        {where_clause}
    """


def _canonical_action_from_row(row: sqlite3.Row) -> GuardAction:
    return canonical_receipt_rollup_action(
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


def _load_receipt_action_row(connection: sqlite3.Connection, receipt_id: str) -> sqlite3.Row | None:
    return connection.execute(
        _receipt_action_query("where r.receipt_id = ?"),
        (receipt_id,),
    ).fetchone()


def _decision_bucket(policy_decision: str) -> str:
    if policy_decision in {"allow", "warn"}:
        return "allowed"
    if policy_decision == "block":
        return "blocked"
    return "reviewed"


def _bucket_counts(policy_decision: str) -> tuple[int, int, int]:
    bucket = _decision_bucket(policy_decision)
    if bucket == "allowed":
        return 1, 0, 0
    if bucket == "blocked":
        return 0, 1, 0
    return 0, 0, 1


def _day_key_from_timestamp(timestamp: str) -> str:
    return timestamp[:10] if len(timestamp) >= 10 else timestamp


def _artifact_key(artifact_name: str | None, artifact_id: str) -> str:
    name = (artifact_name or "").strip()
    if name:
        return name.lower()
    return artifact_id.lower()


def _coerce_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return 0
        try:
            return int(stripped)
        except ValueError:
            return 0
    return 0


def _apply_receipt_delta(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_name: str | None,
    artifact_id: str,
    policy_decision: str,
    timestamp: str,
    multiplier: int,
) -> None:
    allowed_delta, blocked_delta, reviewed_delta = _bucket_counts(policy_decision)
    allowed_delta *= multiplier
    blocked_delta *= multiplier
    reviewed_delta *= multiplier
    total_delta = multiplier
    day_key = _day_key_from_timestamp(timestamp)
    artifact_key = _artifact_key(artifact_name, artifact_id)

    connection.execute(
        """
        insert into receipt_aggregate_totals (
          totals_key, total, allowed, blocked, reviewed, first_activity_at, last_activity_at
        )
        values (?, ?, ?, ?, ?, ?, ?)
        on conflict(totals_key) do update set
          total = total + excluded.total,
          allowed = allowed + excluded.allowed,
          blocked = blocked + excluded.blocked,
          reviewed = reviewed + excluded.reviewed,
          first_activity_at = case
            when first_activity_at is null then excluded.first_activity_at
            when excluded.first_activity_at is null then first_activity_at
            when excluded.first_activity_at < first_activity_at then excluded.first_activity_at
            else first_activity_at
          end,
          last_activity_at = case
            when last_activity_at is null then excluded.last_activity_at
            when excluded.last_activity_at is null then last_activity_at
            when excluded.last_activity_at > last_activity_at then excluded.last_activity_at
            else last_activity_at
          end
        """,
        (
            _RECEIPT_TOTALS_KEY,
            total_delta,
            allowed_delta,
            blocked_delta,
            reviewed_delta,
            timestamp,
            timestamp,
        ),
    )

    connection.execute(
        """
        insert into receipt_daily_rollups (day_key, total, allowed, blocked, reviewed)
        values (?, ?, ?, ?, ?)
        on conflict(day_key) do update set
          total = total + excluded.total,
          allowed = allowed + excluded.allowed,
          blocked = blocked + excluded.blocked,
          reviewed = reviewed + excluded.reviewed
        """,
        (day_key, total_delta, allowed_delta, blocked_delta, reviewed_delta),
    )

    connection.execute(
        """
        insert into receipt_harness_rollups (harness, total, allowed, blocked, reviewed)
        values (?, ?, ?, ?, ?)
        on conflict(harness) do update set
          total = total + excluded.total,
          allowed = allowed + excluded.allowed,
          blocked = blocked + excluded.blocked,
          reviewed = reviewed + excluded.reviewed
        """,
        (harness, total_delta, allowed_delta, blocked_delta, reviewed_delta),
    )

    connection.execute(
        """
        insert into receipt_artifact_rollups (artifact_key, total, allowed, blocked, reviewed)
        values (?, ?, ?, ?, ?)
        on conflict(artifact_key) do update set
          total = total + excluded.total,
          allowed = allowed + excluded.allowed,
          blocked = blocked + excluded.blocked,
          reviewed = reviewed + excluded.reviewed
        """,
        (artifact_key, total_delta, allowed_delta, blocked_delta, reviewed_delta),
    )


def _record_clean_rollup_action(
    connection: sqlite3.Connection,
    *,
    receipt_id: str,
    policy_decision: str,
) -> None:
    connection.execute(
        """
        insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
        values (?, ?, 0)
        on conflict(receipt_id) do update set
          policy_decision = excluded.policy_decision,
          dirty = 0
        """,
        (receipt_id, policy_decision),
    )


def _reconcile_pending_receipt_event_action(
    connection: sqlite3.Connection,
    *,
    receipt_id: str,
    policy_decision: GuardAction,
) -> None:
    """Keep an unsent receipt event aligned with its current canonical action."""

    row = connection.execute(
        """
        select payload_json
        from guard_cloud_events
        where idempotency_key = ? and uploaded_at is null
        """,
        (f"receipt.created:{receipt_id}",),
    ).fetchone()
    if row is None:
        return
    event = _json_object(row["payload_json"])
    event_payload = event.get("payload") if event is not None else None
    if event is None or not isinstance(event_payload, dict):
        raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)
    _reject_hidden_receipt_event_authority(event)
    if event_payload.get("policyDecision") == policy_decision:
        return
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


def _reject_hidden_receipt_event_authority(event: Mapping[str, object]) -> None:
    """Require ``payload.policyDecision`` to be the event's sole action field."""

    def visit(value: object, *, path: tuple[str, ...]) -> None:
        if isinstance(value, Mapping):
            for raw_key, nested in value.items():
                if not isinstance(raw_key, str):
                    raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)
                allowed = path == ("payload",) and raw_key == "policyDecision"
                if not allowed and _is_action_or_decision_key(raw_key):
                    raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)
                visit(nested, path=(*path, raw_key))
            return
        if isinstance(value, (list, tuple)):
            for index, nested in enumerate(value):
                visit(nested, path=(*path, str(index)))

    visit(event, path=())


def _is_action_or_decision_key(key: str) -> bool:
    if is_action_bearing_key(key):
        return True
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", key)
    tokens = re.sub(r"[^A-Za-z0-9]+", " ", separated).lower().split()
    return any(token in {"decision", "decisions"} for token in tokens)


def reconcile_pending_receipt_events(connection: sqlite3.Connection) -> None:
    """Reproject every pending receipt event from its clean rollup action."""

    rows = connection.execute(
        """
        select r.receipt_id, s.policy_decision
        from runtime_receipts r
        join receipt_rollup_actions s on s.receipt_id = r.receipt_id
        join guard_cloud_events e on e.idempotency_key = 'receipt.created:' || r.receipt_id
        where e.uploaded_at is null
        """
    ).fetchall()
    for row in rows:
        _reconcile_pending_receipt_event_action(
            connection,
            receipt_id=str(row["receipt_id"]),
            policy_decision=normalize_guard_action(
                row["policy_decision"],
                unknown_action="require-reapproval",
            ),
        )


def record_receipt_insert(connection: sqlite3.Connection, receipt: GuardReceipt) -> None:
    row = _load_receipt_action_row(connection, receipt.receipt_id)
    policy_decision = _canonical_action_from_row(row) if row is not None else receipt.policy_decision
    _apply_receipt_delta(
        connection,
        harness=receipt.harness,
        artifact_name=receipt.artifact_name,
        artifact_id=receipt.artifact_id,
        policy_decision=policy_decision,
        timestamp=receipt.timestamp,
        multiplier=1,
    )
    _record_clean_rollup_action(
        connection,
        receipt_id=receipt.receipt_id,
        policy_decision=policy_decision,
    )


def record_receipt_policy_decision_change(
    connection: sqlite3.Connection,
    *,
    receipt_id: str,
    harness: str,
    artifact_name: str | None,
    artifact_id: str,
    timestamp: str,
    old_policy_decision: str,
    new_policy_decision: str,
) -> None:
    state_row = connection.execute(
        "select policy_decision from receipt_rollup_actions where receipt_id = ?",
        (receipt_id,),
    ).fetchone()
    previous_rollup_action = str(state_row["policy_decision"]) if state_row is not None else old_policy_decision
    receipt_row = _load_receipt_action_row(connection, receipt_id)
    current_rollup_action = _canonical_action_from_row(receipt_row) if receipt_row is not None else new_policy_decision
    if previous_rollup_action == current_rollup_action:
        _record_clean_rollup_action(
            connection,
            receipt_id=receipt_id,
            policy_decision=current_rollup_action,
        )
        return
    _apply_receipt_delta(
        connection,
        harness=harness,
        artifact_name=artifact_name,
        artifact_id=artifact_id,
        policy_decision=previous_rollup_action,
        timestamp=timestamp,
        multiplier=-1,
    )
    _apply_receipt_delta(
        connection,
        harness=harness,
        artifact_name=artifact_name,
        artifact_id=artifact_id,
        policy_decision=current_rollup_action,
        timestamp=timestamp,
        multiplier=1,
    )
    _record_clean_rollup_action(
        connection,
        receipt_id=receipt_id,
        policy_decision=current_rollup_action,
    )


def backfill_receipt_rollups(connection: sqlite3.Connection) -> None:
    connection.execute("delete from receipt_aggregate_totals")
    connection.execute("delete from receipt_daily_rollups")
    connection.execute("delete from receipt_harness_rollups")
    connection.execute("delete from receipt_artifact_rollups")
    connection.execute("delete from receipt_rollup_actions")

    receipt_rows = connection.execute(_receipt_action_query()).fetchall()
    connection.executemany(
        """
        insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
        values (?, ?, 0)
        """,
        ((str(row["receipt_id"]), _canonical_action_from_row(row)) for row in receipt_rows),
    )
    reconcile_pending_receipt_events(connection)

    connection.execute(
        """
        insert into receipt_aggregate_totals (
          totals_key, total, allowed, blocked, reviewed, first_activity_at, last_activity_at
        )
        select
          ?,
          count(*),
          coalesce(sum(case when s.policy_decision in ('allow', 'warn') then 1 else 0 end), 0),
          coalesce(sum(case when s.policy_decision = 'block' then 1 else 0 end), 0),
          coalesce(sum(case when s.policy_decision not in ('allow', 'warn', 'block') then 1 else 0 end), 0),
          min(r.timestamp),
          max(r.timestamp)
        from runtime_receipts r
        join receipt_rollup_actions s on s.receipt_id = r.receipt_id
        """,
        (_RECEIPT_TOTALS_KEY,),
    )

    connection.execute(
        """
        insert into receipt_daily_rollups (day_key, total, allowed, blocked, reviewed)
        select
          substr(r.timestamp, 1, 10),
          count(*),
          coalesce(sum(case when s.policy_decision in ('allow', 'warn') then 1 else 0 end), 0),
          coalesce(sum(case when s.policy_decision = 'block' then 1 else 0 end), 0),
          coalesce(sum(case when s.policy_decision not in ('allow', 'warn', 'block') then 1 else 0 end), 0)
        from runtime_receipts r
        join receipt_rollup_actions s on s.receipt_id = r.receipt_id
        group by substr(r.timestamp, 1, 10)
        """
    )

    connection.execute(
        """
        insert into receipt_harness_rollups (harness, total, allowed, blocked, reviewed)
        select
          r.harness,
          count(*),
          coalesce(sum(case when s.policy_decision in ('allow', 'warn') then 1 else 0 end), 0),
          coalesce(sum(case when s.policy_decision = 'block' then 1 else 0 end), 0),
          coalesce(sum(case when s.policy_decision not in ('allow', 'warn', 'block') then 1 else 0 end), 0)
        from runtime_receipts r
        join receipt_rollup_actions s on s.receipt_id = r.receipt_id
        group by r.harness
        """
    )

    connection.execute(
        """
        insert into receipt_artifact_rollups (artifact_key, total, allowed, blocked, reviewed)
        select
          lower(coalesce(nullif(trim(r.artifact_name), ''), r.artifact_id)),
          count(*),
          coalesce(sum(case when s.policy_decision in ('allow', 'warn') then 1 else 0 end), 0),
          coalesce(sum(case when s.policy_decision = 'block' then 1 else 0 end), 0),
          coalesce(sum(case when s.policy_decision not in ('allow', 'warn', 'block') then 1 else 0 end), 0)
        from runtime_receipts r
        join receipt_rollup_actions s on s.receipt_id = r.receipt_id
        group by lower(coalesce(nullif(trim(r.artifact_name), ''), r.artifact_id))
        """
    )


def reconcile_dirty_receipt_rollups(connection: sqlite3.Connection) -> None:
    """Apply only canonical-action changes invalidated by persisted authority writes."""

    rows = connection.execute(
        """
        select
          r.receipt_id,
          r.harness,
          r.artifact_id,
          r.artifact_name,
          r.policy_decision,
          r.timestamp,
          s.policy_decision as rollup_policy_decision,
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
        join receipt_rollup_actions s on s.receipt_id = r.receipt_id
        left join runtime_receipt_envelopes e on e.receipt_id = r.receipt_id
        left join approval_requests a on a.request_id = r.approval_request_id
        where s.dirty = 1
        """
    ).fetchall()
    for row in rows:
        previous_action = str(row["rollup_policy_decision"])
        current_action = _canonical_action_from_row(row)
        if previous_action != current_action:
            _apply_receipt_delta(
                connection,
                harness=str(row["harness"]),
                artifact_name=row["artifact_name"],
                artifact_id=str(row["artifact_id"]),
                policy_decision=previous_action,
                timestamp=str(row["timestamp"]),
                multiplier=-1,
            )
            _apply_receipt_delta(
                connection,
                harness=str(row["harness"]),
                artifact_name=row["artifact_name"],
                artifact_id=str(row["artifact_id"]),
                policy_decision=current_action,
                timestamp=str(row["timestamp"]),
                multiplier=1,
            )
        _record_clean_rollup_action(
            connection,
            receipt_id=str(row["receipt_id"]),
            policy_decision=current_action,
        )
        _reconcile_pending_receipt_event_action(
            connection,
            receipt_id=str(row["receipt_id"]),
            policy_decision=current_action,
        )


def receipt_rollups_initialized(connection: sqlite3.Connection) -> bool:
    rollup_row = connection.execute(
        "select 1 from receipt_aggregate_totals where totals_key = ?",
        (_RECEIPT_TOTALS_KEY,),
    ).fetchone()
    return rollup_row is not None


def receipt_rollups_need_backfill(connection: sqlite3.Connection) -> bool:
    rollup_row = connection.execute(
        "select total from receipt_aggregate_totals where totals_key = ?",
        (_RECEIPT_TOTALS_KEY,),
    ).fetchone()
    if rollup_row is None:
        return True
    receipt_row = connection.execute("select count(*) as total from runtime_receipts").fetchone()
    receipt_total = int(receipt_row["total"]) if receipt_row is not None else 0
    rollup_total = int(rollup_row["total"])
    if rollup_total != receipt_total:
        return True
    state_row = connection.execute("select count(*) as total from receipt_rollup_actions").fetchone()
    state_total = int(state_row["total"]) if state_row is not None else 0
    return state_total != receipt_total


def count_receipts_from_rollups(connection: sqlite3.Connection, *, harness: str | None = None) -> int | None:
    global_row = connection.execute(
        "select total from receipt_aggregate_totals where totals_key = ?",
        (_RECEIPT_TOTALS_KEY,),
    ).fetchone()
    if global_row is None:
        return None

    if harness is None:
        return int(global_row["total"])

    row = connection.execute(
        "select total from receipt_harness_rollups where harness = ?",
        (harness,),
    ).fetchone()
    if row is None:
        return None
    return int(row["total"])


def load_receipt_analytics(
    connection: sqlite3.Connection,
    *,
    activity_days: int,
    trend_days: int,
    top_limit: int,
) -> dict[str, object]:
    now = datetime.now(tz=timezone.utc)
    start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    activity_start = start_of_today - timedelta(days=activity_days - 1)
    trend_start = start_of_today - timedelta(days=trend_days - 1)
    activity_start_key = activity_start.strftime("%Y-%m-%d")
    trend_start_key = trend_start.strftime("%Y-%m-%d")

    totals_row = connection.execute(
        "select total, allowed, blocked, reviewed, first_activity_at, last_activity_at "
        "from receipt_aggregate_totals where totals_key = ?",
        (_RECEIPT_TOTALS_KEY,),
    ).fetchone()

    daily_rows = connection.execute(
        """
        select day_key, total, allowed, blocked, reviewed
        from receipt_daily_rollups
        where day_key >= ?
        order by day_key asc
        """,
        (activity_start_key,),
    ).fetchall()

    harness_rows = connection.execute(
        """
        select harness, total, allowed, blocked, reviewed
        from receipt_harness_rollups
        order by total desc
        limit ?
        """,
        (top_limit,),
    ).fetchall()

    artifact_rows = connection.execute(
        """
        select artifact_key, total, allowed, blocked, reviewed
        from receipt_artifact_rollups
        order by total desc
        limit ?
        """,
        (top_limit,),
    ).fetchall()

    total = int(totals_row["total"]) if totals_row is not None else 0
    allowed = int(totals_row["allowed"] or 0) if totals_row is not None else 0
    blocked = int(totals_row["blocked"] or 0) if totals_row is not None else 0
    reviewed = int(totals_row["reviewed"] or 0) if totals_row is not None else 0
    first_activity_at = str(totals_row["first_activity_at"]) if totals_row and totals_row["first_activity_at"] else None
    last_activity_at = str(totals_row["last_activity_at"]) if totals_row and totals_row["last_activity_at"] else None

    daily_map = {str(row["day_key"]): int(row["total"]) for row in daily_rows}
    trend_map = {
        str(row["day_key"]): {
            "allowed": int(row["allowed"] or 0),
            "blocked": int(row["blocked"] or 0),
            "reviewed": int(row["reviewed"] or 0),
        }
        for row in daily_rows
        if str(row["day_key"]) >= trend_start_key
    }

    daily_activity: list[dict[str, object]] = []
    for offset in range(activity_days):
        day = activity_start + timedelta(days=offset)
        day_key = day.strftime("%Y-%m-%d")
        daily_activity.append({"date_key": day_key, "total": daily_map.get(day_key, 0)})

    trend_buckets: list[dict[str, object]] = []
    for offset in range(trend_days):
        day = trend_start + timedelta(days=offset)
        day_key = day.strftime("%Y-%m-%d")
        counts = trend_map.get(day_key, {"allowed": 0, "blocked": 0, "reviewed": 0})
        trend_buckets.append(
            {
                "date_key": day_key,
                "label": f"{day.strftime('%b')} {day.day}",
                "allowed": counts["allowed"],
                "blocked": counts["blocked"],
                "reviewed": counts["reviewed"],
            }
        )

    active_day_streak = 0
    streak_entries = list(reversed(daily_activity))
    if streak_entries and _coerce_int(streak_entries[0]["total"]) == 0:
        streak_entries = streak_entries[1:]
    for entry in streak_entries:
        if _coerce_int(entry["total"]) > 0:
            active_day_streak += 1
        else:
            break

    peak_day_total = max((_coerce_int(entry["total"]) for entry in daily_activity), default=0)

    return {
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "reviewed": reviewed,
        "first_activity_at": first_activity_at,
        "last_activity_at": last_activity_at,
        "active_day_streak": active_day_streak,
        "peak_day_total": peak_day_total,
        "daily_activity": daily_activity,
        "trend_buckets": trend_buckets,
        "by_harness": [
            {
                "harness": str(row["harness"]),
                "total": int(row["total"]),
                "allowed": int(row["allowed"] or 0),
                "blocked": int(row["blocked"] or 0),
            }
            for row in harness_rows
        ],
        "top_artifacts": [
            {
                "name": str(row["artifact_key"]),
                "total": int(row["total"]),
                "allowed": int(row["allowed"] or 0),
                "blocked": int(row["blocked"] or 0),
            }
            for row in artifact_rows
        ],
        "loaded_sample_limit": 200,
    }
