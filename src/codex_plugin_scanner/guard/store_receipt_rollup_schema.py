"""SQLite schema for receipt rollup tables (rows are owned by the resident)."""

from __future__ import annotations

import sqlite3


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


RECEIPT_ROLLUP_REBUILD_PENDING_KEY = "receipt_rollups_rebuild_pending"


def request_receipt_rollup_rebuild(connection: sqlite3.Connection, requested_at: str) -> None:
    """Ask the resident to rebuild every receipt rollup before its next delta or total read."""

    connection.execute(
        """
        insert into sync_state (state_key, payload_json, updated_at) values (?, '{}', ?)
        on conflict(state_key) do update set updated_at = excluded.updated_at
        """,
        (RECEIPT_ROLLUP_REBUILD_PENDING_KEY, requested_at),
    )
