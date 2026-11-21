//! Incremental receipt rollups: global totals, per-day, per-harness and
//! per-artifact counts kept in step with each receipt's canonical action.
//!
//! Authority writes mark rollup rows dirty through schema triggers; the next
//! reader replays only the changed canonical actions.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_db::{exec, int, query_all, query_one, text, Row, StoreResult};
use crate::guard_store_json::{py_prefix, py_strip};
use crate::guard_store_receipt_decision::row_action;
use crate::guard_store_receipt_events::{reconcile_pending_event, reconcile_pending_events};
use guard_contracts::GuardAction;

const TOTALS_KEY: &str = "global";

/// `_receipt_action_query`: every persisted authority a receipt's canonical
/// action is derived from.
pub(crate) fn action_query(where_clause: &str) -> String {
    format!(
        "select r.receipt_id, r.harness, r.artifact_id, r.artifact_name, r.policy_decision, \
         r.timestamp, e.envelope_full_json, e.envelope_redacted_json, r.approval_request_id, \
         a.request_id as linked_approval_request_id, a.status as approval_status, \
         a.resolution_action as approval_resolution_action, \
         a.resolved_at as approval_resolved_at, a.policy_action as approval_policy_action, \
         a.decision_v2_json as approval_decision_v2_json, \
         a.action_envelope_json as approval_envelope_json \
         from runtime_receipts r \
         left join runtime_receipt_envelopes e on e.receipt_id = r.receipt_id \
         left join approval_requests a on a.request_id = r.approval_request_id {where_clause}"
    )
}

fn bucket_counts(policy_decision: &str) -> (i64, i64, i64) {
    match policy_decision {
        "allow" | "warn" => (1, 0, 0),
        "block" => (0, 1, 0),
        _ => (0, 0, 1),
    }
}

fn day_key(timestamp: &str) -> String {
    if timestamp.chars().count() >= 10 {
        py_prefix(timestamp, 10)
    } else {
        timestamp.to_owned()
    }
}

fn artifact_key(artifact_name: &Value, artifact_id: &str) -> String {
    let name = artifact_name.as_str().map_or("", py_strip);
    if name.is_empty() {
        artifact_id.to_lowercase()
    } else {
        name.to_lowercase()
    }
}

const ROLLUP_UPSERT_TAIL: &str = "on conflict({key}) do update set \
     total = total + excluded.total, allowed = allowed + excluded.allowed, \
     blocked = blocked + excluded.blocked, reviewed = reviewed + excluded.reviewed";

fn bucket_upsert(table: &str, key: &str) -> String {
    format!(
        "insert into {table} ({key}, total, allowed, blocked, reviewed) values (?, ?, ?, ?, ?) {}",
        ROLLUP_UPSERT_TAIL.replace("{key}", key)
    )
}

/// `_apply_receipt_delta`.
pub(crate) fn apply_delta(
    connection: &Connection,
    row: &Row,
    policy_decision: &str,
    multiplier: i64,
) -> StoreResult<()> {
    let (allowed, blocked, reviewed) = bucket_counts(policy_decision);
    let (allowed, blocked, reviewed) = (
        allowed * multiplier,
        blocked * multiplier,
        reviewed * multiplier,
    );
    let timestamp = text(row, "timestamp");
    let null = Value::Null;
    let counts = |key: String| {
        vec![
            Value::String(key),
            Value::from(multiplier),
            Value::from(allowed),
            Value::from(blocked),
            Value::from(reviewed),
        ]
    };
    exec(
        connection,
        "insert into receipt_aggregate_totals (totals_key, total, allowed, blocked, reviewed, \
         first_activity_at, last_activity_at) values (?, ?, ?, ?, ?, ?, ?) \
         on conflict(totals_key) do update set \
         total = total + excluded.total, allowed = allowed + excluded.allowed, \
         blocked = blocked + excluded.blocked, reviewed = reviewed + excluded.reviewed, \
         first_activity_at = case \
           when first_activity_at is null then excluded.first_activity_at \
           when excluded.first_activity_at is null then first_activity_at \
           when excluded.first_activity_at < first_activity_at then excluded.first_activity_at \
           else first_activity_at end, \
         last_activity_at = case \
           when last_activity_at is null then excluded.last_activity_at \
           when excluded.last_activity_at is null then last_activity_at \
           when excluded.last_activity_at > last_activity_at then excluded.last_activity_at \
           else last_activity_at end",
        &[
            Value::from(TOTALS_KEY),
            Value::from(multiplier),
            Value::from(allowed),
            Value::from(blocked),
            Value::from(reviewed),
            Value::from(timestamp),
            Value::from(timestamp),
        ],
    )?;
    exec(
        connection,
        &bucket_upsert("receipt_daily_rollups", "day_key"),
        &counts(day_key(timestamp)),
    )?;
    exec(
        connection,
        &bucket_upsert("receipt_harness_rollups", "harness"),
        &counts(text(row, "harness").to_owned()),
    )?;
    let name = row.get("artifact_name").unwrap_or(&null);
    exec(
        connection,
        &bucket_upsert("receipt_artifact_rollups", "artifact_key"),
        &counts(artifact_key(name, text(row, "artifact_id"))),
    )?;
    Ok(())
}

/// `_record_clean_rollup_action`.
pub(crate) fn record_clean_action(
    connection: &Connection,
    receipt_id: &str,
    policy_decision: &str,
) -> StoreResult<()> {
    exec(
        connection,
        "insert into receipt_rollup_actions (receipt_id, policy_decision, dirty) values (?, ?, 0) \
         on conflict(receipt_id) do update set policy_decision = excluded.policy_decision, dirty = 0",
        &[Value::from(receipt_id), Value::from(policy_decision)],
    )?;
    Ok(())
}

/// `record_receipt_insert`: count one new receipt under its canonical action.
pub(crate) fn record_insert(
    connection: &Connection,
    receipt_row: &Row,
    fallback: GuardAction,
) -> StoreResult<()> {
    let loaded = query_one(
        connection,
        &action_query("where r.receipt_id = ?"),
        &[receipt_row
            .get("receipt_id")
            .cloned()
            .unwrap_or(Value::Null)],
    )?;
    let policy = match &loaded {
        Some(row) => row_action(row)?,
        None => fallback,
    };
    apply_delta(connection, receipt_row, policy.as_str(), 1)?;
    record_clean_action(connection, text(receipt_row, "receipt_id"), policy.as_str())
}

/// `record_receipt_policy_decision_change`: move a receipt between buckets when
/// its canonical action changed.
pub(crate) fn record_decision_change(
    connection: &Connection,
    receipt_row: &Row,
    old_policy_decision: &str,
    new_policy_decision: &str,
) -> StoreResult<()> {
    let receipt_id = text(receipt_row, "receipt_id");
    let state = query_one(
        connection,
        "select policy_decision from receipt_rollup_actions where receipt_id = ?",
        &[Value::from(receipt_id)],
    )?;
    let previous = state.as_ref().map_or_else(
        || old_policy_decision.to_owned(),
        |row| text(row, "policy_decision").to_owned(),
    );
    let loaded = query_one(
        connection,
        &action_query("where r.receipt_id = ?"),
        &[Value::from(receipt_id)],
    )?;
    let current = match &loaded {
        Some(row) => row_action(row)?.as_str().to_owned(),
        None => new_policy_decision.to_owned(),
    };
    if previous != current {
        apply_delta(connection, receipt_row, &previous, -1)?;
        apply_delta(connection, receipt_row, &current, 1)?;
    }
    record_clean_action(connection, receipt_id, &current)
}

fn archived_receipts(connection: &Connection) -> StoreResult<i64> {
    let table = query_one(
        connection,
        "select 1 as present from sqlite_master \
         where type = 'table' and name = 'guard_storage_maintenance'",
        &[],
    )?;
    if table.is_none() {
        return Ok(0);
    }
    let row = query_one(
        connection,
        "select archived_receipts from guard_storage_maintenance where singleton = 1",
        &[],
    )?;
    Ok(row.map_or(0, |row| int(&row, "archived_receipts")))
}

const BUCKET_SUMS: &str = "count(*), \
     coalesce(sum(case when s.policy_decision in ('allow', 'warn') then 1 else 0 end), 0), \
     coalesce(sum(case when s.policy_decision = 'block' then 1 else 0 end), 0), \
     coalesce(sum(case when s.policy_decision not in ('allow', 'warn', 'block') then 1 else 0 end), 0)";

fn rebuild_aggregates(connection: &Connection) -> StoreResult<()> {
    let grouped = |table: &str, column: &str, expression: &str| {
        format!(
            "insert into {table} ({column}, total, allowed, blocked, reviewed) \
             select {expression}, {BUCKET_SUMS} from runtime_receipts r \
             join receipt_rollup_actions s on s.receipt_id = r.receipt_id group by {expression}"
        )
    };
    exec(
        connection,
        &format!(
            "insert into receipt_aggregate_totals (totals_key, total, allowed, blocked, reviewed, \
             first_activity_at, last_activity_at) select ?, {BUCKET_SUMS}, min(r.timestamp), \
             max(r.timestamp) from runtime_receipts r \
             join receipt_rollup_actions s on s.receipt_id = r.receipt_id"
        ),
        &[Value::from(TOTALS_KEY)],
    )?;
    exec(
        connection,
        &grouped(
            "receipt_daily_rollups",
            "day_key",
            "substr(r.timestamp, 1, 10)",
        ),
        &[],
    )?;
    exec(
        connection,
        &grouped("receipt_harness_rollups", "harness", "r.harness"),
        &[],
    )?;
    exec(
        connection,
        &grouped(
            "receipt_artifact_rollups",
            "artifact_key",
            "lower(coalesce(nullif(trim(r.artifact_name), ''), r.artifact_id))",
        ),
        &[],
    )?;
    Ok(())
}

/// `backfill_receipt_rollups`: rebuild every rollup from the receipts.
pub(crate) fn backfill(connection: &Connection) -> StoreResult<()> {
    let archived = archived_receipts(connection)?;
    let rows = query_all(connection, &action_query(""), &[])?;
    let mut actions = Vec::with_capacity(rows.len());
    for row in &rows {
        actions.push((text(row, "receipt_id").to_owned(), row_action(row)?));
    }
    if archived > 0 {
        exec(connection, "delete from receipt_rollup_actions", &[])?;
        for (receipt_id, action) in &actions {
            insert_clean(connection, receipt_id, *action)?;
        }
        for (receipt_id, action) in &actions {
            reconcile_pending_event(connection, receipt_id, *action)?;
        }
        exec(
            connection,
            "insert into receipt_aggregate_totals (totals_key, total) values (?, ?) \
             on conflict(totals_key) do update set total = excluded.total",
            &[
                Value::from(TOTALS_KEY),
                Value::from(i64::try_from(rows.len()).unwrap_or(i64::MAX) + archived),
            ],
        )?;
        return Ok(());
    }
    for table in [
        "receipt_aggregate_totals",
        "receipt_daily_rollups",
        "receipt_harness_rollups",
        "receipt_artifact_rollups",
        "receipt_rollup_actions",
    ] {
        exec(connection, &format!("delete from {table}"), &[])?;
    }
    for (receipt_id, action) in &actions {
        insert_clean(connection, receipt_id, *action)?;
    }
    reconcile_pending_events(connection)?;
    rebuild_aggregates(connection)
}

fn insert_clean(connection: &Connection, receipt_id: &str, action: GuardAction) -> StoreResult<()> {
    exec(
        connection,
        "insert into receipt_rollup_actions (receipt_id, policy_decision, dirty) values (?, ?, 0)",
        &[Value::from(receipt_id), Value::from(action.as_str())],
    )?;
    Ok(())
}

/// `reconcile_dirty_receipt_rollups`: apply only the canonical-action changes
/// invalidated by persisted authority writes.
pub(crate) fn reconcile_dirty(connection: &Connection) -> StoreResult<()> {
    let rows = query_all(
        connection,
        "select r.receipt_id, r.harness, r.artifact_id, r.artifact_name, r.policy_decision, \
         r.timestamp, s.policy_decision as rollup_policy_decision, e.envelope_full_json, \
         e.envelope_redacted_json, r.approval_request_id, \
         a.request_id as linked_approval_request_id, a.status as approval_status, \
         a.resolution_action as approval_resolution_action, \
         a.resolved_at as approval_resolved_at, a.policy_action as approval_policy_action, \
         a.decision_v2_json as approval_decision_v2_json, \
         a.action_envelope_json as approval_envelope_json \
         from runtime_receipts r \
         join receipt_rollup_actions s on s.receipt_id = r.receipt_id \
         left join runtime_receipt_envelopes e on e.receipt_id = r.receipt_id \
         left join approval_requests a on a.request_id = r.approval_request_id \
         where s.dirty = 1",
        &[],
    )?;
    for row in &rows {
        let previous = text(row, "rollup_policy_decision");
        let current = row_action(row)?;
        if previous != current.as_str() {
            apply_delta(connection, row, previous, -1)?;
            apply_delta(connection, row, current.as_str(), 1)?;
        }
        let receipt_id = text(row, "receipt_id");
        record_clean_action(connection, receipt_id, current.as_str())?;
        reconcile_pending_event(connection, receipt_id, current)?;
    }
    Ok(())
}

/// `receipt_rollups_need_backfill`.
pub(crate) fn need_backfill(connection: &Connection) -> StoreResult<bool> {
    let totals = query_one(
        connection,
        "select total from receipt_aggregate_totals where totals_key = ?",
        &[Value::from(TOTALS_KEY)],
    )?;
    let Some(totals) = totals else {
        return Ok(true);
    };
    let receipts = query_one(
        connection,
        "select count(*) as total from runtime_receipts",
        &[],
    )?
    .map_or(0, |row| int(&row, "total"));
    if int(&totals, "total") != receipts + archived_receipts(connection)? {
        return Ok(true);
    }
    let states = query_one(
        connection,
        "select count(*) as total from receipt_rollup_actions",
        &[],
    )?
    .map_or(0, |row| int(&row, "total"));
    Ok(states != receipts)
}

/// `sync_state` key a schema migration sets to request a full rollup rebuild.
pub(crate) const REBUILD_PENDING_KEY: &str = "receipt_rollups_rebuild_pending";

/// Whether a migration has requested a full rollup rebuild.
pub(crate) fn rebuild_pending(connection: &Connection) -> StoreResult<bool> {
    Ok(query_one(
        connection,
        "select 1 as pending from sync_state where state_key = ?",
        &[Value::from(REBUILD_PENDING_KEY)],
    )?
    .is_some())
}

/// Run a migration-requested rebuild before any incremental delta or direct
/// total read can build on rollups with stale bucket semantics.
pub(crate) fn rebuild_if_pending(connection: &Connection) -> StoreResult<bool> {
    if !rebuild_pending(connection)? {
        return Ok(false);
    }
    backfill(connection)?;
    exec(
        connection,
        "delete from sync_state where state_key = ?",
        &[Value::from(REBUILD_PENDING_KEY)],
    )?;
    Ok(true)
}

/// Rebuild or reconcile so the rollups reflect every persisted authority.
pub(crate) fn refresh(connection: &Connection) -> StoreResult<()> {
    if rebuild_if_pending(connection)? {
        return Ok(());
    }
    if need_backfill(connection)? {
        backfill(connection)
    } else {
        reconcile_dirty(connection)
    }
}

/// `count_receipts_from_rollups`.
pub(crate) fn count_from_rollups(
    connection: &Connection,
    harness: Option<&str>,
) -> StoreResult<Option<i64>> {
    let global = query_one(
        connection,
        "select total from receipt_aggregate_totals where totals_key = ?",
        &[Value::from(TOTALS_KEY)],
    )?;
    let Some(global) = global else {
        return Ok(None);
    };
    let Some(harness) = harness else {
        return Ok(Some(int(&global, "total")));
    };
    let row = query_one(
        connection,
        "select total from receipt_harness_rollups where harness = ?",
        &[Value::from(harness)],
    )?;
    Ok(row.map(|row| int(&row, "total")))
}
