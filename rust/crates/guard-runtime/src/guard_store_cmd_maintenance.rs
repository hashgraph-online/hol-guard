//! Crash-safe command activity maintenance: rollup backfill, retained-detail
//! compaction and expired-aggregate pruning, one bounded batch per call.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_cmd_lifecycle::recover;
use crate::guard_store_cmd_rollups::{backfill_batch, rebuild, reconciled, Cursor};
use crate::guard_store_db::{
    exec, int, placeholders, query_all, query_one, text, StoreError, StoreResult,
};

fn optional_text(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

/// Delete one batch of detail rows already rolled up; returns
/// `(detail_deleted, correlation_rows_deleted)`.
fn delete_retained_detail(
    connection: &Connection,
    cutoff: &str,
    batch_size: i64,
) -> StoreResult<(i64, i64)> {
    let rows = query_all(
        connection,
        "select membership.activity_id from command_activity_rollup_membership as membership \
         join command_activity as activity on activity.activity_id = membership.activity_id \
         where membership.detail_present = 1 and membership.occurred_at < ? \
         order by membership.occurred_at, membership.activity_id limit ?",
        &[Value::from(cutoff), Value::from(batch_size)],
    )?;
    if rows.is_empty() {
        return Ok((0, 0));
    }
    let ids: Vec<Value> = rows
        .iter()
        .map(|row| Value::from(text(row, "activity_id")))
        .collect();
    let marks = placeholders(ids.len());
    let correlations = query_one(
        connection,
        &format!("select count(*) as count from command_activity_correlations where activity_id in ({marks})"),
        &ids,
    )?
    .map_or(0, |row| int(&row, "count"));
    for table in [
        "command_activity_invocation",
        "command_activity_shadow_cohorts",
        "command_activity_shadow_evaluations",
    ] {
        exec(
            connection,
            &format!("delete from {table} where activity_id in ({marks})"),
            &ids,
        )?;
    }
    let deleted = exec(
        connection,
        &format!("delete from command_activity where activity_id in ({marks})"),
        &ids,
    )?;
    Ok((deleted.max(0), correlations))
}

fn delete_expired_aggregates(
    connection: &Connection,
    cutoff: &str,
    batch_size: i64,
) -> StoreResult<i64> {
    let rollups = exec(
        connection,
        "delete from command_activity_daily_rollups where rowid in ( \
         select rowid from command_activity_daily_rollups \
         where day < ? order by day, dimension, dimension_value limit ?)",
        &[Value::from(cutoff), Value::from(batch_size)],
    )?
    .max(0);
    let remaining = batch_size - rollups;
    if remaining == 0 {
        return Ok(rollups);
    }
    let totals = exec(
        connection,
        "delete from command_activity_daily_totals where rowid in ( \
         select rowid from command_activity_daily_totals where day < ? order by day limit ?)",
        &[Value::from(cutoff), Value::from(remaining)],
    )?
    .max(0);
    let remaining = remaining - totals;
    if remaining == 0 {
        return Ok(rollups + totals);
    }
    let memberships = exec(
        connection,
        "delete from command_activity_rollup_membership where rowid in ( \
         select rowid from command_activity_rollup_membership \
         where detail_present = 0 and day < ? order by day, activity_id limit ?)",
        &[Value::from(cutoff), Value::from(remaining)],
    )?
    .max(0);
    Ok(rollups + totals + memberships)
}

/// Run at most one batch until today's work is complete.
pub(crate) fn maintain(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let batch_size = args.int("batch_size")?;
    let today = args.str("today")?;
    let now = args.str("now")?;
    let state = query_one(
        connection,
        "select * from command_activity_maintenance where singleton = 1",
        &[],
    )?
    .ok_or(StoreError::Invalid("native_guard_store_state_missing"))?;
    let last_completed = state.get("last_completed_day").and_then(Value::as_str);
    let pending = query_one(
        connection,
        "select 1 as present from command_activity_rollup_pending limit 1",
        &[],
    )?;
    if last_completed == Some(today) && pending.is_none() {
        recover(connection, "maintenance")?;
        return Ok(json!([false, true, 0, 0, 0, 0]));
    }
    let backfill = backfill_batch(
        connection,
        batch_size,
        now,
        &Cursor {
            occurred_at: optional_text(state.get("rollup_backfill_cursor_occurred_at")),
            activity_id: optional_text(state.get("rollup_backfill_cursor_activity_id")),
            complete: int(&state, "rollup_backfill_complete") != 0,
        },
    )?;
    let (detail_deleted, correlations_deleted) =
        delete_retained_detail(connection, args.str("detail_cutoff")?, batch_size)?;
    let aggregates_deleted =
        delete_expired_aggregates(connection, args.str("aggregate_cutoff")?, batch_size)?;
    let completed =
        backfill.complete && detail_deleted < batch_size && aggregates_deleted < batch_size;
    exec(
        connection,
        "update command_activity_maintenance \
         set last_completed_day = case when ? then ? else last_completed_day end, \
             last_run_at = ?, last_backfilled_rows = ?, last_detail_rows_deleted = ?, \
             last_correlation_rows_deleted = ?, last_aggregate_rows_deleted = ?, \
             detail_compaction_started_at = case \
               when ? > 0 then coalesce(detail_compaction_started_at, ?) \
               else detail_compaction_started_at end, \
             rollup_backfill_cursor_occurred_at = ?, rollup_backfill_cursor_activity_id = ?, \
             rollup_backfill_complete = ? where singleton = 1",
        &[
            Value::from(completed),
            Value::from(today),
            Value::from(now),
            Value::from(backfill.rolled),
            Value::from(detail_deleted),
            Value::from(correlations_deleted),
            Value::from(aggregates_deleted),
            Value::from(detail_deleted),
            Value::from(now),
            backfill
                .cursor_occurred_at
                .clone()
                .map_or(Value::Null, Value::from),
            backfill
                .cursor_activity_id
                .clone()
                .map_or(Value::Null, Value::from),
            Value::from(backfill.cursor_complete),
        ],
    )?;
    recover(connection, "maintenance")?;
    Ok(json!([
        true,
        completed,
        backfill.rolled,
        detail_deleted,
        correlations_deleted,
        aggregates_deleted
    ]))
}

pub(crate) fn rebuild_rollups(connection: &Connection, args: &Args) -> StoreResult<Value> {
    rebuild(connection, args.str("now")?)?;
    Ok(Value::Null)
}

pub(crate) fn rollups_are_reconciled(connection: &Connection) -> StoreResult<Value> {
    Ok(json!(reconciled(connection)?))
}
