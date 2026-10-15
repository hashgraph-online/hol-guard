//! Bounded lifecycle maintenance for high-volume Guard evidence: archive aged
//! runtime receipts, prune native decision receipts, guard events and uploaded
//! cloud events, and reclaim free pages, one bounded batch per call.
//!
//! The caller passes every timestamp (`now` and both cutoffs) already
//! computed, so this method does no clock or calendar arithmetic. File-level
//! sweeps (quarantined snapshots, update staging) stay with the caller.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, int, placeholders, query_all, query_one, StoreError, StoreResult,
};

const MAX_BATCH_SIZE: i64 = 10_000;
const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");
const HOOK_TABLE: &str = "native_hook_decision_receipts";
const PROMPT_TABLE: &str = "native_prompt_decision_receipts";

struct Limits<'a> {
    cutoff: &'a str,
    cloud_cutoff: &'a str,
    batch_size: i64,
    receipt_detail_limit: i64,
    guard_event_limit: i64,
    uploaded_cloud_event_limit: i64,
}

fn limit(args: &Args, key: &str) -> StoreResult<i64> {
    let value = args.int(key)?;
    if value < 1 {
        return Err(INVALID);
    }
    Ok(value)
}

/// `maintain_storage`: one bounded batch across every evidence table.
pub(crate) fn maintain(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let limits = Limits {
        cutoff: args.str("cutoff")?,
        cloud_cutoff: args.str("cloud_cutoff")?,
        batch_size: limit(args, "batch_size")?,
        receipt_detail_limit: limit(args, "receipt_detail_limit")?,
        guard_event_limit: limit(args, "guard_event_limit")?,
        uploaded_cloud_event_limit: limit(args, "uploaded_cloud_event_limit")?,
    };
    if limits.batch_size > MAX_BATCH_SIZE {
        return Err(INVALID);
    }
    let batch = limits.batch_size;
    let receipts_archived = archive_receipt_batch(connection, &limits)?;
    let tool_budget = (batch / 2).max(1);
    let tool_deleted = delete_native_decision_batch(connection, &limits, HOOK_TABLE, tool_budget)?;
    let prompt_budget = batch - tool_deleted;
    let prompt_deleted = if prompt_budget != 0 {
        delete_native_decision_batch(connection, &limits, PROMPT_TABLE, prompt_budget)?
    } else {
        0
    };
    let native_complete =
        tool_deleted < tool_budget && (prompt_budget <= 0 || prompt_deleted < prompt_budget);
    let guard_events_deleted = delete_guard_event_batch(connection, &limits)?;
    let cloud_events_deleted = delete_uploaded_cloud_event_batch(connection, &limits)?;
    let pages_reclaimed = reclaim_free_pages(connection, batch)?;
    let completed = receipts_archived < batch
        && native_complete
        && guard_events_deleted < batch
        && cloud_events_deleted < batch;
    exec(
        connection,
        "update guard_storage_maintenance \
         set archived_receipts = archived_receipts + ?, last_run_at = ?, last_receipts_archived = ?, \
             last_guard_events_deleted = ?, last_cloud_events_deleted = ?, last_pages_reclaimed = ? \
         where singleton = 1",
        &[
            Value::from(receipts_archived),
            Value::from(args.str("now")?),
            Value::from(receipts_archived),
            Value::from(guard_events_deleted),
            Value::from(cloud_events_deleted),
            Value::from(pages_reclaimed),
        ],
    )?;
    Ok(json!({
        "completed": completed,
        "receipts_archived": receipts_archived,
        "native_decision_receipts_deleted": tool_deleted + prompt_deleted,
        "guard_events_deleted": guard_events_deleted,
        "cloud_events_deleted": cloud_events_deleted,
        "pages_reclaimed": pages_reclaimed,
    }))
}

/// `run_storage_housekeeping`: planner statistics and a passive WAL
/// checkpoint, outside any transaction. Never blocks enforcement.
pub(crate) fn housekeeping(connection: &Connection) -> StoreResult<Value> {
    connection.execute_batch("pragma optimize")?;
    connection.execute_batch("pragma wal_checkpoint(passive)")?;
    Ok(Value::Null)
}

/// Rowid below which a table is over its retained-detail budget.
fn rowid_boundary(
    connection: &Connection,
    table: &str,
    detail_limit: i64,
    filter: &str,
) -> StoreResult<Value> {
    let row = query_one(
        connection,
        &format!("select max(rowid) as boundary from {table} {filter}"),
        &[],
    )?;
    let boundary = row.and_then(|row| row.get("boundary").and_then(Value::as_i64));
    Ok(match boundary {
        Some(max) if max - detail_limit > 0 => Value::from(max - detail_limit),
        _ => Value::Null,
    })
}

fn archive_receipt_batch(connection: &Connection, limits: &Limits) -> StoreResult<i64> {
    let boundary = rowid_boundary(
        connection,
        "runtime_receipts",
        limits.receipt_detail_limit,
        "",
    )?;
    let rows = query_all(
        connection,
        "select r.receipt_id as receipt_id \
         from runtime_receipts as r \
         where (r.timestamp < ? or (? is not null and r.rowid <= ?)) \
           and not exists ( \
             select 1 from guard_cloud_events as cloud \
             where cloud.idempotency_key = 'receipt.created:' || r.receipt_id \
               and cloud.uploaded_at is null) \
           and not exists ( \
             select 1 from approval_requests as approval \
             where approval.request_id = r.approval_request_id \
               and approval.status = 'pending') \
         order by r.timestamp \
         limit ?",
        &[
            Value::from(limits.cutoff),
            boundary.clone(),
            boundary,
            Value::from(limits.batch_size),
        ],
    )?;
    if rows.is_empty() {
        return Ok(0);
    }
    let ids: Vec<Value> = rows
        .iter()
        .filter_map(|row| row.get("receipt_id").cloned())
        .collect();
    let marks = placeholders(ids.len());
    exec(
        connection,
        &format!("delete from runtime_receipt_envelopes where receipt_id in ({marks})"),
        &ids,
    )?;
    exec(
        connection,
        &format!("delete from receipt_rollup_actions where receipt_id in ({marks})"),
        &ids,
    )?;
    let keys: Vec<Value> = ids
        .iter()
        .map(|id| Value::from(format!("receipt.created:{}", id.as_str().unwrap_or(""))))
        .collect();
    exec(
        connection,
        &format!(
            "delete from guard_cloud_events where uploaded_at is not null and idempotency_key in ({marks})"
        ),
        &keys,
    )?;
    exec(
        connection,
        &format!("delete from runtime_receipts where receipt_id in ({marks})"),
        &ids,
    )
}

fn delete_native_decision_batch(
    connection: &Connection,
    limits: &Limits,
    table: &str,
    batch_size: i64,
) -> StoreResult<i64> {
    let boundary = rowid_boundary(connection, table, limits.receipt_detail_limit, "")?;
    exec(
        connection,
        &format!(
            "delete from {table} where rowid in ( \
               select rowid from {table} \
               where recorded_at < ? or (? is not null and rowid <= ?) \
               order by recorded_at, rowid limit ?)"
        ),
        &[
            Value::from(limits.cutoff),
            boundary.clone(),
            boundary,
            Value::from(batch_size),
        ],
    )
}

fn delete_guard_event_batch(connection: &Connection, limits: &Limits) -> StoreResult<i64> {
    let boundary = rowid_boundary(connection, "guard_events", limits.guard_event_limit, "")?;
    exec(
        connection,
        "delete from guard_events where event_id in ( \
           select event.event_id from guard_events as event \
           where (event.occurred_at < ? or (? is not null and event.rowid <= ?)) \
             and not exists ( \
               select 1 from guard_workflow_capability_receipts as receipt \
               where receipt.event_id = event.event_id) \
             and not exists ( \
               select 1 from guard_workflow_capability_authority_transitions as transition \
               where transition.event_id = event.event_id) \
           order by event.occurred_at limit ?)",
        &[
            Value::from(limits.cutoff),
            boundary.clone(),
            boundary,
            Value::from(limits.batch_size),
        ],
    )
}

fn delete_uploaded_cloud_event_batch(connection: &Connection, limits: &Limits) -> StoreResult<i64> {
    let boundary = rowid_boundary(
        connection,
        "guard_cloud_events",
        limits.uploaded_cloud_event_limit,
        "where uploaded_at is not null",
    )?;
    exec(
        connection,
        "delete from guard_cloud_events where event_id in ( \
           select event_id from guard_cloud_events \
           where uploaded_at is not null \
             and (uploaded_at < ? or (? is not null and rowid <= ?)) \
           order by uploaded_at, occurred_at limit ?)",
        &[
            Value::from(limits.cloud_cutoff),
            boundary.clone(),
            boundary,
            Value::from(limits.batch_size),
        ],
    )
}

fn pragma_int(connection: &Connection, name: &str) -> StoreResult<i64> {
    let row = query_one(connection, &format!("pragma {name}"), &[])?;
    Ok(row.map_or(0, |row| int(&row, name)))
}

/// Return up to `batch_size` free pages to the filesystem when the store uses
/// incremental auto-vacuum; reports how many pages were released.
fn reclaim_free_pages(connection: &Connection, batch_size: i64) -> StoreResult<i64> {
    if pragma_int(connection, "auto_vacuum")? != 2 {
        return Ok(0);
    }
    let before = pragma_int(connection, "freelist_count")?;
    if before <= 0 {
        return Ok(0);
    }
    // Each step releases one page, so the statement must run to completion.
    query_all(
        connection,
        &format!("pragma incremental_vacuum({})", before.min(batch_size)),
        &[],
    )?;
    let after = pragma_int(connection, "freelist_count")?;
    Ok((before - after).max(0))
}
