//! The local event log and the bounded `guard.event.v1` upload queue.
//!
//! Queued events wait in `guard_cloud_events` until the cloud sync uploads
//! them. Once the pending queue is full, new events are dropped and the
//! rejection is recorded under the queue capacity state; uploading enough of
//! the backlog marks that state recovered.

use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, query_one, text, StoreError, StoreResult};
use crate::guard_store_json::{dumps_default, py_strip};
use crate::guard_store_receipt_decision::json_object;
use crate::guard_store_receipt_events::{add_guard_event, CAPACITY_KEY};
use crate::guard_store_receipt_reads::reconcile_events;

const ARGS_INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");
const PAYLOAD_INVALID: StoreError = StoreError::Invalid("guard_event_payload_invalid");
const UNENCODABLE: StoreError = StoreError::Invalid("native_guard_store_payload_unencodable");

/// `add_event`: append one entry to the local event log. The caller sends the
/// payload already encoded, so the stored text is exactly what `json.dumps`
/// wrote.
pub(crate) fn add_event(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    exec(
        connection,
        "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
        &[
            Value::from(args.str("event_name")?),
            Value::from(args.str("payload_json")?),
            Value::from(args.str("occurred_at")?),
        ],
    )?;
    Ok(Value::Null)
}

/// `add_guard_event_v1`: queue one event, or record that the queue is full.
pub(crate) fn add(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    let event = Value::Object(args.object("event")?.clone());
    add_guard_event(
        connection,
        &event,
        args.int("event_queue_limit")?,
        args.str("now")?,
    )?;
    Ok(Value::Null)
}

/// `None` for every event, `Some(true)` for uploaded ones and `Some(false)`
/// for the ones still pending.
fn uploaded_filter(args: &Args<'_>) -> StoreResult<&'static str> {
    Ok(match args.raw("uploaded") {
        None => "",
        Some(value) if value.as_bool().ok_or(ARGS_INVALID)? => " where uploaded_at is not null",
        Some(_) => " where uploaded_at is null",
    })
}

fn count_where(connection: &rusqlite::Connection, filter: &str) -> StoreResult<i64> {
    let row = query_one(
        connection,
        &format!("select count(*) as count from guard_cloud_events{filter}"),
        &[],
    )?;
    Ok(row.map_or(0, |row| crate::guard_store_db::int(&row, "count")))
}

/// `count_guard_events_v1`.
pub(crate) fn count(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    Ok(Value::from(count_where(
        connection,
        uploaded_filter(args)?,
    )?))
}

/// `list_guard_events_v1`: settle the pending receipt events first, as
/// `reconcile_receipt_events` does, then read the queue oldest first.
pub(crate) fn list(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    let filter = uploaded_filter(args)?;
    let limit = args.int("limit")?;
    reconcile_events(connection, args)?;
    queued(connection, filter, limit)
}

fn queued(connection: &rusqlite::Connection, filter: &str, limit: i64) -> StoreResult<Value> {
    let rows = query_all(
        connection,
        &format!(
            "select event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at \
             from guard_cloud_events{filter} order by occurred_at asc, event_id asc limit ?"
        ),
        &[Value::from(limit)],
    )?;
    rows.iter()
        .map(|row| {
            let payload = match serde_json::from_str::<Value>(text(row, "payload_json")) {
                Ok(Value::Object(map)) => map,
                Ok(_) => Map::new(),
                Err(_) => return Err(PAYLOAD_INVALID),
            };
            Ok(json!({
                "event_id": text(row, "event_id"),
                "idempotency_key": text(row, "idempotency_key"),
                "event_type": text(row, "event_type"),
                "occurred_at": text(row, "occurred_at"),
                "uploaded_at": row.get("uploaded_at").cloned().unwrap_or(Value::Null),
                "payload": payload,
            }))
        })
        .collect::<StoreResult<Vec<_>>>()
        .map(Value::Array)
}

/// `mark_guard_events_v1_uploaded`: mark the uploaded events and, once the
/// pending queue is back under its limit, record that it recovered.
pub(crate) fn mark_uploaded(
    connection: &rusqlite::Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let ids: Vec<Value> = args
        .strings("event_ids")?
        .ok_or(ARGS_INVALID)?
        .into_iter()
        .filter(|id| !py_strip(id).is_empty())
        .map(Value::from)
        .collect();
    if ids.is_empty() {
        return Ok(Value::from(0));
    }
    let uploaded_at = args.str("uploaded_at")?;
    let queue_limit = args.int("event_queue_limit")?;
    let placeholders = vec!["?"; ids.len()].join(", ");
    let mut params = vec![Value::from(uploaded_at)];
    params.extend(ids);
    let changed = exec(
        connection,
        &format!(
            "update guard_cloud_events set uploaded_at = ? where event_id in ({placeholders})"
        ),
        &params,
    )?;
    let pending = count_where(connection, " where uploaded_at is null")?;
    if pending < queue_limit {
        record_capacity_recovery(connection, pending, uploaded_at)?;
    }
    Ok(Value::from(changed))
}

fn record_capacity_recovery(
    connection: &rusqlite::Connection,
    pending: i64,
    uploaded_at: &str,
) -> StoreResult<()> {
    let Some(row) = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(CAPACITY_KEY)],
    )?
    else {
        return Ok(());
    };
    let mut payload =
        json_object(&Value::String(text(&row, "payload_json").to_owned())).unwrap_or_default();
    payload.insert("exhausted".to_owned(), Value::Bool(false));
    payload.insert("pendingCount".to_owned(), Value::from(pending));
    payload.insert("recoveredAt".to_owned(), Value::from(uploaded_at));
    let encoded = dumps_default(&Value::Object(payload)).ok_or(UNENCODABLE)?;
    exec(
        connection,
        "update sync_state set payload_json = ?, updated_at = ? where state_key = ?",
        &[
            Value::String(encoded),
            Value::from(uploaded_at),
            Value::from(CAPACITY_KEY),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "guard_store_cloud_events_tests.rs"]
mod tests;
