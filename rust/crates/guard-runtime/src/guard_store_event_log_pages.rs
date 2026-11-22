//! `list_events`: the local event log, newest first, one bounded page at a
//! time.
//!
//! A caller may ask for thousands of events, more than one native reply can
//! carry. Each page stops once its stored payload text passes
//! [`PAGE_PAYLOAD_BYTES`] and says whether more rows remain; the caller reads
//! again from the last event it received. The cursor is the
//! `(occurred_at, event_id)` pair the log is ordered by, so an event appended
//! between pages never repeats or shifts an older one.
//!
//! The payload comes back as its stored text so the caller parses it with
//! the key order it was written with.

use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, text, value_error, StoreResult};

/// Stored payload bytes one page carries before it stops: a quarter of the
/// 2 MiB reply limit, so even payload text whose every byte must be escaped
/// again leaves room for the other fields and the envelope. The first row of
/// a page is always included so every page makes progress.
pub(crate) const PAGE_PAYLOAD_BYTES: usize = 512 * 1024;

pub(crate) fn list_events(
    connection: &rusqlite::Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let limit = args.int("limit")?;
    let mut sql = String::from(
        "select event_id, event_name, payload_json, occurred_at from guard_events where 1 = 1",
    );
    let mut params = Vec::new();
    if let Some(event_name) = args.opt_str("event_name")? {
        sql.push_str(" and event_name = ?");
        params.push(Value::from(event_name));
    }
    if let Some(before) = args.opt_object("before")? {
        let (Some(occurred_at), Some(event_id)) = (
            before.get("occurred_at").and_then(Value::as_str),
            before.get("event_id").and_then(Value::as_i64),
        ) else {
            return value_error("before must name an occurred_at and an event_id");
        };
        sql.push_str(" and (occurred_at, event_id) < (?, ?)");
        params.push(Value::from(occurred_at));
        params.push(Value::from(event_id));
    }
    sql.push_str(" order by occurred_at desc, event_id desc limit ?");
    params.push(Value::from(limit));
    let rows = query_all(connection, &sql, &params)?;
    let mut items = Vec::new();
    let mut payload_bytes = 0usize;
    for row in &rows {
        let payload_json = text(row, "payload_json");
        if !items.is_empty() && payload_bytes + payload_json.len() > PAGE_PAYLOAD_BYTES {
            return Ok(json!({"items": items, "more": true}));
        }
        payload_bytes += payload_json.len();
        items.push(json!({
            "event_id": row.get("event_id").cloned().unwrap_or(Value::Null),
            "event_name": text(row, "event_name"),
            "occurred_at": text(row, "occurred_at"),
            "payload_json": payload_json,
        }));
    }
    Ok(json!({"items": items, "more": false}))
}

#[cfg(test)]
#[path = "guard_store_event_log_pages_tests.rs"]
mod tests;
