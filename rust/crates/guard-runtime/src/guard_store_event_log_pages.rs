//! `list_events`: the local event log, newest first, one bounded page at a
//! time.
//!
//! A caller may ask for thousands of events, more than one native reply can
//! carry. Each page stops once its encoded payload text passes
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

/// Encoded payload bytes one page carries before it stops: a quarter of the
/// 2 MiB reply limit, leaving room for the other fields and the envelope. The
/// first row of a page is always included so every page makes progress.
pub(crate) const PAGE_PAYLOAD_BYTES: usize = 512 * 1024;

/// A stored payload whose encoded text passes this bound can never fit one
/// reply beside its row fields, so it reads as `{}` instead. Nothing bounds
/// the payload `append_event` writes, and one such row must not stop every
/// later read of the log.
pub(crate) const ROW_PAYLOAD_BYTES: usize = 1024 * 1024;

const OVERSIZED_PAYLOAD: &str = "{}";

/// One bounded page of the log. With `after_event_id` the page reads oldest
/// first past that id, and the caller continues from the last id it got.
/// Otherwise it reads newest first and continues from the `before` cursor.
/// `event_name` and `event_names` narrow either read.
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
    if let Some(names) = args
        .strings("event_names")?
        .filter(|names| !names.is_empty())
    {
        sql.push_str(" and event_name in (");
        sql.push_str(&vec!["?"; names.len()].join(", "));
        sql.push(')');
        params.extend(names.into_iter().map(Value::from));
    }
    let after = match args.raw("after_event_id") {
        None => None,
        Some(value) => match value.as_i64() {
            Some(event_id) => Some(event_id),
            None => return value_error("after_event_id must be a whole number"),
        },
    };
    let before = args.opt_object("before")?;
    if after.is_some() && before.is_some() {
        return value_error("a page reads either after an event id or before a cursor");
    }
    if let Some(event_id) = after {
        sql.push_str(" and event_id > ? order by event_id asc limit ?");
        params.push(Value::from(event_id));
    } else {
        if let Some(before) = before {
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
    }
    params.push(Value::from(limit));
    let rows = query_all(connection, &sql, &params)?;
    let mut items = Vec::new();
    let mut payload_bytes = 0usize;
    for row in &rows {
        let mut payload_json = text(row, "payload_json");
        let mut encoded = encoded_len(payload_json);
        if encoded > ROW_PAYLOAD_BYTES {
            payload_json = OVERSIZED_PAYLOAD;
            encoded = encoded_len(payload_json);
        }
        if !items.is_empty() && payload_bytes + encoded > PAGE_PAYLOAD_BYTES {
            return Ok(json!({"items": items, "more": true}));
        }
        payload_bytes += encoded;
        items.push(json!({
            "event_id": row.get("event_id").cloned().unwrap_or(Value::Null),
            "event_name": text(row, "event_name"),
            "occurred_at": text(row, "occurred_at"),
            "payload_json": payload_json,
        }));
    }
    Ok(json!({"items": items, "more": false}))
}

/// The length of `text` once encoded as a JSON string in the reply, where
/// quotes, backslashes and control characters grow.
fn encoded_len(text: &str) -> usize {
    serde_json::to_string(text).map_or(usize::MAX, |encoded| encoded.len())
}

#[cfg(test)]
#[path = "guard_store_event_log_pages_tests.rs"]
mod tests;
