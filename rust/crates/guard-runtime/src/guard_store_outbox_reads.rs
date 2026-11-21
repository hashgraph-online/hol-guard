//! Byte-bounded Review outbox reads.
//!
//! The resident rejects replies above `MAX_NATIVE_RESPONSE_BYTES`, and a reply
//! that cannot be sent leaves the caller retrying the same rows forever. Both
//! reads therefore return a prefix of their ordered result that stays under a
//! budget well below the cap, and always make progress:
//!
//! * `list_ready` returns at least one row when it fits. A row that cannot fit
//!   alone is returned by itself without its payload, flagged
//!   `payload_oversized`, so the caller can dead-letter it like any event over
//!   the upload limit instead of looping on it.
//! * `list_snapshots` pages with a cursor. A snapshot that cannot fit alone
//!   can never have been part of an uploadable event; it is skipped and
//!   counted.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, StoreError, StoreResult};
use crate::guard_store_outbox_decode::decode_stored_event;
use crate::guard_store_outbox_queries::optional_identity;
use crate::MAX_NATIVE_RESPONSE_BYTES;

/// Target size of one reply's rows: half the transport cap, leaving room for
/// the envelope and for text that grows when re-encoded.
const REPLY_BUDGET_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES / 2;
/// Largest single row that may be sent alone.
const SINGLE_ROW_LIMIT_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES - 64 * 1024;
const SNAPSHOT_PAGE_ROWS: i64 = 256;

fn encoded_len(value: &Value) -> usize {
    // One byte for the separating comma.
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len().saturating_add(1))
}

pub(crate) fn list_ready(connection: &Connection, source: &str, args: &Args) -> StoreResult<Value> {
    let mut query = String::from(
        "select stream_sequence, event_id, local_request_id, request_sequence, \
         event_type, event_schema_version, payload_json, payload_hash, \
         occurred_at, oauth_source, oauth_subject_hash, workspace_id, \
         machine_id, machine_installation_id, attempt_count \
         from guard_review_outbox_events \
         where oauth_source = ? and binding_status = 'ready' and acknowledged_at is null \
         and (next_attempt_at is null or next_attempt_at <= ?)",
    );
    let mut params = vec![Value::from(source), Value::from(args.str("now")?)];
    if let Some(binding) = optional_identity(args)? {
        query.push_str(
            " and oauth_subject_hash = ? and workspace_id = ? \
             and machine_id = ? and machine_installation_id = ?",
        );
        params.extend(binding.values());
    }
    query.push_str(" order by stream_sequence asc limit ?");
    params.push(Value::from(args.int("limit")?.max(1)));
    let rows = query_all(connection, &query, &params)?;
    let mut events: Vec<Value> = Vec::new();
    let mut used: usize = 2;
    for row in &rows {
        let event = ready_event(row);
        let size = encoded_len(&event);
        if events.is_empty() && size > SINGLE_ROW_LIMIT_BYTES {
            events.push(oversized_event(event, size));
            break;
        }
        if !events.is_empty() && used.saturating_add(size) > REPLY_BUDGET_BYTES {
            break;
        }
        used = used.saturating_add(size);
        events.push(event);
    }
    Ok(Value::Array(events))
}

fn ready_event(row: &crate::guard_store_db::Row) -> Value {
    let null = Value::Null;
    let field = |name: &str| row.get(name).unwrap_or(&null).clone();
    json!({
        "sequence": field("stream_sequence"),
        "stream_sequence": field("stream_sequence"),
        "event_id": field("event_id"),
        "local_request_id": field("local_request_id"),
        "request_sequence": field("request_sequence"),
        "event_type": field("event_type"),
        "event_schema_version": field("event_schema_version"),
        "payload_json": field("payload_json"),
        "payload_hash": field("payload_hash"),
        "changed_at": field("occurred_at"),
        "oauth_source": field("oauth_source"),
        "oauth_subject_hash": field("oauth_subject_hash"),
        "workspace_id": field("workspace_id"),
        "machine_id": field("machine_id"),
        "machine_installation_id": field("machine_installation_id"),
        "attempt_count": field("attempt_count"),
    })
}

/// The event's identity and ordering without its payload.
fn oversized_event(mut event: Value, payload_bytes: usize) -> Value {
    if let Some(map) = event.as_object_mut() {
        map.insert("payload_json".into(), Value::from(""));
        map.insert("payload_oversized".into(), Value::Bool(true));
        map.insert("payload_bytes".into(), Value::from(payload_bytes as u64));
    }
    event
}

fn cursor_position(row: &crate::guard_store_db::Row) -> Value {
    json!({
        "request_sequence": row.get("request_sequence").cloned().unwrap_or(Value::Null),
        "stream_sequence": row.get("stream_sequence").cloned().unwrap_or(Value::Null),
    })
}

fn after_clause(args: &Args, params: &mut Vec<Value>) -> StoreResult<&'static str> {
    let Some(cursor) = args.opt_object("after")? else {
        return Ok("");
    };
    let invalid = StoreError::Invalid("native_guard_store_args_invalid");
    let stream = cursor
        .get("stream_sequence")
        .and_then(Value::as_i64)
        .ok_or(invalid)?;
    match cursor.get("request_sequence") {
        Some(Value::Number(number)) => {
            let request = number
                .as_i64()
                .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))?;
            params.extend([
                Value::from(request),
                Value::from(request),
                Value::from(stream),
            ]);
            // Rows after the cursor in `request_sequence desc, stream_sequence desc`
            // order; NULL request sequences sort last.
            Ok(
                " and (request_sequence < ? or (request_sequence = ? and stream_sequence < ?) \
                 or request_sequence is null)",
            )
        }
        Some(Value::Null) => {
            params.push(Value::from(stream));
            Ok(" and request_sequence is null and stream_sequence < ?")
        }
        _ => Err(StoreError::Invalid("native_guard_store_args_invalid")),
    }
}

/// One page of decoded, authenticated snapshots of a request, newest first.
/// `next` is the cursor of the last row consumed, or null when exhausted.
pub(crate) fn list_snapshots(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let mut params = vec![Value::from(args.str("request_id")?), Value::from(source)];
    let after = after_clause(args, &mut params)?;
    params.push(Value::from(SNAPSHOT_PAGE_ROWS));
    let rows = query_all(
        connection,
        &format!(
            "select stream_sequence, event_id, local_request_id, request_sequence, \
             event_type, event_schema_version, payload_json, payload_hash, \
             occurred_at, oauth_source, oauth_subject_hash, workspace_id, \
             machine_id, machine_installation_id \
             from guard_review_outbox_events \
             where local_request_id = ? and oauth_source = ? and binding_status = 'ready'{after} \
             order by request_sequence desc, stream_sequence desc limit ?"
        ),
        &params,
    )?;
    let mut snapshots: Vec<Value> = Vec::new();
    let mut skipped_oversized = 0_u64;
    let mut used: usize = 2;
    let mut consumed = 0;
    for row in &rows {
        if let Some(event) = decode_stored_event(row) {
            let snapshot = Value::Object(event.snapshot);
            let size = encoded_len(&snapshot);
            if snapshots.is_empty() && size > SINGLE_ROW_LIMIT_BYTES {
                skipped_oversized += 1;
            } else if !snapshots.is_empty() && used.saturating_add(size) > REPLY_BUDGET_BYTES {
                break;
            } else {
                used = used.saturating_add(size);
                snapshots.push(snapshot);
            }
        }
        consumed += 1;
    }
    let more = consumed < rows.len() || rows.len() as i64 == SNAPSHOT_PAGE_ROWS;
    let next = match consumed.checked_sub(1).and_then(|last| rows.get(last)) {
        Some(row) if more => cursor_position(row),
        _ => Value::Null,
    };
    Ok(json!({
        "snapshots": snapshots,
        "next": next,
        "skipped_oversized": skipped_oversized,
    }))
}
