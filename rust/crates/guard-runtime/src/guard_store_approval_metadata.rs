//! Small approval request metadata reads and the desktop notification
//! marker: `GuardStore.get_approval_extension_allow_hint`,
//! `approval_desktop_notified_at`, `mark_approval_desktop_notified` and
//! `oldest_approval_request_created_at`.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_approval_read_rows::json_object;
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, query_one, StoreResult};

/// `get_approval_extension_allow_hint`: the private queue-time hint as an
/// object, or `None` when the row, the column (a store from before it
/// existed) or an object-valued cell is missing. A BLOB cell reads as NULL:
/// Python decoded `str(bytes)`, which is never a JSON object.
pub(crate) fn get_approval_extension_allow_hint(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let has_column = query_all(connection, "pragma table_info(approval_requests)", &[])?
        .iter()
        .any(|column| {
            column.get("name").and_then(Value::as_str) == Some("extension_allow_hint_json")
        });
    if !has_column {
        return Ok(Value::Null);
    }
    match query_one(
        connection,
        "select case when typeof(extension_allow_hint_json) = 'blob' then null \
         else extension_allow_hint_json end as extension_allow_hint_json \
         from approval_requests where request_id = ?",
        &[Value::from(args.str("request_id")?)],
    )? {
        Some(row) => json_object(&row, "extension_allow_hint_json"),
        None => Ok(Value::Null),
    }
}

/// `approval_desktop_notified_at`: the stored marker when it is a non-empty
/// string. A request in a `connector:<identity>:<action>` group also reads
/// the earliest marker of another pending request for the same connector
/// identity, so setting up one connector raises one notice however many of
/// its commands are waiting.
pub(crate) fn approval_desktop_notified_at(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select coalesce(nullif(own.desktop_notified_at, ''), ( \
           select min(nullif(other.desktop_notified_at, '')) from approval_requests other \
           where own.queue_group_id like 'connector:%' \
             and instr(substr(own.queue_group_id, 11), ':') > 1 \
             and other.status = 'pending' and other.request_id != own.request_id \
             and other.oauth_source is own.oauth_source \
             and substr(other.queue_group_id, 1, 10 + instr(substr(own.queue_group_id, 11), ':')) \
               = substr(own.queue_group_id, 1, 10 + instr(substr(own.queue_group_id, 11), ':')) \
         )) as desktop_notified_at \
         from approval_requests own where own.request_id = ?",
        &[Value::from(args.str("request_id")?)],
    )?;
    Ok(non_empty_text(
        row.as_ref().and_then(|row| row.get("desktop_notified_at")),
    ))
}

/// `mark_approval_desktop_notified`: sets the marker once; a request already
/// marked keeps its first time.
pub(crate) fn mark_approval_desktop_notified(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    exec(
        connection,
        "update approval_requests set desktop_notified_at = ? \
         where request_id = ? and desktop_notified_at is null",
        &[
            Value::from(args.str("notified_at")?),
            Value::from(args.str("request_id")?),
        ],
    )?;
    Ok(Value::Null)
}

/// `oldest_approval_request_created_at(status)`: SQLite's `min(created_at)`
/// over the status when it is a non-empty string.
pub(crate) fn oldest_approval_request_created_at(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select min(created_at) as oldest_created_at from approval_requests where status = ?",
        &[Value::from(args.str("status")?)],
    )?;
    Ok(non_empty_text(
        row.as_ref().and_then(|row| row.get("oldest_created_at")),
    ))
}

/// `str(value) if isinstance(value, str) and value else None`.
fn non_empty_text(cell: Option<&Value>) -> Value {
    match cell {
        Some(Value::String(text)) if !text.is_empty() => Value::String(text.clone()),
        _ => Value::Null,
    }
}

#[cfg(all(test, unix))]
#[path = "guard_store_approval_metadata_tests.rs"]
mod tests;
