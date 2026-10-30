//! Which approval requests the user has already viewed.
//!
//! The dashboard marks requests read and unread; only the newest
//! `READ_STATE_LIMIT` marks are kept.

use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, text, StoreError, StoreResult};

const READ_STATE_LIMIT: i64 = 50_000;
const ARGS_INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

/// `mark_requests_read`: mark each request read at `now`, then drop the marks
/// past the limit, oldest first.
pub(crate) fn mark_read(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    let ids = args.strings("request_ids")?.ok_or(ARGS_INVALID)?;
    if ids.is_empty() {
        return Ok(Value::Null);
    }
    let now = args.str("now")?;
    let mut seen = std::collections::HashSet::new();
    for id in ids.into_iter().filter(|id| seen.insert(*id)) {
        exec(
            connection,
            "insert into guard_request_read_state (request_id, read_at) values (?, ?) \
             on conflict(request_id) do update set read_at = excluded.read_at",
            &[Value::from(id), Value::from(now)],
        )?;
    }
    exec(
        connection,
        "delete from guard_request_read_state where request_id not in \
         (select request_id from guard_request_read_state order by read_at desc limit ?)",
        &[Value::from(READ_STATE_LIMIT)],
    )?;
    Ok(Value::Null)
}

/// `mark_request_unread`.
pub(crate) fn mark_unread(
    connection: &rusqlite::Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    exec(
        connection,
        "delete from guard_request_read_state where request_id = ?",
        &[Value::from(args.str("request_id")?)],
    )?;
    Ok(Value::Null)
}

/// `get_read_state`: the read request ids, most recently read first.
pub(crate) fn ids(connection: &rusqlite::Connection, _args: &Args<'_>) -> StoreResult<Value> {
    let rows = query_all(
        connection,
        "select request_id from guard_request_read_state order by read_at desc limit ?",
        &[Value::from(READ_STATE_LIMIT)],
    )?;
    Ok(Value::Array(
        rows.iter()
            .map(|row| Value::from(text(row, "request_id")))
            .collect(),
    ))
}

/// `clear_read_state`.
pub(crate) fn clear(connection: &rusqlite::Connection, _args: &Args<'_>) -> StoreResult<Value> {
    exec(connection, "delete from guard_request_read_state", &[])?;
    Ok(Value::Null)
}

#[cfg(test)]
#[path = "guard_store_read_state_tests.rs"]
mod tests;
