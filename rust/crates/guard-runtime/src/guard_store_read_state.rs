//! Which approval requests the user has already viewed.
//!
//! The dashboard marks requests read and unread; only the newest
//! `READ_STATE_LIMIT` marks are kept. A read of the marks fits in one native
//! store response: it returns a page and a cursor after its last mark, and
//! the caller reads on from there until no cursor comes back.

use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, text, StoreError, StoreResult};

const READ_STATE_LIMIT: i64 = 50_000;

/// The most marks one read returns.
const PAGE_ROWS: i64 = 5_000;

/// Half the 2 MiB response limit, which leaves room for the envelope.
const READ_BYTES_BUDGET: usize = 1024 * 1024;
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

/// `get_read_state`: one page of the read request ids, most recently read
/// first, and the `[read_at, rowid]` to read on from, or null on the last
/// page. Marks read at the same time come in rowid order, which the
/// `read_at` index already carries.
pub(crate) fn ids(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    let (clause, mut params) = match args.raw("after") {
        None | Some(Value::Null) => ("", Vec::new()),
        Some(Value::Array(pair)) => match pair.as_slice() {
            [Value::String(read_at), Value::Number(rowid)] => (
                "where read_at <= ? and (read_at < ? or rowid > ?)",
                vec![
                    Value::from(read_at.as_str()),
                    Value::from(read_at.as_str()),
                    Value::from(rowid.as_i64().ok_or(ARGS_INVALID)?),
                ],
            ),
            _ => return Err(ARGS_INVALID),
        },
        Some(_) => return Err(ARGS_INVALID),
    };
    params.push(Value::from(PAGE_ROWS));
    let rows = query_all(
        connection,
        &format!(
            "select request_id, read_at, rowid as row_order from guard_request_read_state \
             {clause} order by read_at desc, rowid asc limit ?"
        ),
        &params,
    )?;
    let full = rows.len() as i64 == PAGE_ROWS;
    let mut page = Vec::new();
    let mut size = 0;
    let mut after = Value::Null;
    for row in &rows {
        let id = text(row, "request_id");
        if !page.is_empty() && size + id.len() > READ_BYTES_BUDGET {
            break;
        }
        size += id.len();
        page.push(Value::from(id));
        after = json!([
            text(row, "read_at"),
            row.get("row_order").cloned().unwrap_or(Value::Null)
        ]);
    }
    if page.len() == rows.len() && !full {
        after = Value::Null;
    }
    Ok(json!({"ids": page, "after": after}))
}

/// `clear_read_state`.
pub(crate) fn clear(connection: &rusqlite::Connection, _args: &Args<'_>) -> StoreResult<Value> {
    exec(connection, "delete from guard_request_read_state", &[])?;
    Ok(Value::Null)
}

#[cfg(test)]
#[path = "guard_store_read_state_tests.rs"]
mod tests;
