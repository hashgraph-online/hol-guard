//! `get_raw_approval_request_snapshot`: one stored approval request row with
//! every column as SQLite holds it, before any projection or scope contract.
//! The exact Guard Cloud review path compares it with the projected request,
//! so a projection can never hide a stored field.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_one, StoreResult};

/// The stored row for `request_id`, or `null` when there is none.
pub(crate) fn get(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select * from approval_requests where request_id = ?",
        &[Value::from(args.str("request_id")?)],
    )?;
    Ok(row.map_or(Value::Null, Value::Object))
}

#[cfg(test)]
#[path = "guard_store_approval_raw_row_tests.rs"]
mod tests;
