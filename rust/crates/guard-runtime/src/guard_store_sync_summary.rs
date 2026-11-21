//! `record_sync_summary`: the rows a successful cloud sync writes.
//!
//! The caller passes the summary already encoded, so the stored
//! `sync_summary` row keeps the text the runner wrote before. The summary row
//! and the connect state's first-sync proof run in the one store write, so a
//! reader never sees the new summary beside a connect state that still waits
//! for its first sync.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};
use crate::guard_store_sync_state::write_encoded;

const SUMMARY: &str = "sync_summary";

/// The `record_sync_summary` store method.
///
/// `persist_summary` writes the `sync_summary` row; `record_connect` marks the
/// latest connect state as synced, with the summary as its proof. The answer
/// is the connect state that call returns, or `null` when it was not asked
/// for or no connect state was found.
pub(crate) fn method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let text = args.str("summary_json")?;
    let Ok(Value::Object(summary)) = serde_json::from_str::<Value>(text) else {
        return value_error("invalid_payload");
    };
    let now = args.str("now")?;
    if args.flag("persist_summary")? {
        write_encoded(connection, SUMMARY, text, now)?;
    }
    if !args.flag("record_connect")? {
        return Ok(Value::Null);
    }
    let request = json!({
        "status": "connected",
        "milestone": "first_sync_succeeded",
        "now": now,
        "reason": null,
        "request_id": null,
        "sync_payload": Value::Object(summary),
    });
    let request: &Map<String, Value> = request
        .as_object()
        .map_or_else(|| value_error("invalid_payload"), Ok)?;
    crate::guard_store_connect::record_sync_result(connection, &Args(request))
}

#[cfg(test)]
#[path = "guard_store_sync_summary_tests.rs"]
mod tests;
