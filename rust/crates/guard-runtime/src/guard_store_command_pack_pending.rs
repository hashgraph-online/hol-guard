//! The pending command-pack activation records, read for cache cleanup.
//!
//! Port of the `extension_command_pack_pending` read the offline cache
//! cleanup ran on its own SQLite connection. Nothing is authenticated here:
//! each record, digest and MAC goes back as stored, ordered by control
//! revision, and the lifecycle op authenticates them before they keep any
//! cached pack. A store without the pending table has none. A cell that is
//! not text comes back `null` so the caller refuses the answer instead of
//! dropping the row.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_db::{query_all, StoreResult};
use crate::guard_store_local_cli_inventory::table_exists;

const METHOD: &str = "list_command_pack_pending_records";
const FIELDS: [&str; 3] = ["record_json", "record_digest", "record_mac"];

pub(crate) fn handles(method: &str) -> bool {
    method == METHOD
}

pub(crate) fn dispatch(connection: &Connection) -> StoreResult<Value> {
    if !table_exists(connection, "extension_command_pack_pending")? {
        return Ok(json!({"items": []}));
    }
    let rows = query_all(
        connection,
        "select case when typeof(record_json) = 'text' then record_json end as record_json, \
                case when typeof(record_digest) = 'text' then record_digest end as record_digest, \
                case when typeof(record_mac) = 'text' then record_mac end as record_mac \
         from extension_command_pack_pending order by control_revision",
        &[],
    )?;
    let items: Vec<Value> = rows
        .iter()
        .map(|row| {
            let record: Map<String, Value> = FIELDS
                .iter()
                .map(|name| {
                    (
                        (*name).to_owned(),
                        row.get(*name).cloned().unwrap_or(Value::Null),
                    )
                })
                .collect();
            Value::Object(record)
        })
        .collect();
    Ok(json!({"items": items}))
}

#[cfg(test)]
#[path = "guard_store_command_pack_pending_tests.rs"]
mod tests;
