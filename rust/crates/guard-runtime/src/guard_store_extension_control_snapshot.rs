//! The committed extension-control snapshot's layers, read before recovery.
//!
//! Port of the snapshot reads `_restore_missing_snapshot_before_recovery` and
//! `_note_controls_lost_by_reset` ran on their own SQLite connection after the
//! schema check. The answer is `{"snapshot": null}` when there is no snapshot
//! row (or no snapshot table yet), and otherwise `{"snapshot": {"layers_json":
//! text}}`. A layers cell that is not text answers `null` in its place so the
//! caller counts no controls instead of failing the reset.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_db::{query_one, StoreResult};
use crate::guard_store_local_cli_inventory::table_exists;

const METHOD: &str = "extension_control_snapshot_layers";

pub(crate) fn handles(method: &str) -> bool {
    method == METHOD
}

pub(crate) fn dispatch(connection: &Connection) -> StoreResult<Value> {
    if !table_exists(connection, "extension_control_authority_snapshot")? {
        return Ok(json!({"snapshot": null}));
    }
    let row = query_one(
        connection,
        "select case when typeof(layers_json) = 'text' then layers_json end as layers_json \
         from extension_control_authority_snapshot where singleton = 1",
        &[],
    )?;
    Ok(match row {
        None => json!({"snapshot": null}),
        Some(row) => {
            let layers = row
                .get("layers_json")
                .filter(|value| value.is_string())
                .cloned()
                .unwrap_or(Value::Null);
            json!({"snapshot": {"layers_json": layers}})
        }
    })
}

#[cfg(test)]
#[path = "guard_store_extension_control_snapshot_tests.rs"]
mod tests;
