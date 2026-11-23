//! Whether the first pack activation must send the legacy baseline.
//!
//! Port of the SQL read the first pack activation ran on its own SQLite
//! connection. `command_pack_baseline_retained` answers whether the store
//! already holds the activation slot a pack schema keeps, so the activation
//! need not send the legacy baseline again. A store without the schema
//! tables answers `{"state": "schema_missing"}`, as the SQL read failed there.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_db::{query_one, StoreResult};
use crate::guard_store_local_cli_inventory::table_exists;

const BASELINE: &str = "command_pack_baseline_retained";
const MARKER_TABLE: &str = "extension_control_schema_migration";
const SLOT_TABLE: &str = "extension_command_pack_activation";

pub(crate) fn handles(method: &str) -> bool {
    method == BASELINE
}

pub(crate) fn dispatch(connection: &Connection) -> StoreResult<Value> {
    if !table_exists(connection, MARKER_TABLE)? {
        return Ok(json!({"state": "schema_missing"}));
    }
    let pack_schema = query_one(
        connection,
        &format!(
            "select 1 as found from {MARKER_TABLE} where singleton = 1 \
             and typeof(version) in ('integer', 'real') and version in (5, 6)"
        ),
        &[],
    )?
    .is_some();
    if !pack_schema {
        return Ok(json!({"state": "present", "retained": false}));
    }
    if !table_exists(connection, SLOT_TABLE)? {
        return Ok(json!({"state": "schema_missing"}));
    }
    let slot = query_one(
        connection,
        &format!("select 1 as found from {SLOT_TABLE} where singleton = 1"),
        &[],
    )?;
    Ok(json!({"state": "present", "retained": slot.is_some()}))
}

#[cfg(test)]
#[path = "guard_store_command_pack_baseline_tests.rs"]
mod tests;
