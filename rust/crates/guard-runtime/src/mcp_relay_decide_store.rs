//! Whether the store holds anything a saved lookup could return.
//!
//! The proxy reads saved policy rows, one-shot approvals and the cloud policy
//! bundle for every call. Without any of them each lookup it names misses and
//! the diagnostic has nothing to explain, so the resident can answer those
//! lookups itself. Any saved row, a newer or unknown schema, or a store it
//! cannot read defers the call.

use crate::local_store_read::{
    open_read_only, schema_version, table_exists, STORE_FILE_NAME, SUPPORTED_SCHEMA_VERSION,
};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;

const SAVED_POLICY: &str = "mcp_relay_saved_policy";
const STORE_UNREADABLE: &str = "mcp_relay_store_unreadable";

const ROW_QUERIES: [(&str, &str); 3] = [
    ("policy_decisions", "select 1 from policy_decisions limit 1"),
    (
        "guard_local_once_approvals",
        "select 1 from guard_local_once_approvals limit 1",
    ),
    (
        "sync_state",
        "select 1 from sync_state where state_key = 'policy_bundle' limit 1",
    ),
];

pub(super) fn require_no_saved_policy(guard_home: &Path) -> Result<(), &'static str> {
    let Some(connection) =
        open_read_only(&guard_home.join(STORE_FILE_NAME)).map_err(|_| STORE_UNREADABLE)?
    else {
        // No store yet: nothing is saved.
        return Ok(());
    };
    match schema_version(&connection).map_err(|_| STORE_UNREADABLE)? {
        Some(version) if version <= SUPPORTED_SCHEMA_VERSION => {}
        _ => return Err(STORE_UNREADABLE),
    }
    for (table, query) in ROW_QUERIES {
        if table_exists(&connection, table).map_err(|_| STORE_UNREADABLE)?
            && any_row(&connection, query)?
        {
            return Err(SAVED_POLICY);
        }
    }
    Ok(())
}

fn any_row(connection: &Connection, query: &str) -> Result<bool, &'static str> {
    connection
        .query_row(query, [], |_| Ok(()))
        .optional()
        .map(|found| found.is_some())
        .map_err(|_| STORE_UNREADABLE)
}
