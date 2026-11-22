//! `catalog_recorded_writer_version`: the Guard version that wrote a command
//! catalog, read from the catalog migration events.
//!
//! Port of `recorded_writer_version`, which ran on its own SQLite connection
//! before a catalog migration. The lookup is keyed on the catalog, not on the
//! revision that last moved the store to it: a digest is its contents, so the
//! install that wrote those contents is the one whose controls a migration
//! away from them retires. Only an event written by the migrating install
//! carries a writer version; a backfilled event names none and is skipped.
//!
//! The scan is bounded to the newest 512 migration events, one per revision.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, text, StoreResult};

const MIGRATED_EVENT: &str = "extension_control_authority_catalog_migrated";
const WRITER_LOOKUP_LIMIT: i64 = 512;

pub(crate) fn handles(method: &str) -> bool {
    method == "catalog_recorded_writer_version"
}

/// `{"writer_version": str | null}` for the catalog `catalog_digest` names.
pub(crate) fn dispatch(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let catalog_digest = args.str("catalog_digest")?;
    let rows = query_all(
        connection,
        "select payload_json from guard_events where event_name = ? order by event_id desc limit ?",
        &[
            Value::from(MIGRATED_EVENT),
            Value::from(WRITER_LOOKUP_LIMIT),
        ],
    )?;
    let writer_version = rows.iter().find_map(|row| {
        let Ok(Value::Object(recorded)) = serde_json::from_str::<Value>(text(row, "payload_json"))
        else {
            return None;
        };
        if recorded.get("catalog_digest").and_then(Value::as_str) != Some(catalog_digest) {
            return None;
        }
        recorded
            .get("provenance")
            .and_then(|provenance| provenance.get("writer_version"))
            .and_then(Value::as_str)
            .filter(|version| !version.is_empty())
            .map(str::to_owned)
    });
    Ok(json!({ "writer_version": writer_version }))
}

#[cfg(test)]
#[path = "guard_store_catalog_writer_version_tests.rs"]
mod tests;
