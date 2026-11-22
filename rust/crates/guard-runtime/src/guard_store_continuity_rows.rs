//! `custom_extension_continuity_rows`: the store values a custom Extension
//! continuity plan or local mutation is built from, read in one snapshot.
//!
//! Port of the reads at the top of `prepare_verified_custom_extension_continuity`
//! and `record_local_custom_extension_mutation` in
//! `runtime/custom_extension_continuity.py`. Python read the local CLI
//! authority revision, the continuity state row and the local removals row one
//! after another, each on its own connection, so a commit between two reads
//! could pair a revision with rows from a different moment. Here all three are
//! read inside one deferred transaction:
//!
//! - the revision is `local_cli_authority.revision`, zero when nothing is
//!   recorded yet, and a stored value that is not a whole number is refused;
//! - a row that is an object or an array comes back as stored, a missing row
//!   or one holding another JSON value comes back as `null`, as
//!   `get_sync_payload` answered;
//! - a row whose bytes are not UTF-8 JSON is named in `unreadable`, since
//!   `get_sync_payload` raised for it, and the caller refuses the snapshot.

use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_local_cli_inventory::authority_revision;

/// The continuity state row.
const STATE_KEY: &str = "custom_extension_continuity";
/// The local removals row.
const REMOVALS_KEY: &str = "custom_extension_continuity_local_removals";

/// Whether `method` is the continuity snapshot.
pub(crate) fn handles(method: &str) -> bool {
    method == "custom_extension_continuity_rows"
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    _args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "custom_extension_continuity_rows" => continuity_rows(connection),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

fn continuity_rows(connection: &Connection) -> StoreResult<Value> {
    let revision = authority_revision(connection)?;
    let mut unreadable = Vec::new();
    let mut read = |role: &'static str, key: &str| -> StoreResult<Value> {
        Ok(match stored_row(connection, key)? {
            Row::Missing => Value::Null,
            Row::Unreadable => {
                unreadable.push(role);
                Value::Null
            }
            Row::Parsed(payload @ (Value::Object(_) | Value::Array(_))) => payload,
            Row::Parsed(_) => Value::Null,
        })
    };
    let state = read("state", STATE_KEY)?;
    let removals = read("removals", REMOVALS_KEY)?;
    Ok(json!({
        "revision": revision,
        "state": state,
        "removals": removals,
        "unreadable": unreadable,
    }))
}

/// One `sync_state` row as the snapshot sees it.
enum Row {
    Missing,
    Unreadable,
    Parsed(Value),
}

/// Read `key` as bytes so a BLOB or invalid UTF-8 cell is judged here, as
/// unreadable, rather than failing the decoder.
fn stored_row(connection: &Connection, key: &str) -> StoreResult<Row> {
    let row: Option<Option<Vec<u8>>> = connection
        .query_row(
            "select cast(payload_json as blob) from sync_state where state_key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match row {
        None => Row::Missing,
        Some(bytes) => bytes
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .map_or(Row::Unreadable, Row::Parsed),
    })
}

#[cfg(test)]
#[path = "guard_store_continuity_rows_tests.rs"]
mod tests;
