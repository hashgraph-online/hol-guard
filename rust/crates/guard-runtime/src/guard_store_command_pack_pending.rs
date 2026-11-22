//! The pending command-pack activation records, read for cache cleanup.
//!
//! Port of the `extension_command_pack_pending` read the offline cache
//! cleanup ran on its own SQLite connection. Nothing is authenticated here:
//! each record, digest and MAC goes back as stored, ordered by control
//! revision, and the lifecycle op authenticates them before they keep any
//! cached pack. A store without the pending table has none. A cell that is
//! not text comes back `null` so the caller refuses the answer instead of
//! dropping the row.
//!
//! Nothing caps how many activations may be pending, so one reply cannot
//! promise to hold them all. The read is paged in revision order: each page
//! stays inside the byte budget the history pages use and names the revision
//! the next page starts after. The caller reads every page before it evicts
//! anything. A single record too large for any page is refused rather than
//! sent as a reply the resident would reject.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::command_pack_legacy_evidence::{item_bytes, HISTORY_PAGE_BYTES};
use crate::guard_store_args::Args;
use crate::guard_store_db::{query_each, Row, StoreError, StoreResult};
use crate::guard_store_local_cli_inventory::table_exists;

const METHOD: &str = "list_command_pack_pending_records";
const FIELDS: [&str; 3] = ["record_json", "record_digest", "record_mac"];
const PAGE_ROWS: usize = 256;
/// One row past a full page, so a full page knows another one follows.
const QUERY_ROWS: i64 = 257;

pub(crate) fn handles(method: &str) -> bool {
    method == METHOD
}

pub(crate) fn dispatch(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let after = match args.raw("after_revision") {
        None => 0,
        Some(value) => value
            .as_i64()
            .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))?,
    };
    if !table_exists(connection, "extension_command_pack_pending")? {
        return Ok(json!({"items": [], "next": null}));
    }
    let mut items = Vec::new();
    let mut spent = 0usize;
    let mut last = Value::Null;
    let mut next = Value::Null;
    // Rows are read one at a time and the walk stops at the first row the
    // page has no room for, so a page never holds records it then drops.
    query_each(
        connection,
        "select control_revision, \
                case when typeof(record_json) = 'text' then record_json end as record_json, \
                case when typeof(record_digest) = 'text' then record_digest end as record_digest, \
                case when typeof(record_mac) = 'text' then record_mac end as record_mac \
         from extension_command_pack_pending where control_revision > ? \
         order by control_revision limit ?",
        &[Value::from(after), Value::from(QUERY_ROWS)],
        |row| {
            let item = record(&row);
            let size = item_bytes(&item);
            if size > HISTORY_PAGE_BYTES {
                return Err(StoreError::Invalid(
                    "native_command_pack_pending_item_too_large",
                ));
            }
            let full = items.len() >= PAGE_ROWS;
            if !items.is_empty() && (full || spent.saturating_add(size) > HISTORY_PAGE_BYTES) {
                next = last.clone();
                return Ok(false);
            }
            spent = spent.saturating_add(size);
            last = row
                .get("control_revision")
                .filter(|value| value.is_i64())
                .cloned()
                .unwrap_or(Value::Null);
            items.push(item);
            Ok(true)
        },
    )?;
    Ok(json!({"items": items, "next": next}))
}

fn record(row: &Row) -> Value {
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
}

#[cfg(test)]
#[path = "guard_store_command_pack_pending_tests.rs"]
mod tests;
