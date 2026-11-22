//! `review_policy_memory_rows`: the stored Cloud Review policy-memory cursor a
//! signed memory bundle is checked and planned against, read in one snapshot.
//!
//! Port of `_stored_policy_version` and the registry read in `_memory_plan`
//! in `runtime/review_policy_memory_executor.py`. Python read the policy
//! version row and the rule registry row one after another, each on its own
//! connection, so a memory apply landing between them could pair a version
//! with another bundle's registry. Here both rows are read inside one deferred
//! transaction:
//!
//! - `registry` is the registry row when it holds an object or an array, and
//!   `null` when it is missing or holds another JSON value, as
//!   `get_sync_payload` answered;
//! - `policy_version` is the version row's `policyVersion` with surrounding
//!   whitespace removed, and `null` when the row, the field or the trimmed
//!   text is absent;
//! - a row whose bytes are not UTF-8 JSON is named in `unreadable`, since
//!   `get_sync_payload` raised for it, and the caller refuses the snapshot.

use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};

/// The memory rule registry row.
const REGISTRY_KEY: &str = "guard_review_memory_registry";
/// The last applied memory policy version row.
const VERSION_KEY: &str = "guard_review_memory_policy_version";

/// Whether `method` is the policy-memory snapshot.
pub(crate) fn handles(method: &str) -> bool {
    method == "review_policy_memory_rows"
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    _args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "review_policy_memory_rows" => memory_rows(connection),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

fn memory_rows(connection: &Connection) -> StoreResult<Value> {
    let mut unreadable = Vec::new();
    let registry = match stored_row(connection, REGISTRY_KEY)? {
        Row::Unreadable => {
            unreadable.push("registry");
            Value::Null
        }
        Row::Parsed(payload @ (Value::Object(_) | Value::Array(_))) => payload,
        Row::Missing | Row::Parsed(_) => Value::Null,
    };
    let policy_version = match stored_row(connection, VERSION_KEY)? {
        Row::Unreadable => {
            unreadable.push("policy_version");
            Value::Null
        }
        Row::Parsed(Value::Object(version)) => version
            .get("policyVersion")
            .and_then(Value::as_str)
            .map(python_strip)
            .filter(|text| !text.is_empty())
            .map_or(Value::Null, |text| Value::String(text.to_owned())),
        Row::Missing | Row::Parsed(_) => Value::Null,
    };
    Ok(json!({
        "registry": registry,
        "policy_version": policy_version,
        "unreadable": unreadable,
    }))
}

/// `str.strip()` as Python applies it: Unicode whitespace plus the four
/// information separators Python also counts as space.
fn python_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
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
#[path = "guard_store_review_memory_rows_tests.rs"]
mod tests;
