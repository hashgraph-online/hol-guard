//! The legacy authority envelopes the pack lifecycle migration carries.
//!
//! Port of the SQL reads `catalog_delivery.lifecycle_store.legacy_evidence`
//! ran on its own SQLite connection. Nothing is authenticated here: every
//! record, digest and MAC goes back as stored, and the native lifecycle op
//! authenticates each one before it gives the row any authority.
//!
//! `command_pack_legacy_evidence_rows` answers the committed snapshot, and,
//! for the revision the caller observed in its protected anchor, the pending
//! activation and the transition at that revision. A store without the
//! snapshot table answers `{"state": "schema_missing"}`, as does one that
//! needs the transition table and lacks it; the caller refuses both, as the
//! Python reads failed on the missing table.
//!
//! `command_pack_legacy_history_page` pages the snapshot envelopes of every
//! transition below a revision, newest first. The control history grows by
//! one transition per policy save, so one answer cannot hold it: each page
//! stays inside a byte budget, measured on the encoded reply, and names the
//! cursor of the next page. A single envelope too large for any page is
//! refused rather than sent as a reply the resident would reject.
//!
//! A cell that is not text (or a revision that is not an integer) comes back
//! `null`, so the caller refuses the answer instead of dropping the row.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_each, query_one, Row, StoreError, StoreResult};
use crate::guard_store_local_cli_inventory::table_exists;

const EVIDENCE: &str = "command_pack_legacy_evidence_rows";
const HISTORY: &str = "command_pack_legacy_history_page";
const SNAPSHOT_TABLE: &str = "extension_control_authority_snapshot";
const TRANSITION_TABLE: &str = "extension_control_authority_transition";
const PENDING_TABLE: &str = "extension_command_pack_pending";
/// Encoded item bytes one history page may carry: half the response cap,
/// leaving room for the reply envelope, as the outbox reads do.
pub(crate) const HISTORY_PAGE_BYTES: usize = guard_contracts::MAX_NATIVE_RESPONSE_BYTES / 2;
const HISTORY_PAGE_ROWS: usize = 256;
/// One row past a full page, so a full page knows another one follows.
const HISTORY_QUERY_ROWS: i64 = 257;

pub(crate) fn handles(method: &str) -> bool {
    method == EVIDENCE || method == HISTORY
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    if method == HISTORY {
        return history_page(connection, args);
    }
    evidence(connection, optional_int(args, "observed_revision")?)
}

fn optional_int(args: &Args<'_>, key: &str) -> StoreResult<Option<i64>> {
    match args.raw(key) {
        None => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or(StoreError::Invalid("native_guard_store_args_invalid")),
    }
}

/// The SQL selecting `prefix`'s envelope as text-or-null cells.
fn envelope_columns(prefix: &str) -> String {
    ["json", "digest", "mac"]
        .iter()
        .map(|part| {
            format!(
                "case when typeof({prefix}_{part}) = 'text' then {prefix}_{part} end \
                 as {prefix}_{part}"
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn envelope(row: &Row, prefix: &str) -> Value {
    let mut out = Map::new();
    for (name, part) in [("record", "json"), ("digest", "digest"), ("mac", "mac")] {
        let value = row
            .get(&format!("{prefix}_{part}"))
            .filter(|value| value.is_string())
            .cloned()
            .unwrap_or(Value::Null);
        out.insert(name.to_owned(), value);
    }
    Value::Object(out)
}

fn schema_missing() -> Value {
    json!({"state": "schema_missing"})
}

fn evidence(connection: &Connection, observed: Option<i64>) -> StoreResult<Value> {
    if !table_exists(connection, SNAPSHOT_TABLE)? {
        return Ok(schema_missing());
    }
    let snapshot = query_one(
        connection,
        &format!(
            "select case when typeof(revision) = 'integer' then revision end as revision, {} \
             from {SNAPSHOT_TABLE} where singleton = 1",
            envelope_columns("snapshot")
        ),
        &[],
    )?;
    let mut pending = None;
    if let Some(revision) = observed {
        if table_exists(connection, PENDING_TABLE)? {
            pending = query_one(
                connection,
                &format!(
                    "select {}, {} from {PENDING_TABLE} where control_revision = ?",
                    envelope_columns("record"),
                    envelope_columns("link")
                ),
                &[Value::from(revision)],
            )?;
        }
    }
    let needs_transitions = snapshot.is_some() || pending.is_some();
    if needs_transitions && !table_exists(connection, TRANSITION_TABLE)? {
        return Ok(schema_missing());
    }
    let transition = match (observed, pending.is_some()) {
        (Some(revision), true) => query_one(
            connection,
            &format!(
                "select {}, {} from {TRANSITION_TABLE} where revision = ?",
                envelope_columns("transition"),
                envelope_columns("snapshot")
            ),
            &[Value::from(revision)],
        )?,
        _ => None,
    };
    let snapshot_value = snapshot.map_or(Value::Null, |row| {
        let mut value = envelope(&row, "snapshot");
        if let Value::Object(fields) = &mut value {
            let revision = row
                .get("revision")
                .filter(|value| value.is_i64())
                .cloned()
                .unwrap_or(Value::Null);
            fields.insert("revision".to_owned(), revision);
        }
        value
    });
    let pending_value = pending.map_or(
        Value::Null,
        |row| json!({"activation": envelope(&row, "record"), "link": envelope(&row, "link")}),
    );
    let transition_value = transition.map_or(Value::Null, |row| {
        json!({"transition": envelope(&row, "transition"), "snapshot": envelope(&row, "snapshot")})
    });
    Ok(json!({
        "state": "present",
        "snapshot": snapshot_value,
        "pending": pending_value,
        "transition": transition_value,
    }))
}

fn history_page(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let below = args.int("below_revision")?;
    let limit = match optional_int(args, "before")? {
        Some(before) => before.min(below),
        None => below,
    };
    if !table_exists(connection, TRANSITION_TABLE)? {
        return Ok(schema_missing());
    }
    let mut items = Vec::new();
    let mut spent = 0usize;
    let mut last = Value::Null;
    let mut next = Value::Null;
    // Rows are read one at a time and the walk stops at the first row the
    // page has no room for, so a page never holds envelopes it then drops.
    query_each(
        connection,
        &format!(
            "select revision, {} from {TRANSITION_TABLE} where revision < ? \
             order by revision desc limit ?",
            envelope_columns("snapshot")
        ),
        &[Value::from(limit), Value::from(HISTORY_QUERY_ROWS)],
        |row| {
            let item = envelope(&row, "snapshot");
            let size = item_bytes(&item);
            if size > HISTORY_PAGE_BYTES {
                return Err(StoreError::Invalid(
                    "native_command_pack_history_item_too_large",
                ));
            }
            let full = items.len() >= HISTORY_PAGE_ROWS;
            if !items.is_empty() && (full || spent.saturating_add(size) > HISTORY_PAGE_BYTES) {
                next = last.clone();
                return Ok(false);
            }
            spent = spent.saturating_add(size);
            last = items_cursor(&row);
            items.push(item);
            Ok(true)
        },
    )?;
    Ok(json!({"state": "present", "items": items, "next": next}))
}

/// The revision the next page starts below: the last row this page carried.
fn items_cursor(row: &Row) -> Value {
    row.get("revision")
        .filter(|value| value.is_i64())
        .cloned()
        .unwrap_or(Value::Null)
}

/// The item's encoded length plus its separating comma. The reply is JSON,
/// so every quote and backslash in a record costs two bytes, not one.
fn item_bytes(item: &Value) -> usize {
    serde_json::to_vec(item).map_or(usize::MAX, |bytes| bytes.len().saturating_add(1))
}

#[cfg(test)]
#[path = "guard_store_command_pack_legacy_evidence_tests.rs"]
mod tests;
