//! `policy_activation_view`: everything a policy-bundle activation is checked
//! against, read as one view.
//!
//! The activation decides in Python whether a bundle may replace the one in
//! force, then asks the resident to write it only while every observed value
//! is still the one read here. It reads:
//!
//! - each named `sync_state` row as its stored text (`null` when absent), so
//!   the observed values the resident compares are byte-for-byte the stored
//!   ones;
//! - the extension-control authority snapshot's revision and digest;
//! - every remote-source policy row, in the column order the resident
//!   writes, so an activation that changes no enforcement can leave the fence
//!   open.
//!
//! The key list must hold 1 to [`MAX_KEYS`] distinct, non-empty keys.

use guard_policy_snapshot::policy_integrity::REMOTE_POLICY_SOURCES;
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, StoreError, StoreResult};

/// The most `sync_state` rows one view reads.
const MAX_KEYS: usize = 16;

const KEYS_INVALID: StoreError = StoreError::Invalid("native_policy_activation_view_keys_invalid");

/// The remote-row columns, in the order the resident inserts them.
const ROW_COLUMNS: [&str; 18] = [
    "harness",
    "scope",
    "artifact_id",
    "artifact_hash",
    "workspace",
    "publisher",
    "action",
    "reason",
    "owner",
    "source",
    "expires_at",
    "updated_at",
    "integrity_version",
    "integrity_generation",
    "payload_hash",
    "payload_mac",
    "integrity_key_id",
    "signed_at",
];

pub(super) fn policy_activation_view(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let keys = keys(args)?;
    let mut sync_state = Map::new();
    for key in keys {
        let row = query_one(
            connection,
            "select payload_json from sync_state where state_key = ?",
            &[json!(key)],
        )?;
        let text = row.and_then(|row| row.get("payload_json").cloned());
        let text = match text {
            None | Some(Value::Null) => Value::Null,
            Some(text @ Value::String(_)) => text,
            Some(_) => return Err(StoreError::Invalid("native_guard_store_cell_invalid")),
        };
        sync_state.insert(key.to_owned(), text);
    }
    let authority = query_one(
        connection,
        "select revision, snapshot_digest from extension_control_authority_snapshot \
         where singleton = 1",
        &[],
    )?;
    Ok(json!({
        "sync_state": sync_state,
        "authority": authority,
        "remote_rows": remote_rows(connection)?,
    }))
}

fn keys<'a>(args: &Args<'a>) -> StoreResult<Vec<&'a str>> {
    let keys = args
        .strings("state_keys")
        .map_err(|_| KEYS_INVALID)?
        .ok_or(KEYS_INVALID)?;
    if keys.is_empty() || keys.len() > MAX_KEYS || keys.iter().any(|key| key.is_empty()) {
        return Err(KEYS_INVALID);
    }
    for (index, key) in keys.iter().enumerate() {
        if keys[..index].contains(key) {
            return Err(KEYS_INVALID);
        }
    }
    Ok(keys)
}

fn remote_rows(connection: &Connection) -> StoreResult<Vec<Value>> {
    let placeholders = vec!["?"; REMOTE_POLICY_SOURCES.len()].join(", ");
    let sql = format!(
        "select {} from policy_decisions where source in ({placeholders})",
        ROW_COLUMNS.join(", ")
    );
    let params: Vec<Value> = REMOTE_POLICY_SOURCES
        .iter()
        .map(|source| json!(source))
        .collect();
    Ok(query_all(connection, &sql, &params)?
        .into_iter()
        .map(|mut row| {
            Value::Array(
                ROW_COLUMNS
                    .iter()
                    .map(|column| row.remove(*column).unwrap_or(Value::Null))
                    .collect(),
            )
        })
        .collect())
}

#[cfg(test)]
#[path = "guard_store_policy_activation_view_tests.rs"]
mod tests;
