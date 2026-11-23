//! `compare_and_set_managed_installs`: the managed-install transition rows a
//! runtime transition moves together, ported from `store_cloud_events.py`.
//!
//! Python ran the compare, its file mutation and the row writes inside one
//! SQLite transaction. The file mutation stays in Python, so the store now
//! answers two calls: `compare_managed_installs` checks every row before the
//! mutation, and `compare_and_set_managed_installs` checks them again and
//! writes them in one transaction after it. Both run under the caller's Codex
//! install lock, which every managed-install writer holds, so no writer can
//! change a row between the two calls. A crash during the mutation leaves the
//! rows unwritten, as the rolled-back transaction did, and the signed file
//! plan recovers the files.
//!
//! A change is `{harness, allowed, replacement}`. `allowed` lists the rows
//! (or `null` for an absent row) the current row must equal; a row compares
//! as `{harness, active, workspace, manifest, updated_at}` with the manifest
//! decoded, as Python compared them. `replacement` is the row to write, with
//! the manifest sent as its encoded `manifest_json` text so the stored bytes
//! stay exactly what `json.dumps` wrote, or `null` to delete the row.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::{bump_at, COLUMNS};
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, int, is_null, query_one, text, StoreError, StoreResult};

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");
/// A transition moves at most a handful of harnesses; anything larger is not
/// a request this contract sends.
const MAX_CHANGES: usize = 64;
const MAX_ALLOWED: usize = 2;

struct Change<'a> {
    harness: &'a str,
    allowed: &'a [Value],
    replacement: Option<&'a Map<String, Value>>,
}

/// `compare_managed_installs`: whether every row is one its change allows.
pub(super) fn compare(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    Ok(Value::Bool(all_allowed(connection, &changes(args)?)?))
}

/// `compare_and_set_managed_installs`: check every row again, then write
/// them all and bump the table's revision. Answers `false`, writing nothing,
/// when any row moved.
pub(super) fn compare_and_set(
    connection: &rusqlite::Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let changes = changes(args)?;
    let now = args.str("now")?;
    if !all_allowed(connection, &changes)? {
        return Ok(Value::Bool(false));
    }
    for change in &changes {
        match change.replacement {
            None => {
                exec(
                    connection,
                    "delete from managed_installs where harness = ?",
                    &[Value::from(change.harness)],
                )?;
            }
            Some(row) => write(connection, change.harness, row)?,
        }
    }
    bump_at(connection, now)?;
    Ok(Value::Bool(true))
}

fn changes<'a>(args: &Args<'a>) -> StoreResult<Vec<Change<'a>>> {
    let items = args
        .raw("changes")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty() && items.len() <= MAX_CHANGES)
        .ok_or(INVALID)?;
    let mut seen = BTreeSet::new();
    items
        .iter()
        .map(|item| {
            let change = change(item)?;
            if seen.insert(change.harness) {
                Ok(change)
            } else {
                Err(INVALID)
            }
        })
        .collect()
}

fn change(item: &Value) -> StoreResult<Change<'_>> {
    let item = item.as_object().ok_or(INVALID)?;
    let harness = item.get("harness").and_then(Value::as_str).ok_or(INVALID)?;
    let allowed = item
        .get("allowed")
        .and_then(Value::as_array)
        .filter(|allowed| !allowed.is_empty() && allowed.len() <= MAX_ALLOWED)
        .ok_or(INVALID)?;
    if allowed
        .iter()
        .any(|row| !(row.is_null() || row.is_object()))
    {
        return Err(INVALID);
    }
    let replacement = match item.get("replacement") {
        None | Some(Value::Null) => None,
        Some(Value::Object(row)) => Some(replacement(harness, row)?),
        Some(_) => return Err(INVALID),
    };
    Ok(Change {
        harness,
        allowed: allowed.as_slice(),
        replacement,
    })
}

fn replacement<'a>(
    harness: &str,
    row: &'a Map<String, Value>,
) -> StoreResult<&'a Map<String, Value>> {
    let named = row.get("harness").and_then(Value::as_str) == Some(harness);
    let typed = row.get("active").is_some_and(Value::is_boolean)
        && row
            .get("workspace")
            .is_some_and(|workspace| workspace.is_null() || workspace.is_string())
        && row.get("updated_at").is_some_and(Value::is_string)
        && row
            .get("manifest_json")
            .and_then(Value::as_str)
            .is_some_and(|manifest| serde_json::from_str::<Value>(manifest).is_ok());
    if named && typed {
        Ok(row)
    } else {
        Err(INVALID)
    }
}

fn all_allowed(connection: &rusqlite::Connection, changes: &[Change<'_>]) -> StoreResult<bool> {
    for change in changes {
        let current = current(connection, change.harness)?;
        if !change.allowed.contains(&current) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The harness's row as Python compared it, or `null`. A stored manifest that
/// no longer decodes fails the call, as Python's `json.loads` raised.
fn current(connection: &rusqlite::Connection, harness: &str) -> StoreResult<Value> {
    let Some(row) = query_one(
        connection,
        &format!("{COLUMNS} where harness = ?"),
        &[Value::from(harness)],
    )?
    else {
        return Ok(Value::Null);
    };
    let Ok(manifest) = serde_json::from_str::<Value>(text(&row, "manifest_json")) else {
        return Err(StoreError::Invalid("managed_install_manifest_invalid"));
    };
    let workspace = if is_null(&row, "workspace") {
        Value::Null
    } else {
        row.get("workspace").cloned().unwrap_or(Value::Null)
    };
    Ok(json!({
        "harness": text(&row, "harness"),
        "active": int(&row, "active") != 0,
        "workspace": workspace,
        "manifest": manifest,
        "updated_at": text(&row, "updated_at"),
    }))
}

fn write(
    connection: &rusqlite::Connection,
    harness: &str,
    row: &Map<String, Value>,
) -> StoreResult<()> {
    let active = row.get("active").and_then(Value::as_bool).ok_or(INVALID)?;
    exec(
        connection,
        "insert into managed_installs (harness, active, workspace, manifest_json, updated_at) \
         values (?, ?, ?, ?, ?) \
         on conflict(harness) do update set \
           active = excluded.active, \
           workspace = excluded.workspace, \
           manifest_json = excluded.manifest_json, \
           updated_at = excluded.updated_at",
        &[
            Value::from(harness),
            Value::from(i64::from(active)),
            row.get("workspace").cloned().unwrap_or(Value::Null),
            row.get("manifest_json").cloned().ok_or(INVALID)?,
            row.get("updated_at").cloned().ok_or(INVALID)?,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "guard_store_managed_installs_cas_tests.rs"]
mod tests;
