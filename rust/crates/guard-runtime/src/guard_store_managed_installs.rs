//! The `managed_installs` rows: one per harness Guard installed into or
//! removed from, ported from `store_cloud_events.py`.
//!
//! The caller sends the manifest already encoded, so the stored text is
//! exactly what `json.dumps` wrote, and reads answer that text unparsed for
//! the caller to decode as `json.loads` did.
//!
//! The table's revision lives in the store: every write to a row bumps the
//! counter in the same transaction, so a reader that remembers an answer can
//! tell a later write from its own, in any process.

use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, int, is_null, query_all, query_one, text, Row, StoreResult};

/// Atomically decide whether a hook harness is unmanaged. The direct row and
/// the active-harness fallback are read from one store snapshot, so a write
/// cannot race between the two reads as it did in the Python cache path.
pub(crate) fn hook_admission(
    connection: &rusqlite::Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let harness = args.str("harness")?;
    let direct = query_one(
        connection,
        "select active from managed_installs where harness = ?",
        &[Value::from(harness)],
    )?;
    let unmanaged = match direct {
        Some(row) => int(&row, "active") == 0,
        None => query_all(
            connection,
            "select harness, active from managed_installs where active != 0",
            &[],
        )?
        .iter()
        .any(|row| text(row, "harness") != harness),
    };
    Ok(json!({
        "unmanaged": unmanaged,
        "revision": read_revision(connection)?,
    }))
}

/// The `sync_state` row that holds the table's revision.
const REVISION_KEY: &str = "managed_install_revision";

const COLUMNS: &str = "select harness, active, workspace, manifest_json, updated_at \
                       from managed_installs";

fn row_payload(row: &Row) -> Value {
    json!({
        "harness": text(row, "harness"),
        "active": int(row, "active") != 0,
        "workspace": if is_null(row, "workspace") {
            Value::Null
        } else {
            row.get("workspace").cloned().unwrap_or(Value::Null)
        },
        "manifest_json": text(row, "manifest_json"),
        "updated_at": text(row, "updated_at"),
    })
}

/// `get_managed_install_revision`: how many writes the table has seen.
pub(crate) fn revision(connection: &rusqlite::Connection, _args: &Args<'_>) -> StoreResult<Value> {
    Ok(Value::from(read_revision(connection)?))
}

fn read_revision(connection: &rusqlite::Connection) -> StoreResult<i64> {
    let row = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(REVISION_KEY)],
    )?;
    Ok(row
        .and_then(|row| serde_json::from_str::<Value>(text(&row, "payload_json")).ok())
        .and_then(|payload| payload.get("revision").and_then(Value::as_i64))
        .unwrap_or(0))
}

fn bump_at(connection: &rusqlite::Connection, now: &str) -> StoreResult<i64> {
    let next = read_revision(connection)?.saturating_add(1);
    exec(
        connection,
        "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) \
         on conflict(state_key) do update set \
           payload_json = excluded.payload_json, updated_at = excluded.updated_at",
        &[
            Value::from(REVISION_KEY),
            Value::from(json!({ "revision": next }).to_string()),
            Value::from(now),
        ],
    )?;
    Ok(next)
}

/// `bump_managed_install_revision`: a write the caller made to the table
/// outside `set_managed_install`. Answers the new revision.
pub(crate) fn bump(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    Ok(Value::from(bump_at(connection, args.str("now")?)?))
}

/// `_set_managed_install_owned`: insert or replace the harness's row.
pub(crate) fn set(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    bump_at(connection, args.str("now")?)?;
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
            Value::from(args.str("harness")?),
            Value::from(i64::from(args.flag("active")?)),
            args.opt_str("workspace")?.map_or(Value::Null, Value::from),
            Value::from(args.str("manifest_json")?),
            Value::from(args.str("now")?),
        ],
    )?;
    Ok(Value::Null)
}

/// `get_managed_install`: the harness's row, or `null`.
pub(crate) fn get(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    let row = query_one(
        connection,
        &format!("{COLUMNS} where harness = ?"),
        &[Value::from(args.str("harness")?)],
    )?;
    Ok(row.as_ref().map_or(Value::Null, row_payload))
}

/// `list_managed_installs`: every row, by harness.
pub(crate) fn list(connection: &rusqlite::Connection, _args: &Args<'_>) -> StoreResult<Value> {
    let rows = query_all(connection, &format!("{COLUMNS} order by harness asc"), &[])?;
    Ok(Value::Array(rows.iter().map(row_payload).collect()))
}

#[path = "guard_store_managed_installs_cas.rs"]
mod cas;

/// Whether `method` is one of the managed-install row calls.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "set_managed_install"
            | "get_managed_install"
            | "get_managed_install_revision"
            | "bump_managed_install_revision"
            | "list_managed_installs"
            | "hook_managed_install_admission"
            | "compare_managed_installs"
            | "compare_and_set_managed_installs"
    )
}

/// Whether `method` must commit at `synchronous=FULL`: the transition rows
/// take part in a durable file inverse, so they survive power loss as well
/// as a process exit.
pub(crate) fn durable(method: &str) -> bool {
    method == "compare_and_set_managed_installs"
}

pub(crate) fn dispatch(
    connection: &rusqlite::Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "set_managed_install" => set(connection, args),
        "get_managed_install" => get(connection, args),
        "get_managed_install_revision" => revision(connection, args),
        "bump_managed_install_revision" => bump(connection, args),
        "list_managed_installs" => list(connection, args),
        "hook_managed_install_admission" => hook_admission(connection, args),
        "compare_managed_installs" => cas::compare(connection, args),
        "compare_and_set_managed_installs" => cas::compare_and_set(connection, args),
        _ => Err(crate::guard_store_db::StoreError::Invalid(
            "native_guard_store_method_unknown",
        )),
    }
}

#[cfg(test)]
#[path = "guard_store_managed_installs_tests.rs"]
mod tests;
