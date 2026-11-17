//! The `managed_installs` rows: one per harness Guard installed into or
//! removed from, ported from `store_cloud_events.py`.
//!
//! The caller sends the manifest already encoded, so the stored text is
//! exactly what `json.dumps` wrote, and reads answer that text unparsed for
//! the caller to decode as `json.loads` did.

use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, int, is_null, query_all, query_one, text, Row, StoreResult};

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

/// `_set_managed_install_owned`: insert or replace the harness's row.
pub(crate) fn set(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
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

#[cfg(test)]
#[path = "guard_store_managed_installs_tests.rs"]
mod tests;
