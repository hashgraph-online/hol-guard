//! The flagged tool names of a local MCP catalog, read for review.
//!
//! Port of the read half of `store_mcp_catalog.catalog_change_ids`, which ran
//! on its own SQLite connection before a grant or continuity write:
//! `local_mcp_catalog_change_names` answers the sorted, distinct names listed
//! under `changes.added` and `changes.changed` in every stored catalog of the
//! given CLI ids. A catalog that no longer decodes as a bounded inventory
//! contributes nothing, as does a store without the catalog table. The caller
//! still turns the names into command ids.

use std::collections::BTreeSet;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, StoreError, StoreResult};
use crate::guard_store_local_cli_inventory::table_exists;
use crate::guard_store_local_cli_mcp_snapshot::decode_snapshot;

const METHOD: &str = "local_mcp_catalog_change_names";
const CHANGE_KEYS: [&str; 2] = ["added", "changed"];

pub(crate) fn handles(method: &str) -> bool {
    method == METHOD
}

pub(crate) fn dispatch(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let cli_ids = args
        .strings("cli_ids")?
        .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))?;
    let mut names = BTreeSet::new();
    if table_exists(connection, "local_mcp_catalog")? {
        for cli_id in cli_ids {
            let rows = query_all(
                connection,
                "select case when typeof(catalog_json) = 'text' then catalog_json end \
                   as catalog_json \
                 from local_mcp_catalog where cli_id = ?1",
                &[Value::from(cli_id)],
            )?;
            for row in rows {
                collect(decode_snapshot(row.get("catalog_json")), &mut names);
            }
        }
    }
    Ok(json!({ "names": names.into_iter().collect::<Vec<_>>() }))
}

fn collect(snapshot: Option<Value>, names: &mut BTreeSet<String>) {
    let Some(changes) = snapshot
        .as_ref()
        .and_then(|payload| payload.get("changes"))
        .and_then(Value::as_object)
    else {
        return;
    };
    for key in CHANGE_KEYS {
        let Some(listed) = changes.get(key).and_then(Value::as_array) else {
            continue;
        };
        names.extend(listed.iter().filter_map(Value::as_str).map(str::to_owned));
    }
}

#[cfg(test)]
#[path = "guard_store_local_mcp_catalog_changes_tests.rs"]
mod tests;
