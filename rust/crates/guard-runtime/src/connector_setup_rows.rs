//! `connector_setup_rows` runner-authority kind: the connectors Protect shows
//! and which of them still need setup.
//!
//! `hol-guard mcp list`, `status` and `doctor` count the same connectors the
//! local dashboard does. The caller lists the stored connectors; this kind
//! applies the Protect workspace filter and the dashboard's needs-review rule,
//! so a connector that needs setup is counted once everywhere.
//!
//! Request: `{"items": [listed connector, ...]}`.
//!
//! Answer: `{"rows": [{cli_id, name, surface, state, source_label,
//! remote_origin, needs_setup, declared_sources}, ...]}` in listing order. A
//! listed connector without a string id, name or surface has no row.

use serde_json::{json, Map, Value};

use crate::guard_config_coerce::python_truthy;

const ERR_INVALID: &str = "native_runner_authority_invalid";
const SETUP_SURFACES: [&str; 2] = ["mcp", "cli"];

pub(crate) fn dispatch(args: &Value) -> Result<Value, &'static str> {
    let object = args.as_object().ok_or(ERR_INVALID)?;
    if object.len() != 1 {
        return Err(ERR_INVALID);
    }
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let rows = items
        .iter()
        .map(|item| item.as_object().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|item| in_workspace(item))
        .filter_map(row)
        .collect::<Vec<_>>();
    Ok(json!({ "rows": rows }))
}

/// The dashboard's Protect workspace filter, without catalog seeds.
fn in_workspace(item: &Map<String, Value>) -> bool {
    item.get("state").and_then(Value::as_str) != Some("unset")
        || (item.get("suggestable") == Some(&Value::Bool(true))
            && item
                .get("surface")
                .and_then(Value::as_str)
                .is_some_and(|surface| SETUP_SURFACES.contains(&surface)))
}

/// The dashboard's needs-review rule for one listed connector.
fn needs_setup(item: &Map<String, Value>) -> bool {
    if item.get("stale") == Some(&Value::Bool(true))
        || item.get("state").and_then(Value::as_str) == Some("unset")
    {
        return true;
    }
    let Some(catalog) = item.get("mcp_catalog").and_then(Value::as_object) else {
        return false;
    };
    let changed = catalog
        .get("changes")
        .and_then(Value::as_object)
        .is_some_and(|changes| {
            python_truthy(changes.get("added")) || python_truthy(changes.get("changed"))
        });
    catalog.get("stale") == Some(&Value::Bool(true))
        || catalog.get("complete") == Some(&Value::Bool(false))
        || changed
}

fn row(item: &Map<String, Value>) -> Option<Value> {
    let cli_id = item.get("cli_id")?.as_str()?;
    let name = if python_truthy(item.get("display_name")) {
        item.get("display_name")
    } else {
        item.get("name")
    };
    let name = name?.as_str()?;
    let surface = item.get("surface")?.as_str()?;
    let label = |key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
    };
    let declared = item
        .get("declared_sources")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    Some(json!({
        "cli_id": cli_id,
        "name": name,
        "surface": surface,
        "state": item.get("state").and_then(Value::as_str).unwrap_or("unset"),
        "source_label": label("source_label"),
        "remote_origin": label("remote_origin"),
        "needs_setup": needs_setup(item),
        "declared_sources": declared,
    }))
}

#[cfg(test)]
#[path = "connector_setup_rows_tests.rs"]
mod tests;
