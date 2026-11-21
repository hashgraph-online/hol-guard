//! The capability half of the local CLI inventory: which capabilities a
//! device grant has turned on, and which one a recorded blocked cause would
//! suggest turning on next. Nothing here grants anything; a suggestion is
//! only what the user could decide.

use std::collections::{BTreeSet, HashMap};

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_db::{query_all, StoreResult};
use crate::guard_store_local_cli_inventory::{column_names, table_exists};
use crate::guard_store_local_cli_inventory_rows::py_text;

/// `LOCAL_CLI_CAPABILITIES`.
const CAPABILITIES: [&str; 3] = ["loopback-network", "state-dir-read", "state-dir-write"];

/// `CAPABILITY_BY_CAUSE`: the capability a recorded blocked cause points at.
const CAPABILITY_BY_CAUSE: [(&str, &str); 3] = [
    ("connect_loopback", "loopback-network"),
    ("read_home_state", "state-dir-read"),
    ("write_home_state", "state-dir-write"),
];

/// `load_local_cli_capabilities`: only capabilities that are on, and only
/// names this build knows.
pub(crate) fn capabilities(
    connection: &Connection,
) -> StoreResult<HashMap<String, BTreeSet<String>>> {
    let mut stored: HashMap<String, BTreeSet<String>> = HashMap::new();
    if !table_exists(connection, "local_cli_grant_capability")? {
        return Ok(stored);
    }
    let rows = query_all(
        connection,
        "select cli_id, capability, state from local_cli_grant_capability",
        &[],
    )?;
    for row in rows {
        let Some(cli_id) = row.get("cli_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(capability) = row.get("capability").and_then(Value::as_str) else {
            continue;
        };
        if !CAPABILITIES.contains(&capability)
            || row.get("state").and_then(Value::as_str) != Some("on")
        {
            continue;
        }
        stored
            .entry(cli_id.to_owned())
            .or_default()
            .insert(capability.to_owned());
    }
    Ok(stored)
}

/// `capability_map`: the full map for one CLI, with absent capabilities off.
pub(crate) fn capability_map(enabled: Option<&BTreeSet<String>>) -> Value {
    let mut map = Map::new();
    for capability in CAPABILITIES {
        let on = enabled.is_some_and(|enabled| enabled.contains(capability));
        map.insert(
            capability.to_owned(),
            Value::from(if on { "on" } else { "off" }),
        );
    }
    Value::Object(map)
}

/// `implied_capabilities`: the capability each CLI's recorded blocked cause
/// points at, with the identity that cause was recorded for.
pub(crate) fn implied_capabilities(
    connection: &Connection,
) -> StoreResult<HashMap<String, (String, String)>> {
    let mut implied = HashMap::new();
    if !table_exists(connection, "local_cli_observation")?
        || !column_names(connection, "local_cli_observation")?.contains("first_blocked_cause")
    {
        return Ok(implied);
    }
    let rows = query_all(
        connection,
        "select cli_id, identity_hash, first_blocked_cause from local_cli_observation \
         where surface = 'cli' and first_blocked_cause in (?, ?, ?)",
        &CAPABILITY_BY_CAUSE.map(|(cause, _)| Value::from(cause)),
    )?;
    for row in rows {
        let cause = row
            .get("first_blocked_cause")
            .map(py_text)
            .unwrap_or_default();
        let Some((_, capability)) = CAPABILITY_BY_CAUSE
            .iter()
            .find(|(known, _)| *known == cause)
        else {
            continue;
        };
        implied.insert(
            row.get("cli_id").map(py_text).unwrap_or_default(),
            (
                row.get("identity_hash").map(py_text).unwrap_or_default(),
                (*capability).to_owned(),
            ),
        );
    }
    Ok(implied)
}

/// `_suggested_capability`: the capability an allowed CLI's recorded cause
/// points at while it is still off.
pub(crate) fn suggested_capability(
    item: &Map<String, Value>,
    implied: Option<&(String, String)>,
) -> Option<String> {
    let (identity_hash, capability) = implied?;
    if item.get("state").and_then(Value::as_str) != Some("allowed")
        || item.get("stale") == Some(&Value::Bool(true))
        || item.get("identity_hash").and_then(Value::as_str) != Some(identity_hash.as_str())
    {
        return None;
    }
    let on = item
        .get("capabilities")
        .and_then(Value::as_object)
        .and_then(|map| map.get(capability))
        .and_then(Value::as_str)
        == Some("on");
    if on {
        None
    } else {
        Some(capability.clone())
    }
}
