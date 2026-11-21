//! This-device custom-extension grant reads: the device grant and one
//! extension's command catalog and per-command states.

use std::collections::HashMap;

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, Row, StoreResult};
use crate::guard_store_observed_mcp::is_local_cli_id;

const COMMAND_STATES: [&str; 4] = ["inherit", "allow", "review", "block"];

/// The grant row, or `None` for an invalid id or no grant.
pub(crate) fn read_grant(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return Ok(Value::Null);
    }
    let row = query_one(
        connection,
        "select cli_id, identity_hash, state, revision, updated_at from local_cli_grant where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    Ok(row.map_or(Value::Null, Value::Object))
}

/// Catalog rows in display order, skipping rows with non-text cells.
pub(crate) fn read_command_catalog(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return Ok(Value::Array(Vec::new()));
    }
    let rows = command_catalog(connection, cli_id)?;
    Ok(Value::Array(rows.into_iter().map(Value::Object).collect()))
}

/// Per-command states, skipping unknown states and non-text ids.
pub(crate) fn read_command_states(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return Ok(Value::Object(Map::new()));
    }
    let states = command_states(connection, cli_id)?
        .into_iter()
        .map(|(command_id, state)| (command_id, Value::from(state)))
        .collect();
    Ok(Value::Object(states))
}

/// One extension's well-formed catalog rows in display order. Rows with a
/// non-text cell are skipped in SQL, never decoded.
pub(crate) fn command_catalog(connection: &Connection, cli_id: &str) -> StoreResult<Vec<Row>> {
    query_all(
        connection,
        "select command_id, name, usage, description, parent_id from local_cli_command \
         where cli_id = ? and typeof(command_id) = 'text' and typeof(name) = 'text' \
         and typeof(usage) = 'text' and typeof(description) = 'text' \
         and typeof(parent_id) in ('text', 'null') \
         order by sort_index asc, command_id asc",
        &[Value::from(cli_id)],
    )
}

/// One extension's per-command states, recognised states only.
pub(crate) fn command_states(
    connection: &Connection,
    cli_id: &str,
) -> StoreResult<HashMap<String, String>> {
    let rows = query_all(
        connection,
        "select command_id, state from local_cli_command_grant \
         where cli_id = ? and typeof(command_id) = 'text' and typeof(state) = 'text'",
        &[Value::from(cli_id)],
    )?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let command_id = row.get("command_id")?.as_str()?;
            let state = row.get("state")?.as_str()?;
            COMMAND_STATES
                .contains(&state)
                .then(|| (command_id.to_owned(), state.to_owned()))
        })
        .collect())
}
