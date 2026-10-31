//! The per-connector half of the local CLI inventory read: the command
//! catalog, MCP description, provider coverage and capabilities one listed
//! item carries.
//!
//! These are the reads that grow with a connector's catalog, so a page runs
//! them only for the items it lists. Every lookup is keyed by `cli_id`, the
//! leading primary-key column of each table it reads, so walking every page
//! of the inventory reads each connector's catalog once.

use std::collections::{BTreeSet, HashMap};

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_db::{query_all, query_one, StoreResult};
use crate::guard_store_local_cli_inventory::{is_mcp, table_exists};
use crate::guard_store_local_cli_inventory_capabilities::{
    capabilities, capability_map, implied_capabilities, suggested_capability,
};
use crate::guard_store_local_cli_inventory_rows::{classifications, py_text};
use crate::guard_store_local_cli_mcp_snapshot::decode_snapshot;

/// What every item of one page is enriched from. The capability rows are one
/// short row per connector, so a page reads them whole; everything sized by a
/// catalog is read per item.
pub(crate) struct Enrichment {
    authority_revision: i64,
    capability_rows: HashMap<String, BTreeSet<String>>,
    implied: HashMap<String, (String, String)>,
    commands: bool,
    command_grants: bool,
    catalogs: bool,
    providers: bool,
}

impl Enrichment {
    pub(crate) fn load(connection: &Connection, authority_revision: i64) -> StoreResult<Self> {
        Ok(Self {
            authority_revision,
            capability_rows: capabilities(connection)?,
            implied: implied_capabilities(connection)?,
            commands: table_exists(connection, "local_cli_command")?,
            command_grants: table_exists(connection, "local_cli_command_grant")?,
            catalogs: table_exists(connection, "local_mcp_catalog")?,
            providers: table_exists(connection, "local_mcp_provider_action")?
                && table_exists(connection, "local_cli_observation")?,
        })
    }

    /// Capability-annotate `item` and, for an MCP connector, describe its
    /// commands from the catalog still bound to its identity.
    pub(crate) fn enrich(
        &self,
        connection: &Connection,
        item: &mut Map<String, Value>,
    ) -> StoreResult<()> {
        let cli_id = item.get("cli_id").map(py_text).unwrap_or_default();
        item.insert(
            "authority_revision".to_owned(),
            Value::from(self.authority_revision),
        );
        let mut commands = if self.commands {
            commands_for(connection, &cli_id, self.command_grants)?
        } else {
            Vec::new()
        };
        let surface_is_cli = item.get("surface").and_then(Value::as_str) == Some("cli");
        item.insert(
            "capabilities".to_owned(),
            if surface_is_cli {
                capability_map(self.capability_rows.get(&cli_id))
            } else {
                Value::Object(Map::new())
            },
        );
        if let Some(capability) = suggested_capability(item, self.implied.get(&cli_id)) {
            item.insert("suggested_capability".to_owned(), Value::from(capability));
        }
        if self.catalogs && is_mcp(item) {
            if let Some((identity_hash, payload)) = catalog_for(connection, &cli_id)? {
                if item.get("identity_hash").and_then(Value::as_str) == Some(identity_hash.as_str())
                {
                    describe(&mut commands, &payload);
                    item.insert("mcp_catalog".to_owned(), payload);
                }
            }
        }
        item.insert(
            "commands".to_owned(),
            Value::Array(commands.into_iter().map(Value::Object).collect()),
        );
        if self.providers {
            if let Some(summary) = provider_summary(connection, &cli_id)? {
                item.insert("provider_catalog".to_owned(), summary);
            }
        }
        Ok(())
    }
}

/// `_load_commands_by_cli` for one CLI: its catalog rows in display order
/// with their stored per-command state.
fn commands_for(
    connection: &Connection,
    cli_id: &str,
    command_grants: bool,
) -> StoreResult<Vec<Map<String, Value>>> {
    let mut states: HashMap<String, String> = HashMap::new();
    if command_grants {
        for row in query_all(
            connection,
            "select command_id, state from local_cli_command_grant where cli_id = ?",
            &[Value::from(cli_id)],
        )? {
            let (Some(command_id), Some(state)) = (
                row.get("command_id").and_then(Value::as_str),
                row.get("state").and_then(Value::as_str),
            ) else {
                continue;
            };
            states.insert(command_id.to_owned(), state.to_owned());
        }
    }
    let rows = query_all(
        connection,
        "select command_id, name, usage, description, parent_id from local_cli_command \
         where cli_id = ? order by sort_index asc, command_id asc",
        &[Value::from(cli_id)],
    )?;
    let mut commands = Vec::new();
    for row in rows {
        let Some(command_id) = row.get("command_id").and_then(Value::as_str) else {
            continue;
        };
        let state = states.get(command_id).map_or("inherit", String::as_str);
        let mut command = Map::new();
        command.insert("command_id".to_owned(), Value::from(command_id));
        for field in ["name", "usage", "description", "parent_id"] {
            command.insert(
                field.to_owned(),
                row.get(field).cloned().unwrap_or(Value::Null),
            );
        }
        command.insert("state".to_owned(), Value::from(state));
        commands.push(command);
    }
    Ok(commands)
}

/// `load_mcp_catalogs` for one CLI: the stored discovery snapshot and the
/// identity it was discovered for.
fn catalog_for(connection: &Connection, cli_id: &str) -> StoreResult<Option<(String, Value)>> {
    let Some(row) = query_one(
        connection,
        "select identity_hash, catalog_json, revision, updated_at, last_complete_at \
         from local_mcp_catalog where cli_id = ?",
        &[Value::from(cli_id)],
    )?
    else {
        return Ok(None);
    };
    let Some(Value::Object(mut payload)) = decode_snapshot(row.get("catalog_json")) else {
        return Ok(None);
    };
    for field in ["revision", "updated_at", "last_complete_at"] {
        payload.insert(
            field.to_owned(),
            row.get(field).cloned().unwrap_or(Value::Null),
        );
    }
    let identity_hash = row.get("identity_hash").map(py_text).unwrap_or_default();
    Ok(Some((identity_hash, Value::Object(payload))))
}

/// `load_provider_catalog_summaries` for one CLI: how much of a provider's
/// action list this device has seen. Coverage is a subset and the account is
/// unverified; both are stated so no surface reads the count as completeness.
fn provider_summary(connection: &Connection, cli_id: &str) -> StoreResult<Option<Value>> {
    let Some(row) = query_one(
        connection,
        "select count(*) as known_count, sum(p.full_schema) as full_schema_count, \
         max(p.updated_at) as updated_at \
         from local_mcp_provider_action p join local_cli_observation o \
         on p.cli_id = o.cli_id and p.identity_hash = o.identity_hash \
         where p.cli_id = ? group by p.cli_id",
        &[Value::from(cli_id)],
    )?
    else {
        return Ok(None);
    };
    Ok(Some(json!({
        "provider": "composio",
        "known_count": row.get("known_count").cloned().unwrap_or(Value::Null),
        "full_schema_count": row.get("full_schema_count").cloned().unwrap_or(Value::Null),
        "updated_at": row.get("updated_at").cloned().unwrap_or(Value::Null),
        "coverage": "discovery-subset",
        "account_binding": "unverified",
    })))
}

/// Attach the classifier's description to each command whose usage names a
/// tool the catalog declares. The definitions stay borrowed from the catalog:
/// a connector's stored schemas can be large, and the classifier clones what
/// it sends.
fn describe(commands: &mut [Map<String, Value>], payload: &Value) {
    let by_name = tools_by_name(payload);
    let mut positions: Vec<usize> = Vec::new();
    let mut definitions: Vec<&Value> = Vec::new();
    for (position, command) in commands.iter().enumerate() {
        let Some(definition) = command
            .get("usage")
            .and_then(Value::as_str)
            .and_then(|usage| by_name.get(usage))
        else {
            continue;
        };
        positions.push(position);
        definitions.push(*definition);
    }
    if definitions.is_empty() {
        return;
    }
    for (position, classification) in positions.into_iter().zip(classifications(&definitions)) {
        if classification.is_null() {
            continue;
        }
        commands[position].insert("classification".to_owned(), classification);
    }
}

/// The catalog's tool declarations by name; a declaration without a text
/// name describes nothing a command can be matched to.
fn tools_by_name(payload: &Value) -> HashMap<&str, &Value> {
    let mut by_name = HashMap::new();
    let Some(tools) = payload.get("tools").and_then(Value::as_array) else {
        return by_name;
    };
    for tool in tools {
        if !tool.is_object() {
            continue;
        }
        if let Some(name) = tool.get("name").and_then(Value::as_str) {
            by_name.insert(name, tool);
        }
    }
    by_name
}
