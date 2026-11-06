//! `store_custom_extension_continuity.apply_custom_extension_continuity_transaction`
//! and `store_local_cli.upsert_local_cli_grant`: the local CLI grant writer.
//!
//! A continuity mutation commits exact local authority, the continuity state
//! it was preflighted against and its receipt in one `begin immediate`: the
//! grant rows, per-command choices, provider choices and capabilities, then
//! the `sync_state` payloads and `guard_events` rows. Any refusal rolls all of
//! it back, so a crash can never leave authority without the continuity state
//! that explains it.
//!
//! The caller resolves the command ids of flagged catalog changes before the
//! write lock and encodes the payload and event JSON itself, so the stored
//! text is byte for byte what Python's `json.dumps` writes.

use std::collections::HashSet;

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, query_all, query_one, text, value_error, StoreError, StoreResult,
};
use crate::guard_store_json::dumps_sorted;
use crate::guard_store_local_cli_catalog::{insert_command, parse_commands};
use crate::guard_store_local_cli_mcp_snapshot::decode_snapshot;
use crate::guard_store_observed_mcp::{is_local_cli_id, marker_source};
use crate::local_mcp_grant_identity::is_command_id;

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");
const ROOT_COMMAND_ID: &str = "root";
const OTHER_COMMAND_ID: &str = "other";
const CAPABILITIES: [&str; 3] = ["loopback-network", "state-dir-read", "state-dir-write"];
/// `CAPABILITY_BY_CAUSE`: the blocked cause each capability resolves.
const CAUSE_BY_CAPABILITY: [(&str, &str); 3] = [
    ("loopback-network", "connect_loopback"),
    ("state-dir-read", "read_home_state"),
    ("state-dir-write", "write_home_state"),
];
const MAX_PROVIDER_UPDATES: usize = 100;

fn is_command_state(state: &str) -> bool {
    matches!(state, "inherit" | "allow" | "review" | "block")
}

/// One `(identity, state, command_states)` authority update.
struct Update<'a> {
    cli_id: &'a str,
    identity_hash: &'a str,
    state: &'a str,
    /// `None` leaves the per-command choices untouched.
    command_states: Option<&'a Map<String, Value>>,
}

fn update<'a>(value: &'a Value) -> StoreResult<Update<'a>> {
    let item = Args(value.as_object().ok_or(INVALID)?);
    Ok(Update {
        cli_id: item.str("cli_id")?,
        identity_hash: item.str("identity_hash")?,
        state: item.str("state")?,
        command_states: item.opt_object("command_states")?,
    })
}

fn command_state(value: &Value) -> StoreResult<&str> {
    value.as_str().ok_or(INVALID)
}

/// Grant writes shared by both methods, against one transaction.
struct Writer<'a> {
    connection: &'a Connection,
    updated_at: &'a str,
    change_ids: Option<&'a Map<String, Value>>,
}

/// `apply_custom_extension_continuity_transaction`.
pub(crate) fn apply_continuity(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let updates = args
        .raw("updates")
        .and_then(Value::as_array)
        .ok_or(INVALID)?
        .iter()
        .map(update)
        .collect::<StoreResult<Vec<_>>>()?;
    for update in &updates {
        if !is_local_cli_id(update.cli_id)
            || !matches!(update.state, "allowed" | "blocked" | "unset")
        {
            return value_error("invalid local CLI continuity update");
        }
        for (command_id, state) in update.command_states.into_iter().flatten() {
            if !is_command_id(command_id) || !is_command_state(command_state(state)?) {
                return value_error("invalid local CLI continuity command update");
            }
        }
    }
    let updated: HashSet<&str> = updates.iter().map(|update| update.cli_id).collect();
    let provider_updates = args.opt_object("provider_updates")?;
    let capability_updates = args.opt_object("capability_updates")?;
    if provider_updates
        .into_iter()
        .flatten()
        .any(|(cli_id, _)| !updated.contains(cli_id.as_str()))
    {
        return value_error("provider choices require matching extension authority");
    }
    if capability_updates
        .into_iter()
        .flatten()
        .any(|(cli_id, _)| !updated.contains(cli_id.as_str()))
    {
        return value_error("capability choices require matching extension authority");
    }
    let mut revision = authority_revision(connection)?;
    if revision != args.int("expected_revision")? {
        return value_error("local_cli_revision_conflict");
    }
    require_sync_preconditions(connection, args.opt_object("sync_preconditions")?)?;
    require_observation_preconditions(connection, args.opt_object("observation_preconditions")?)?;
    seed_default_catalogs(connection, args.opt_object("catalog_seeds")?)?;
    let catalog_reviews = args.opt_object("catalog_reviews")?;
    let writer = Writer {
        connection,
        updated_at: args.str("updated_at")?,
        change_ids: args.opt_object("catalog_change_ids")?,
    };
    for update in &updates {
        let reviewed = match catalog_reviews.and_then(|reviews| reviews.get(update.cli_id)) {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_i64().ok_or(INVALID)?),
        };
        revision = writer.write_grant(update, revision, reviewed)?;
        let providers = match provider_updates.and_then(|items| items.get(update.cli_id)) {
            None | Some(Value::Null) => &[][..],
            Some(value) => value.as_array().ok_or(INVALID)?.as_slice(),
        };
        if !providers.is_empty() {
            if update.state == "unset" {
                return value_error("provider choices cannot accompany removal");
            }
            writer.write_provider_choices(update, providers)?;
        }
        let capabilities = match capability_updates.and_then(|items| items.get(update.cli_id)) {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_object().ok_or(INVALID)?),
        };
        if let Some(capabilities) = capabilities.filter(|choices| !choices.is_empty()) {
            if update.state == "unset" {
                // `LocalCliCapabilityError`; the caller re-raises it by message.
                return value_error("capabilities_require_allowed_grant");
            }
            writer.write_capabilities(update.cli_id, capabilities, revision)?;
        }
    }
    for (state_key, payload) in args.opt_object("sync_payloads")?.into_iter().flatten() {
        exec(
            connection,
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) \
             on conflict(state_key) do update set \
             payload_json = excluded.payload_json, updated_at = excluded.updated_at",
            &[
                Value::from(state_key.as_str()),
                Value::from(payload.as_str().ok_or(INVALID)?),
                Value::from(writer.updated_at),
            ],
        )?;
    }
    for event in args
        .raw("events")
        .map(|events| events.as_array().ok_or(INVALID))
        .transpose()?
        .into_iter()
        .flatten()
    {
        let [Value::String(name), Value::String(payload)] =
            event.as_array().ok_or(INVALID)?.as_slice()
        else {
            return Err(INVALID);
        };
        exec(
            connection,
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
            &[
                Value::from(name.as_str()),
                Value::from(payload.as_str()),
                Value::from(writer.updated_at),
            ],
        )?;
    }
    Ok(json!(revision))
}

/// `upsert_local_cli_grant`: one grant write without continuity state.
pub(crate) fn upsert_grant(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let update = Update {
        cli_id: args.str("cli_id")?,
        identity_hash: args.str("identity_hash")?,
        state: args.str("state")?,
        command_states: args.opt_object("command_states")?,
    };
    if !matches!(update.state, "allowed" | "blocked" | "unset") {
        return value_error("invalid local CLI grant state");
    }
    if !is_local_cli_id(update.cli_id) {
        return value_error("invalid local CLI id");
    }
    let revision = authority_revision(connection)?;
    if revision != args.int("expected_revision")? {
        return value_error("local_cli_revision_conflict");
    }
    let reviewed = match args.raw("reviewed_catalog_revision") {
        None => None,
        Some(value) => Some(value.as_i64().ok_or(INVALID)?),
    };
    let writer = Writer {
        connection,
        updated_at: args.str("updated_at")?,
        change_ids: args.opt_object("catalog_change_ids")?,
    };
    Ok(json!(writer.write_grant(&update, revision, reviewed)?))
}

fn authority_revision(connection: &Connection) -> StoreResult<i64> {
    match query_one(
        connection,
        "select revision from local_cli_authority where singleton = 1",
        &[],
    )? {
        None => Ok(0),
        Some(row) => match row.get("revision") {
            Some(Value::Number(number)) if number.is_i64() => Ok(number.as_i64().unwrap_or(0)),
            _ => value_error("invalid local CLI row"),
        },
    }
}

/// `_require_sync_preconditions`: each named payload still parses to the value
/// the mutation was preflighted against (`None` when absent).
fn require_sync_preconditions(
    connection: &Connection,
    expected: Option<&Map<String, Value>>,
) -> StoreResult<()> {
    for (state_key, expected) in expected.into_iter().flatten() {
        let row = query_one(
            connection,
            "select payload_json from sync_state where state_key = ?",
            &[Value::from(state_key.as_str())],
        )?;
        let actual = match row {
            None => Some(Value::Null),
            Some(row) => serde_json::from_str::<Value>(text(&row, "payload_json")).ok(),
        };
        if actual.as_ref() != Some(expected) {
            return value_error("custom_extension_continuity_sync_precondition_changed");
        }
    }
    Ok(())
}

/// `_require_observation_preconditions` over `_local_cli_observation_snapshot`.
fn require_observation_preconditions(
    connection: &Connection,
    expected: Option<&Map<String, Value>>,
) -> StoreResult<()> {
    for (cli_id, expected) in expected.into_iter().flatten() {
        if &observation_snapshot(connection, cli_id)? != expected {
            return value_error("custom_extension_continuity_observation_changed");
        }
    }
    Ok(())
}

fn observation_snapshot(connection: &Connection, cli_id: &str) -> StoreResult<Value> {
    let Some(row) = query_one(
        connection,
        "select identity_hash, kind, name, interpreter_name, example_label, observed_count, surface \
         from local_cli_observation where cli_id = ?",
        &[Value::from(cli_id)],
    )?
    else {
        return Ok(Value::Null);
    };
    let command_ids: Vec<Value> = query_all(
        connection,
        "select command_id from local_cli_command where cli_id = ? \
         order by sort_index asc, command_id asc",
        &[Value::from(cli_id)],
    )?
    .iter()
    .map(|command| Value::from(text(command, "command_id")))
    .collect();
    let mut snapshot = row;
    snapshot.insert("command_ids".to_owned(), Value::Array(command_ids));
    Ok(Value::Object(snapshot))
}

/// `_seed_default_catalogs`: store a curated catalog only where the stored
/// one holds just the defaults. Default commands stay in the seed, so no saved
/// rule is dropped.
fn seed_default_catalogs(
    connection: &Connection,
    seeds: Option<&Map<String, Value>>,
) -> StoreResult<()> {
    for (cli_id, commands) in seeds.into_iter().flatten() {
        let stored = query_all(
            connection,
            "select command_id from local_cli_command where cli_id = ?",
            &[Value::from(cli_id.as_str())],
        )?;
        if stored
            .iter()
            .any(|row| !matches!(text(row, "command_id"), ROOT_COMMAND_ID | OTHER_COMMAND_ID))
        {
            continue;
        }
        let commands = parse_commands(Some(commands))?;
        let seeded: HashSet<&str> = commands.iter().map(|command| command.command_id).collect();
        if !seeded.contains(ROOT_COMMAND_ID) || !seeded.contains(OTHER_COMMAND_ID) {
            return value_error("invalid local CLI catalog seed");
        }
        exec(
            connection,
            "delete from local_cli_command where cli_id = ?",
            &[Value::from(cli_id.as_str())],
        )?;
        for (index, command) in commands.iter().enumerate() {
            if !is_command_id(command.command_id) {
                return value_error("invalid local CLI command id");
            }
            insert_command(connection, cli_id, command, index as i64)?;
        }
    }
    Ok(())
}

impl Writer<'_> {
    fn surface(&self, cli_id: &str) -> StoreResult<Option<String>> {
        Ok(query_one(
            self.connection,
            "select surface from local_cli_observation where cli_id = ?",
            &[Value::from(cli_id)],
        )?
        .map(|row| text(&row, "surface").to_owned()))
    }

    /// `_write_local_cli_grant`: returns the authority revision it moved to.
    fn write_grant(
        &self,
        update: &Update<'_>,
        current_revision: i64,
        reviewed_catalog_revision: Option<i64>,
    ) -> StoreResult<i64> {
        let connection = self.connection;
        let cli_id = Value::from(update.cli_id);
        let next_revision = current_revision + 1;
        let previous = query_one(
            connection,
            "select identity_hash, state from local_cli_grant where cli_id = ?",
            &[cli_id.clone()],
        )?;
        let same_allowed = update.state == "allowed"
            && previous.as_ref().is_some_and(|row| {
                row.get("identity_hash") == Some(&Value::from(update.identity_hash))
                    && row.get("state") == Some(&Value::from(update.state))
            });
        if !same_allowed {
            // Capabilities were chosen for one exact allowed grant. A grant
            // that is blocked, reviewed, removed or re-identified, or that
            // comes back from such a state, never inherits rows.
            exec(
                connection,
                "delete from local_cli_grant_capability where cli_id = ?",
                &[cli_id.clone()],
            )?;
        }
        if update.state == "unset" {
            for table in [
                "local_mcp_provider_grant",
                "local_cli_grant",
                "local_cli_command_grant",
            ] {
                exec(
                    connection,
                    &format!("delete from {table} where cli_id = ?"),
                    &[cli_id.clone()],
                )?;
            }
        } else {
            exec(
                connection,
                "insert into local_cli_grant (cli_id, identity_hash, state, revision, updated_at) \
                 values (?, ?, ?, ?, ?) on conflict(cli_id) do update set \
                 identity_hash = excluded.identity_hash, state = excluded.state, \
                 revision = excluded.revision, updated_at = excluded.updated_at",
                &[
                    cli_id.clone(),
                    Value::from(update.identity_hash),
                    Value::from(update.state),
                    Value::from(next_revision),
                    Value::from(self.updated_at),
                ],
            )?;
            if let Some(states) = update.command_states {
                let mcp = self.surface(update.cli_id)?.as_deref() == Some("mcp");
                if mcp {
                    // The visible payload omits retired tools. Preserve their
                    // Deny and Ask tombstones while replacing choices for
                    // listed tools.
                    exec(
                        connection,
                        "delete from local_cli_command_grant where cli_id = ? \
                         and (state not in ('block', 'review') or command_id in \
                         (select command_id from local_cli_command where cli_id = ?))",
                        &[cli_id.clone(), cli_id.clone()],
                    )?;
                } else {
                    exec(
                        connection,
                        "delete from local_cli_command_grant where cli_id = ?",
                        &[cli_id.clone()],
                    )?;
                }
                self.write_command_states(update.cli_id, states)?;
                if let (true, Some(revision)) = (mcp, reviewed_catalog_revision) {
                    self.acknowledge_catalog_changes(update, states, revision)?;
                }
            }
        }
        exec(
            connection,
            "update local_cli_authority set revision = ? where singleton = 1",
            &[Value::from(next_revision)],
        )?;
        Ok(next_revision)
    }

    /// `store_local_cli._write_command_states`.
    fn write_command_states(&self, cli_id: &str, states: &Map<String, Value>) -> StoreResult<()> {
        let mut values = Vec::with_capacity(states.len());
        for (command_id, state) in states {
            values.push((command_id.as_str(), command_state(state)?));
        }
        if values.iter().any(|(_, state)| *state == "review")
            && self.surface(cli_id)?.as_deref() != Some("mcp")
        {
            return value_error("explicit review is supported only for MCP tools");
        }
        let known: HashSet<String> = query_all(
            self.connection,
            "select command_id from local_cli_command where cli_id = ?",
            &[Value::from(cli_id)],
        )?
        .iter()
        .map(|row| text(row, "command_id").to_owned())
        .collect();
        for (command_id, state) in values {
            if !known.contains(command_id) || !is_command_id(command_id) {
                return value_error("invalid local CLI command id");
            }
            if !is_command_state(state) {
                return value_error("invalid local CLI command state");
            }
            exec(
                self.connection,
                "insert into local_cli_command_grant (cli_id, command_id, state) values (?, ?, ?) \
                 on conflict(cli_id, command_id) do update set state = excluded.state",
                &[
                    Value::from(cli_id),
                    Value::from(command_id),
                    Value::from(state),
                ],
            )?;
        }
        Ok(())
    }

    /// `store_mcp_catalog.acknowledge_catalog_changes`: a saved choice for a
    /// new or changed tool reviews that change, but only on the catalog
    /// revision the choices were made against.
    fn acknowledge_catalog_changes(
        &self,
        update: &Update<'_>,
        reviewed: &Map<String, Value>,
        catalog_revision: i64,
    ) -> StoreResult<()> {
        let Some(row) = query_one(
            self.connection,
            "select catalog_json, revision from local_mcp_catalog \
             where cli_id = ? and identity_hash = ?",
            &[
                Value::from(update.cli_id),
                Value::from(update.identity_hash),
            ],
        )?
        else {
            return Ok(());
        };
        if row.get("revision").and_then(Value::as_i64) != Some(catalog_revision) {
            return Ok(());
        }
        let Some(mut payload) = decode_snapshot(row.get("catalog_json")) else {
            return Ok(());
        };
        let Some(changes) = payload.get("changes").and_then(Value::as_object) else {
            return Ok(());
        };
        let is_reviewed = |name: &Value| {
            name.as_str()
                .and_then(|name| self.change_ids?.get(name)?.as_str())
                .is_some_and(|command_id| reviewed.contains_key(command_id))
        };
        let mut updated = changes.clone();
        for key in ["added", "changed"] {
            if let Some(Value::Array(names)) = updated.get_mut(key) {
                names.retain(|name| !is_reviewed(name));
            }
        }
        if &updated == changes {
            return Ok(());
        }
        payload["changes"] = Value::Object(updated);
        let Some(raw) = dumps_sorted(&payload) else {
            return value_error("MCP catalog snapshot is not representable");
        };
        exec(
            self.connection,
            "update local_mcp_catalog set catalog_json = ? where cli_id = ? and identity_hash = ?",
            &[
                Value::from(raw),
                Value::from(update.cli_id),
                Value::from(update.identity_hash),
            ],
        )?;
        Ok(())
    }

    /// `store_mcp_provider_permissions.write_provider_choices`.
    fn write_provider_choices(&self, update: &Update<'_>, choices: &[Value]) -> StoreResult<()> {
        let mut parsed = Vec::with_capacity(choices.len());
        for choice in choices {
            let [Value::String(slug), state, revision] =
                choice.as_array().ok_or(INVALID)?.as_slice()
            else {
                return Err(INVALID);
            };
            parsed.push((slug.as_str(), state, revision));
        }
        let slugs: HashSet<&str> = parsed.iter().map(|(slug, _, _)| *slug).collect();
        if parsed.len() > MAX_PROVIDER_UPDATES || slugs.len() != parsed.len() {
            return value_error("invalid provider action choices");
        }
        for (slug, state, revision) in parsed {
            let state = state
                .as_str()
                .filter(|state| matches!(*state, "review" | "block"));
            let revision = revision.as_i64().filter(|revision| *revision >= 1);
            let (Some(state), Some(revision)) = (state, revision) else {
                return value_error("invalid provider action choice");
            };
            let current = query_one(
                self.connection,
                "select a.revision from local_mcp_provider_action a \
                 join local_cli_observation o on o.cli_id = a.cli_id \
                 and o.identity_hash = a.identity_hash \
                 where a.cli_id = ? and a.identity_hash = ? and a.tool_slug = ? and o.surface = 'mcp'",
                &[
                    Value::from(update.cli_id),
                    Value::from(update.identity_hash),
                    Value::from(slug),
                ],
            )?;
            if current.and_then(|row| row.get("revision").and_then(Value::as_i64)) != Some(revision)
            {
                return value_error("provider_action_revision_conflict");
            }
            // Cached metadata cannot invent a different authority namespace.
            let marker = query_one(
                self.connection,
                "select server_command from local_cli_observation where cli_id = ?",
                &[Value::from(update.cli_id)],
            )?;
            let source = marker
                .as_ref()
                .and_then(|row| row.get("server_command"))
                .and_then(Value::as_str)
                .and_then(marker_source)
                .filter(|source| source.identity_hash() == update.identity_hash);
            let Some(source) = source else {
                return value_error("invalid provider authority identity");
            };
            if source.action_selector(slug).is_none() {
                return value_error("invalid provider action identity");
            }
            exec(
                self.connection,
                "insert into local_mcp_provider_grant values (?, ?, ?, ?, ?) \
                 on conflict(cli_id, identity_hash, tool_slug) do update set \
                 state = excluded.state, updated_at = excluded.updated_at",
                &[
                    Value::from(update.cli_id),
                    Value::from(update.identity_hash),
                    Value::from(slug),
                    Value::from(state),
                    Value::from(self.updated_at),
                ],
            )?;
        }
        Ok(())
    }

    /// `store_local_cli_capabilities.write_local_cli_capabilities`. Refusals
    /// are `LocalCliCapabilityError` messages the caller re-raises by name.
    fn write_capabilities(
        &self,
        cli_id: &str,
        choices: &Map<String, Value>,
        revision: i64,
    ) -> StoreResult<()> {
        if choices.len() > CAPABILITIES.len() {
            return value_error("invalid_capabilities");
        }
        let mut checked = Vec::with_capacity(choices.len());
        for (name, state) in choices {
            let state = state
                .as_str()
                .filter(|state| matches!(*state, "on" | "off"));
            let Some(state) = state.filter(|_| CAPABILITIES.contains(&name.as_str())) else {
                return value_error("invalid_capabilities");
            };
            checked.push((name.as_str(), state));
        }
        if checked.is_empty() {
            return Ok(());
        }
        if self.surface(cli_id)?.as_deref() != Some("cli") {
            return value_error("capabilities_require_cli_surface");
        }
        if checked.iter().any(|(_, state)| *state == "on") {
            let grant = query_one(
                self.connection,
                "select state from local_cli_grant where cli_id = ?",
                &[Value::from(cli_id)],
            )?;
            if grant.as_ref().map(|row| text(row, "state")) != Some("allowed") {
                return value_error("capabilities_require_allowed_grant");
            }
        }
        // `Map` iterates in key order, matching Python's `sorted(...)`.
        for (name, state) in &checked {
            exec(
                self.connection,
                "insert into local_cli_grant_capability \
                 (cli_id, capability, state, revision, updated_at) values (?, ?, ?, ?, ?) \
                 on conflict(cli_id, capability) do update set state = excluded.state, \
                 revision = excluded.revision, updated_at = excluded.updated_at",
                &[
                    Value::from(cli_id),
                    Value::from(*name),
                    Value::from(*state),
                    Value::from(revision),
                    Value::from(self.updated_at),
                ],
            )?;
        }
        self.clear_resolved_causes(cli_id, &checked)
    }

    /// `_clear_resolved_causes`: drop a blocked cause once the capability it
    /// points at is on.
    fn clear_resolved_causes(&self, cli_id: &str, checked: &[(&str, &str)]) -> StoreResult<()> {
        let causes: Vec<Value> = CAUSE_BY_CAPABILITY
            .iter()
            .filter(|(capability, _)| checked.contains(&(*capability, "on")))
            .map(|(_, cause)| Value::from(*cause))
            .collect();
        if causes.is_empty() {
            return Ok(());
        }
        let has_column = query_all(
            self.connection,
            "select name from pragma_table_info('local_cli_observation')",
            &[],
        )?
        .iter()
        .any(|row| text(row, "name") == "first_blocked_cause");
        if !has_column {
            return Ok(());
        }
        let marks = vec!["?"; causes.len()].join(", ");
        let mut params = vec![Value::from(cli_id)];
        params.extend(causes);
        exec(
            self.connection,
            &format!(
                "update local_cli_observation set first_blocked_cause = null \
                 where cli_id = ? and first_blocked_cause in ({marks})"
            ),
            &params,
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "guard_store_continuity_write_tests.rs"]
mod tests;
