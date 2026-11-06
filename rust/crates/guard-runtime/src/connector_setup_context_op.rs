//! `ConnectorSetupContext` — what Guard knows about a connector waiting for
//! setup, kept with its observation.
//!
//! The caller names an observed connector and the review wording Guard
//! composed for it. The resident records that context (the first cause that
//! blocked it, scrubbed and capped wording, the harness and workspace label),
//! then answers with what this device already allows in the connector's
//! namespace and the setup choice Guard would recommend.
//!
//! The answer is advice only. Nothing here writes a grant, a command state or
//! a capability, and a recommendation is never preselected: a person decides
//! through the local admin path. A store whose schema is not exactly this
//! build's is refused rather than guessed at.

use std::collections::BTreeSet;

use guard_contracts::{
    ConnectorSetupContextRequestV1, ConnectorSetupContextResultV1, GuardStoreRequestV1,
    CONNECTOR_SETUP_CONTEXT_REQUEST_SCHEMA, CONNECTOR_SETUP_CONTEXT_RESULT_SCHEMA,
    GUARD_STORE_REQUEST_SCHEMA,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::guard_store_connector_context::{
    is_first_blocked_cause, MAX_IDENTITY_HASH_BYTES, MAX_RAW_FIELD_BYTES,
};
use crate::guard_store_observed_mcp::is_local_cli_id;
use crate::local_mcp_grant_identity::{composio_requires_action_review, slug_command_id};
use crate::local_store_read::{self, StoreReadError};

const STORE_UNAVAILABLE: &str = "native_connector_setup_context_store_unavailable";
const REQUEST_INVALID: &str = "native_connector_setup_context_request_invalid";
/// Longest list of tools or subcommands returned.
const MAX_LISTED: usize = 50;
const MCP_SURFACE: &str = "mcp";
const CLI_SURFACE: &str = "cli";

pub(crate) fn evaluate_connector_setup_context_request(
    request: &ConnectorSetupContextRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != CONNECTOR_SETUP_CONTEXT_REQUEST_SCHEMA {
        return Err("native_connector_setup_context_schema_mismatch".to_owned());
    }
    let (status, code, payload) = match record_and_advise(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    crate::resident_protocol::encode_response(&ConnectorSetupContextResultV1 {
        schema: CONNECTOR_SETUP_CONTEXT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

fn request_digest(request: &ConnectorSetupContextRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request).map_err(|_| REQUEST_INVALID.to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| REQUEST_INVALID.to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

/// The observation a request names, as stored.
struct Observation {
    surface: String,
    first_blocked_cause: Option<String>,
}

fn record_and_advise(request: &ConnectorSetupContextRequestV1) -> Result<Value, &'static str> {
    let store_path = local_store_read::require_store_path(&request.store_path, &request.guard_home)
        .map_err(store_error)?;
    validate(request)?;
    let connection = local_store_read::open_read_only(&store_path)
        .map_err(store_error)?
        .ok_or(STORE_UNAVAILABLE)?;
    require_current_schema(&connection)?;
    require_observation(&connection, request)?;
    record_context(request)?;
    // The write above commits on its own connection; this read starts after it.
    let observation = load_observation(&connection, request)?;
    let resolution = resolution_state(&connection, &request.cli_id, &request.identity_hash)?;
    let commands = load_commands(&connection, request, &observation.surface, resolution)?;
    Ok(json!({
        "cli_id": request.cli_id,
        "identity_hash": request.identity_hash,
        "surface": observation.surface,
        "first_blocked_cause": observation.first_blocked_cause,
        "resolution_state": resolution,
        "allowed_alternatives": allowed_alternatives(&observation.surface, &commands),
        "card_recommendation": card_recommendation(&observation, &commands),
    }))
}

fn validate(request: &ConnectorSetupContextRequestV1) -> Result<(), &'static str> {
    let identity = &request.identity_hash;
    if !is_local_cli_id(&request.cli_id)
        || identity.is_empty()
        || identity.len() > MAX_IDENTITY_HASH_BYTES
        || !identity.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(REQUEST_INVALID);
    }
    if request
        .first_blocked_cause
        .as_deref()
        .is_some_and(|cause| !is_first_blocked_cause(cause))
    {
        return Err("native_connector_setup_context_cause_invalid");
    }
    let oversized = [
        &request.trigger_summary,
        &request.why_now,
        &request.harness,
        &request.workspace_label,
    ]
    .into_iter()
    .flatten()
    .any(|text| text.len() > MAX_RAW_FIELD_BYTES);
    if oversized {
        return Err(REQUEST_INVALID);
    }
    Ok(())
}

/// Exactly this build's schema: a newer store is unsupported, an older one has
/// no context columns yet, and a damaged marker is never trusted.
fn require_current_schema(connection: &Connection) -> Result<(), &'static str> {
    match local_store_read::schema_version(connection).map_err(store_error)? {
        Some(version) if version > local_store_read::SUPPORTED_SCHEMA_VERSION => {
            Err("native_connector_setup_context_schema_unsupported")
        }
        Some(version) if version == local_store_read::SUPPORTED_SCHEMA_VERSION => {
            let columns = local_store_read::column_exists(
                connection,
                "local_cli_observation",
                "first_blocked_cause",
            )
            .map_err(store_error)?;
            if columns {
                Ok(())
            } else {
                Err("native_connector_setup_context_schema_outdated")
            }
        }
        _ => Err("native_connector_setup_context_schema_outdated"),
    }
}

fn require_observation(
    connection: &Connection,
    request: &ConnectorSetupContextRequestV1,
) -> Result<(), &'static str> {
    load_observation(connection, request).map(|_| ())
}

fn load_observation(
    connection: &Connection,
    request: &ConnectorSetupContextRequestV1,
) -> Result<Observation, &'static str> {
    let row: Option<(String, String, Option<String>)> = connection
        .query_row(
            "select identity_hash, surface, first_blocked_cause from local_cli_observation \
             where cli_id = ?1",
            params![request.cli_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    let Some((identity_hash, surface, first_blocked_cause)) = row else {
        return Err("native_connector_setup_context_observation_missing");
    };
    if identity_hash != request.identity_hash {
        return Err("native_connector_setup_context_identity_mismatch");
    }
    Ok(Observation {
        surface,
        first_blocked_cause,
    })
}

/// The one write: the scrubbed context columns, through the store method that
/// owns them.
fn record_context(request: &ConnectorSetupContextRequestV1) -> Result<(), &'static str> {
    let mut args = Map::new();
    args.insert("cli_id".to_owned(), json!(request.cli_id));
    args.insert("identity_hash".to_owned(), json!(request.identity_hash));
    args.insert(
        "first_blocked_cause".to_owned(),
        json!(request.first_blocked_cause),
    );
    args.insert("trigger_summary".to_owned(), json!(request.trigger_summary));
    args.insert("why_now".to_owned(), json!(request.why_now));
    args.insert("harness".to_owned(), json!(request.harness));
    args.insert("workspace_label".to_owned(), json!(request.workspace_label));
    args.insert("observed_at".to_owned(), json!(request.observed_at));
    crate::guard_store_op::evaluate(&GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        store_path: request.store_path.clone(),
        guard_home: request.guard_home.clone(),
        method: "record_connector_setup_context".to_owned(),
        source: request.source.clone(),
        busy_timeout_ms: request.busy_timeout_ms,
        args,
    })
    // The store's own code keeps the SQLite failure class.
    .map_err(|error| error.code())
    .and_then(|(changed, _)| match changed.as_i64() {
        // The observation vanished or changed identity after it was checked:
        // no context was kept, so no advice is given for it.
        Some(0) => Err("native_connector_setup_context_observation_missing"),
        _ => Ok(()),
    })
}

/// Derived from the grant each time, never stored: `allowed` or `blocked` while
/// the grant covers this identity, otherwise `unset`.
fn resolution_state(
    connection: &Connection,
    cli_id: &str,
    identity_hash: &str,
) -> Result<&'static str, &'static str> {
    if !table_exists(connection, "local_cli_grant")? {
        return Ok("unset");
    }
    let row: Option<(String, String)> = connection
        .query_row(
            "select identity_hash, state from local_cli_grant where cli_id = ?1",
            params![cli_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    Ok(match row {
        Some((stored, state)) if stored == identity_hash => match state.as_str() {
            "allowed" => "allowed",
            "blocked" => "blocked",
            _ => "unset",
        },
        _ => "unset",
    })
}

/// What the connector is known to offer, and what this device already allows.
struct Commands {
    /// Typed catalog commands as `(command id, display name)`, without the
    /// pseudo ids `root` and `other`.
    seen: Vec<(String, String)>,
    /// Command ids this device allows now.
    allowed: BTreeSet<String>,
}

impl Commands {
    /// Allowed entries as the caller names them: tool names for an MCP
    /// connector, command ids for a CLI.
    fn allowed_labels(&self, surface: &str) -> Vec<String> {
        self.labels(surface, true)
    }

    fn seen_labels(&self, surface: &str) -> Vec<String> {
        self.labels(surface, false)
    }

    fn labels(&self, surface: &str, only_allowed: bool) -> Vec<String> {
        let mut labels: Vec<String> = self
            .seen
            .iter()
            .filter(|(id, _)| !only_allowed || self.allowed.contains(id))
            .map(|(id, name)| {
                if surface == MCP_SURFACE {
                    name.clone()
                } else {
                    id.clone()
                }
            })
            .collect();
        labels.sort();
        labels.dedup();
        labels.truncate(MAX_LISTED);
        labels
    }
}

/// The commands the connector has been seen with, and those this device
/// allows. Nothing is allowed unless the connector's grant is allowed for this
/// identity and the command's own state is `allow`. An MCP tool must also be
/// in the connector's current catalog snapshot, and not one the live decision
/// always reviews per call, as the live decision requires. Checks that need
/// the live call (its action and authority digest) are not claimed here.
fn load_commands(
    connection: &Connection,
    request: &ConnectorSetupContextRequestV1,
    surface: &str,
    resolution: &str,
) -> Result<Commands, &'static str> {
    let seen = catalog_commands(connection, &request.cli_id)?;
    if resolution != "allowed" {
        return Ok(Commands {
            seen,
            allowed: BTreeSet::new(),
        });
    }
    let listed = if surface == MCP_SURFACE {
        current_tool_ids(connection, request)?
    } else {
        None
    };
    let states = allowed_command_ids(connection, &request.cli_id)?;
    let allowed = seen
        .iter()
        .filter(|(id, name)| {
            states.contains(id)
                && listed.as_ref().is_none_or(|ids| ids.contains(id))
                && !(surface == MCP_SURFACE && composio_requires_action_review(name))
        })
        .map(|(id, _)| id.clone())
        .collect();
    Ok(Commands { seen, allowed })
}

fn catalog_commands(
    connection: &Connection,
    cli_id: &str,
) -> Result<Vec<(String, String)>, &'static str> {
    if !table_exists(connection, "local_cli_command")? {
        return Ok(Vec::new());
    }
    // A row counts only when every column has its declared type.
    let mut statement = connection
        .prepare(
            "select command_id, name from local_cli_command where cli_id = ?1 \
             and typeof(command_id) = 'text' and typeof(name) = 'text' \
             and typeof(usage) = 'text' and typeof(description) = 'text' \
             and (parent_id is null or typeof(parent_id) = 'text') \
             and command_id not in ('root', 'other') order by command_id",
        )
        .map_err(|_| STORE_UNAVAILABLE)?;
    let rows = statement
        .query_map(params![cli_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| STORE_UNAVAILABLE)?;
    rows.map(|row| row.map_err(|_| STORE_UNAVAILABLE)).collect()
}

fn allowed_command_ids(
    connection: &Connection,
    cli_id: &str,
) -> Result<BTreeSet<String>, &'static str> {
    if !table_exists(connection, "local_cli_command_grant")? {
        return Ok(BTreeSet::new());
    }
    let mut statement = connection
        .prepare(
            "select command_id from local_cli_command_grant where cli_id = ?1 \
             and typeof(command_id) = 'text' and typeof(state) = 'text' and state = 'allow'",
        )
        .map_err(|_| STORE_UNAVAILABLE)?;
    let rows = statement
        .query_map(params![cli_id], |row| row.get::<_, String>(0))
        .map_err(|_| STORE_UNAVAILABLE)?;
    rows.map(|row| row.map_err(|_| STORE_UNAVAILABLE)).collect()
}

/// Command ids of the tools in the connector's current catalog snapshot, or
/// `None` while it has no snapshot (an observed connector the daemon has not
/// listed yet), when the live decision applies no snapshot check either.
fn current_tool_ids(
    connection: &Connection,
    request: &ConnectorSetupContextRequestV1,
) -> Result<Option<BTreeSet<String>>, &'static str> {
    if !table_exists(connection, "local_mcp_catalog")? {
        return Ok(None);
    }
    let revision: Option<i64> = connection
        .query_row(
            "select revision from local_mcp_catalog where cli_id = ?1 and identity_hash = ?2",
            params![request.cli_id, request.identity_hash],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    let Some(revision) = revision else {
        return Ok(None);
    };
    if !table_exists(connection, "local_mcp_tool_authority")? {
        return Ok(Some(BTreeSet::new()));
    }
    let mut statement = connection
        .prepare(
            "select tool_name from local_mcp_tool_authority where cli_id = ?1 \
             and identity_hash = ?2 and catalog_revision = ?3 and typeof(tool_name) = 'text'",
        )
        .map_err(|_| STORE_UNAVAILABLE)?;
    let rows = statement
        .query_map(
            params![request.cli_id, request.identity_hash, revision],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| STORE_UNAVAILABLE)?;
    let mut ids = BTreeSet::new();
    for row in rows {
        ids.insert(slug_command_id(&row.map_err(|_| STORE_UNAVAILABLE)?));
    }
    Ok(Some(ids))
}

/// What the person has already allowed in this connector's namespace: tools
/// for an MCP connector, subcommands for a CLI. The list that does not apply
/// is empty. This device has no catalog-contribution source for a connector,
/// so that list is always empty.
fn allowed_alternatives(surface: &str, commands: &Commands) -> Value {
    let allowed = commands.allowed_labels(surface);
    let (tools, subcommands) = if surface == MCP_SURFACE {
        (allowed, Vec::new())
    } else {
        (Vec::new(), allowed)
    };
    json!({
        "tools": tools,
        "subcommands": subcommands,
        "catalog_contributions": Vec::<String>::new(),
    })
}

/// The setup choice Guard would put on the card. It starts off: nothing is
/// preselected, and the person decides.
///
/// An MCP connector recommends allowing the tools already seen and reviewing
/// any other. A CLI recommends the one capability its first cause implies.
fn card_recommendation(observation: &Observation, commands: &Commands) -> Value {
    if observation.surface == MCP_SURFACE {
        return json!({
            "kind": "mcp-tools",
            "seen_tools": commands.seen_labels(MCP_SURFACE),
            "seen_tools_action": "allow",
            "other_tools_action": "review",
            "preselected": false,
        });
    }
    let capability = if observation.surface == CLI_SURFACE {
        observation
            .first_blocked_cause
            .as_deref()
            .and_then(implied_capability)
    } else {
        None
    };
    json!({
        "kind": "cli-capability",
        "capability": capability,
        "preselected": false,
    })
}

/// The grant capability a first cause points at; the others imply none.
fn implied_capability(cause: &str) -> Option<&'static str> {
    match cause {
        "connect_loopback" => Some("loopback-network"),
        "read_home_state" => Some("state-dir-read"),
        "write_home_state" => Some("state-dir-write"),
        _ => None,
    }
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, &'static str> {
    local_store_read::table_exists(connection, table).map_err(store_error)
}

fn store_error(error: StoreReadError) -> &'static str {
    match error {
        StoreReadError::PathInvalid => "native_connector_setup_context_path_invalid",
        StoreReadError::StoreUnavailable => STORE_UNAVAILABLE,
        StoreReadError::SchemaInvalid => "native_connector_setup_context_schema_invalid",
    }
}

#[cfg(test)]
#[path = "connector_setup_context_op_refusal_tests.rs"]
mod refusal_tests;
#[cfg(test)]
#[path = "connector_setup_context_op_tests.rs"]
mod tests;
