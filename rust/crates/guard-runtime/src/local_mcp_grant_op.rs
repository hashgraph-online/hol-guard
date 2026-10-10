//! `LocalMcpGrantDecide` — the native decision for this-device MCP grants.
//!
//! Rust reads the observation, grant, command catalog, per-tool states, and
//! catalog authority from `guard.db` itself and composes the answer for a live
//! `tools/call`. The caller supplies only the server identity fields recorded
//! in artifact metadata, the tool name, the live authority digest, and the
//! connection identity digest; none of those can create a grant.

use guard_contracts::{
    LocalMcpGrantRequestV1, LocalMcpGrantResultV1, LOCAL_MCP_GRANT_REQUEST_SCHEMA,
    LOCAL_MCP_GRANT_RESULT_SCHEMA,
};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde_json::{json, Value};

use crate::local_mcp_grant_identity::{
    composio_requires_action_review, normalized_hash, observed_mcp_tool, slug_command_id,
    OTHER_COMMAND_ID,
};
use crate::local_mcp_grant_launcher::equivalent_package_launcher_observation;
use crate::local_store_read::{self, StoreReadError};

const UNBOUND_PREFIX: &str = "guard-context-unbound:";
const MAX_LAUNCHER_ENV_BYTES: usize = 32 * 1024;
const MAX_TEXT_BYTES: usize = 4096;
pub(crate) const STORE_UNAVAILABLE: &str = "native_local_mcp_grant_store_unavailable";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpGrantState {
    Allowed,
    Blocked,
    Review,
    None,
}

impl McpGrantState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::Review => "review",
            Self::None => "none",
        }
    }
}

/// The server identity a call is looked up under.
struct Target {
    identity_hash: String,
    command_id: String,
    /// `None` for an observed connector, which has no configured connection.
    connection_identity_hash: Option<String>,
    observed: bool,
}

pub(crate) struct Observation {
    pub(crate) cli_id: String,
    pub(crate) identity_hash: String,
}

pub(crate) fn evaluate_local_mcp_grant_request(
    request: &LocalMcpGrantRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != LOCAL_MCP_GRANT_REQUEST_SCHEMA {
        return Err("native_local_mcp_grant_schema_mismatch".to_owned());
    }
    let (status, code, payload) = match decide(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    crate::resident_protocol::encode_response(&LocalMcpGrantResultV1 {
        schema: LOCAL_MCP_GRANT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

fn request_digest(request: &LocalMcpGrantRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request)
        .map_err(|_| "native_local_mcp_grant_request_invalid".to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_local_mcp_grant_request_invalid".to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

fn store_error(error: StoreReadError) -> &'static str {
    match error {
        StoreReadError::PathInvalid => "native_local_mcp_grant_path_invalid",
        StoreReadError::StoreUnavailable => STORE_UNAVAILABLE,
        StoreReadError::SchemaInvalid => "native_local_mcp_grant_schema_invalid",
    }
}

fn outcome(state: McpGrantState, observation: Option<&Observation>) -> Value {
    json!({
        "state": state.as_str(),
        "cli_id": observation.map(|found| found.cli_id.as_str()),
        "identity_hash": observation.map(|found| found.identity_hash.as_str()),
    })
}

fn validate(request: &LocalMcpGrantRequestV1) -> Result<(), &'static str> {
    const INVALID: &str = "native_local_mcp_grant_request_invalid";
    let server = &request.server;
    let bounded =
        |value: &Option<String>, limit: usize| value.as_ref().is_none_or(|v| v.len() <= limit);
    let valid = request.tool_name.len() <= MAX_TEXT_BYTES
        && request.harness.len() <= MAX_TEXT_BYTES
        && bounded(&server.command, MAX_TEXT_BYTES)
        && bounded(&server.package_name, MAX_TEXT_BYTES)
        && bounded(&server.package_version, MAX_TEXT_BYTES)
        && bounded(&server.package_source, MAX_TEXT_BYTES)
        && bounded(&server.env_values_hash, MAX_TEXT_BYTES)
        && bounded(&server.identity_hash, MAX_TEXT_BYTES)
        && bounded(&server.transport, MAX_TEXT_BYTES)
        && bounded(&request.tool_authority_hash, MAX_TEXT_BYTES)
        && bounded(&request.launcher_path, MAX_LAUNCHER_ENV_BYTES)
        && bounded(&request.launcher_home, MAX_TEXT_BYTES)
        // The caller computes this mechanically; anything else is not a digest.
        && request
            .connection_identity_hash
            .as_deref()
            .is_none_or(|hash| normalized_hash(Some(hash)).is_some());
    if valid {
        Ok(())
    } else {
        Err(INVALID)
    }
}

fn decide(request: &LocalMcpGrantRequestV1) -> Result<Value, &'static str> {
    let store_path = local_store_read::require_store_path(&request.store_path, &request.guard_home)
        .map_err(store_error)?;
    validate(request)?;
    if !matches!(
        request.current_action.as_str(),
        "allow" | "review" | "require-reapproval" | "warn"
    ) {
        return Ok(outcome(McpGrantState::None, None));
    }
    let Some(target) = resolve_target(request) else {
        return Ok(outcome(McpGrantState::None, None));
    };
    // An unverifiable configured environment cannot satisfy any binding.
    if request
        .server
        .env_values_hash
        .as_deref()
        .is_some_and(|hash| hash.starts_with(UNBOUND_PREFIX))
    {
        return Ok(outcome(McpGrantState::None, None));
    }
    let Some(connection) = local_store_read::open_read_only(&store_path).map_err(store_error)?
    else {
        return Ok(outcome(McpGrantState::None, None));
    };
    // One deferred read transaction pins a single snapshot for the schema check
    // and every grant read below. Autocommit reads would each see the latest
    // commit, so a writer revoking a server while allowing one of its tools could
    // be read as the old parent grant plus the new tool state.
    let snapshot = connection
        .unchecked_transaction()
        .map_err(|_| STORE_UNAVAILABLE)?;
    require_readable_schema(&snapshot)?;
    let (state, observation) = grant_decision(&snapshot, request, &target)?;
    Ok(outcome(state, observation.as_ref()))
}

/// Observed connectors derive their identity here from the harness and tool
/// name. A configured server uses the metadata hash and its connection.
fn resolve_target(request: &LocalMcpGrantRequestV1) -> Option<Target> {
    let server = &request.server;
    let server_hash = normalized_hash(server.identity_hash.as_deref());
    let observed_transport = server.transport.as_deref() == Some("observed");
    match server_hash {
        Some(identity_hash) if !observed_transport => Some(Target {
            identity_hash,
            command_id: slug_command_id(&request.tool_name),
            connection_identity_hash: request
                .connection_identity_hash
                .as_deref()
                .and_then(|hash| normalized_hash(Some(hash))),
            observed: false,
        }),
        _ => {
            let observed = observed_mcp_tool(&request.harness, &request.tool_name)?;
            Some(Target {
                identity_hash: observed.identity_hash,
                command_id: observed.command_id,
                connection_identity_hash: None,
                observed: true,
            })
        }
    }
}

/// A store written by a newer Guard stays unreadable rather than guessed at.
/// An older store would be migrated by the Python writer first; refusing keeps
/// a stored block from silently vanishing in the meantime.
fn require_readable_schema(connection: &Connection) -> Result<(), &'static str> {
    match local_store_read::schema_version(connection).map_err(store_error)? {
        Some(version) if version > local_store_read::SUPPORTED_SCHEMA_VERSION => {
            Err("native_local_mcp_grant_schema_unsupported")
        }
        Some(version) if version < local_store_read::SUPPORTED_SCHEMA_VERSION => {
            Err("native_local_mcp_grant_schema_outdated")
        }
        _ => Ok(()),
    }
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, &'static str> {
    local_store_read::table_exists(connection, table).map_err(store_error)
}

fn grant_decision(
    connection: &Connection,
    request: &LocalMcpGrantRequestV1,
    target: &Target,
) -> Result<(McpGrantState, Option<Observation>), &'static str> {
    const NONE: (McpGrantState, Option<Observation>) = (McpGrantState::None, Option::None);
    // Every read below must share one snapshot; see `decide`.
    debug_assert!(
        !connection.is_autocommit(),
        "grant decision reads must run inside one read transaction"
    );
    if !table_exists(connection, "local_cli_observation")?
        || !table_exists(connection, "local_cli_grant")?
    {
        return Ok(NONE);
    }
    let Some(observation) = find_observation(connection, request, target)? else {
        return Ok(NONE);
    };
    let grant: Option<(SqlValue, SqlValue)> = connection
        .query_row(
            "select identity_hash, state from local_cli_grant where cli_id = ?1",
            params![observation.cli_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    let (SqlValue::Text(stored_hash), SqlValue::Text(raw_state)) =
        grant.unwrap_or((SqlValue::Null, SqlValue::Null))
    else {
        return Ok(NONE);
    };
    if stored_hash != observation.identity_hash
        || !matches!(raw_state.as_str(), "allowed" | "blocked")
    {
        return Ok(NONE);
    }
    let state = if raw_state == "blocked" {
        McpGrantState::Blocked
    } else {
        allowed_grant_decision(connection, request, target, &observation)?
    };
    Ok((state, Some(observation)))
}

/// The grant is allowed; decide for the called tool.
fn allowed_grant_decision(
    connection: &Connection,
    request: &LocalMcpGrantRequestV1,
    target: &Target,
    observation: &Observation,
) -> Result<McpGrantState, &'static str> {
    let cli_id = &observation.cli_id;
    let known = catalog_has_command(connection, cli_id, &target.command_id)?;
    let tool_state = command_state(connection, cli_id, &target.command_id)?;
    if !known {
        // Enrollment cannot grant unseen tools. Retired exact denies survive a
        // removal, including removal of every tool in the inventory.
        let other_block =
            command_state(connection, cli_id, OTHER_COMMAND_ID)?.as_deref() == Some("block");
        return Ok(if tool_state.as_deref() == Some("block") || other_block {
            McpGrantState::Blocked
        } else {
            McpGrantState::Review
        });
    }
    match tool_state.as_deref().unwrap_or("inherit") {
        "review" => Ok(McpGrantState::Review),
        "block" => Ok(McpGrantState::Blocked),
        "allow" => allowed_tool_decision(connection, request, target, observation),
        _ => Ok(McpGrantState::None),
    }
}

fn allowed_tool_decision(
    connection: &Connection,
    request: &LocalMcpGrantRequestV1,
    target: &Target,
    observation: &Observation,
) -> Result<McpGrantState, &'static str> {
    if composio_requires_action_review(&request.tool_name)
        || request.current_action == "require-reapproval"
    {
        return Ok(McpGrantState::None);
    }
    let catalog = catalog_authority(connection, observation, &request.tool_name)?;
    let connection_bound = target
        .connection_identity_hash
        .as_deref()
        .is_some_and(|hash| hash == observation.identity_hash);
    if catalog.is_some() || connection_bound {
        // An absent or invalid live digest must fail closed.
        let matches = matches!(
            (&catalog, request.tool_authority_hash.as_deref()),
            (Some(Some(stored)), Some(live)) if stored == live
        );
        if !matches {
            return Ok(McpGrantState::Review);
        }
    }
    Ok(McpGrantState::Allowed)
}

pub(crate) fn text(row: &Row<'_>, index: usize) -> Option<String> {
    match row.get::<_, SqlValue>(index) {
        Ok(SqlValue::Text(value)) => Some(value),
        _ => None,
    }
}

fn observation_row(row: &Row<'_>) -> rusqlite::Result<Option<Observation>> {
    Ok(text(row, 0)
        .zip(text(row, 1))
        .map(|(cli_id, identity_hash)| Observation {
            cli_id,
            identity_hash,
        }))
}

fn find_observation(
    connection: &Connection,
    request: &LocalMcpGrantRequestV1,
    target: &Target,
) -> Result<Option<Observation>, &'static str> {
    const BY_HASH: &str = "select cli_id, identity_hash from local_cli_observation \
        where surface = 'mcp' and identity_hash = ?1 \
        and (server_identity_hash = ?2 or server_identity_hash is null) \
        order by last_seen_at desc, cli_id asc limit 1";
    let by_hash = |lookup: &str| -> Result<Option<Observation>, &'static str> {
        connection
            .query_row(
                BY_HASH,
                params![lookup, target.identity_hash],
                observation_row,
            )
            .optional()
            .map(Option::flatten)
            .map_err(|_| STORE_UNAVAILABLE)
    };
    // Configured connections are host/configuration scoped. A legacy
    // server-wide row must never satisfy a different connection's call.
    let lookup = target
        .connection_identity_hash
        .as_deref()
        .unwrap_or(&target.identity_hash);
    if let Some(found) = by_hash(lookup)? {
        return Ok(Some(found));
    }
    if target.connection_identity_hash.is_some() {
        // Pre-connection grants are compatible only before this server has any
        // configured connection; once discovered, a missing exact match stays
        // missing.
        let configured = connection
            .query_row(
                "select 1 from local_cli_observation where surface = 'mcp' \
                 and server_identity_hash = ?1 and identity_hash != ?1 limit 1",
                params![target.identity_hash],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| STORE_UNAVAILABLE)?;
        if configured.is_some() {
            return Ok(None);
        }
        if let Some(found) = by_hash(&target.identity_hash)? {
            return Ok(Some(found));
        }
    }
    if target.observed {
        // An observed connector has no launcher to be equivalent to.
        return Ok(None);
    }
    equivalent_package_launcher_observation(connection, request)
}

fn catalog_has_command(
    connection: &Connection,
    cli_id: &str,
    command_id: &str,
) -> Result<bool, &'static str> {
    if !table_exists(connection, "local_cli_command")? {
        return Ok(false);
    }
    // A row counts only when every column has its declared type, so a damaged
    // row cannot pose as catalog presence.
    connection
        .query_row(
            "select exists(select 1 from local_cli_command where cli_id = ?1 and command_id = ?2 \
             and typeof(name) = 'text' and typeof(usage) = 'text' and typeof(description) = 'text' \
             and (parent_id is null or typeof(parent_id) = 'text'))",
            params![cli_id, command_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| STORE_UNAVAILABLE)
}

/// Stored per-tool state; an unknown value is not a state at all.
fn command_state(
    connection: &Connection,
    cli_id: &str,
    command_id: &str,
) -> Result<Option<String>, &'static str> {
    if !table_exists(connection, "local_cli_command_grant")? {
        return Ok(None);
    }
    let raw: Option<SqlValue> = connection
        .query_row(
            "select state from local_cli_command_grant where cli_id = ?1 and command_id = ?2",
            params![cli_id, command_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    Ok(match raw {
        Some(SqlValue::Text(state))
            if matches!(state.as_str(), "inherit" | "allow" | "review" | "block") =>
        {
            Some(state)
        }
        _ => None,
    })
}

/// `None` without a catalog snapshot for this identity; otherwise the stored
/// authority digest of the tool in that snapshot, when it has one.
fn catalog_authority(
    connection: &Connection,
    observation: &Observation,
    tool_name: &str,
) -> Result<Option<Option<String>>, &'static str> {
    if !table_exists(connection, "local_mcp_catalog")? {
        return Ok(None);
    }
    let revision: Option<i64> = connection
        .query_row(
            "select revision from local_mcp_catalog where cli_id = ?1 and identity_hash = ?2",
            params![observation.cli_id, observation.identity_hash],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    let Some(revision) = revision else {
        return Ok(None);
    };
    if !table_exists(connection, "local_mcp_tool_authority")? {
        return Ok(Some(None));
    }
    let stored: Option<SqlValue> = connection
        .query_row(
            "select authority_hash from local_mcp_tool_authority where cli_id = ?1 \
             and identity_hash = ?2 and catalog_revision = ?3 and tool_name = ?4",
            params![
                observation.cli_id,
                observation.identity_hash,
                revision,
                tool_name
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    Ok(Some(match stored {
        Some(SqlValue::Text(hash)) => Some(hash),
        _ => None,
    }))
}

#[cfg(test)]
#[path = "local_mcp_grant_op_tests.rs"]
mod tests;
