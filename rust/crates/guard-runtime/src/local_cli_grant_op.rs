//! `LocalCliGrantDecide` — the native decision for this-device local CLI
//! allow and block grants.
//!
//! Rust derives the CLI identity from the verified launch material, reads the
//! grant, command catalog, per-command states, and observation surface from
//! `guard.db` itself, and composes the result. The caller supplies only the
//! launch material, the action being refined, and the command id it resolved
//! from the command model; none of those can create a grant.

use guard_contracts::{
    LocalCliGrantRequestV1, LocalCliGrantResultV1, LocalCliIdentitySourceV1,
    LOCAL_CLI_GRANT_REQUEST_SCHEMA, LOCAL_CLI_GRANT_RESULT_SCHEMA,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::local_store_read::{self, StoreReadError};

const ROOT_COMMAND_ID: &str = "root";
const OTHER_COMMAND_ID: &str = "other";
const PACKAGE_SCRIPT_SURFACE: &str = "package-scripts";
const MAX_COMMAND_ID_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantState {
    Allowed,
    Blocked,
    None,
}

impl GrantState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandState {
    Inherit,
    Allow,
    Block,
}

pub(crate) fn evaluate_local_cli_grant_request(
    request: &LocalCliGrantRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != LOCAL_CLI_GRANT_REQUEST_SCHEMA {
        return Err("native_local_cli_grant_schema_mismatch".to_owned());
    }
    let (status, code, payload) = match decide(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    crate::resident_protocol::encode_response(&LocalCliGrantResultV1 {
        schema: LOCAL_CLI_GRANT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

fn request_digest(request: &LocalCliGrantRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request)
        .map_err(|_| "native_local_cli_grant_request_invalid".to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_local_cli_grant_request_invalid".to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

fn decide(request: &LocalCliGrantRequestV1) -> Result<Value, &'static str> {
    let store_path = local_store_read::require_store_path(&request.store_path, &request.guard_home)
        .map_err(store_error)?;
    if let Some(id) = request.command_id.as_deref() {
        if id.is_empty() || id.len() > MAX_COMMAND_ID_BYTES || !id.is_ascii() {
            return Err("native_local_cli_grant_command_invalid");
        }
    }
    let Some(identity) = crate::context_digest_local_cli::local_cli_identity(&request.source)
        .map_err(|_| "native_local_cli_grant_identity_invalid")?
    else {
        return Ok(outcome(GrantState::None, None, None));
    };
    let reply = |state| outcome(state, Some(&identity.cli_id), Some(&identity.identity_hash));
    if !matches!(
        request.current_action.as_str(),
        "allow" | "review" | "require-reapproval" | "warn"
    ) {
        return Ok(reply(GrantState::None));
    }
    let Some(connection) = local_store_read::open_read_only(&store_path).map_err(store_error)?
    else {
        return Ok(reply(GrantState::None));
    };
    let registry_package = matches!(
        request.source,
        LocalCliIdentitySourceV1::RegistryPackage { .. }
    );
    let state = grant_decision(
        &connection,
        &identity.cli_id,
        &identity.identity_hash,
        registry_package,
        request.command_id.as_deref().unwrap_or(OTHER_COMMAND_ID),
    )?;
    Ok(reply(state))
}

fn outcome(state: GrantState, cli_id: Option<&str>, identity_hash: Option<&str>) -> Value {
    json!({
        "state": state.as_str(),
        "cli_id": cli_id,
        "identity_hash": identity_hash,
    })
}

fn store_error(error: StoreReadError) -> &'static str {
    match error {
        StoreReadError::PathInvalid => "native_local_cli_grant_path_invalid",
        StoreReadError::StoreUnavailable => STORE_UNAVAILABLE,
        StoreReadError::SchemaInvalid => "native_local_cli_grant_schema_invalid",
    }
}

fn grant_decision(
    connection: &Connection,
    cli_id: &str,
    identity_hash: &str,
    registry_package: bool,
    command_id: &str,
) -> Result<GrantState, &'static str> {
    require_supported_schema(connection)?;
    if !table_exists(connection, "local_cli_grant")? {
        return Ok(GrantState::None);
    }
    let row: Option<(String, String)> = connection
        .query_row(
            "select identity_hash, state from local_cli_grant where cli_id = ?1",
            params![cli_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    let Some((stored_hash, raw_state)) = row else {
        return Ok(GrantState::None);
    };
    let allowed = match raw_state.as_str() {
        "allowed" => true,
        "blocked" => false,
        _ => return Ok(GrantState::None),
    };
    if stored_hash != identity_hash {
        return Ok(GrantState::None);
    }
    if !allowed {
        return Ok(GrantState::Blocked);
    }
    let command_state = if catalog_present(connection, cli_id)? {
        command_state(connection, cli_id, command_id)?
    } else {
        // Nothing to scope: the CLI-level allow covers every invocation.
        CommandState::Allow
    };
    if command_state == CommandState::Block {
        return Ok(GrantState::Blocked);
    }
    // A registry fetch runs whatever the registry serves, so only blocks bind.
    if registry_package {
        return Ok(GrantState::None);
    }
    if command_state == CommandState::Allow {
        return Ok(GrantState::Allowed);
    }
    if command_id != ROOT_COMMAND_ID
        && command_id != OTHER_COMMAND_ID
        && observation_surface(connection, cli_id)? == PACKAGE_SCRIPT_SURFACE
    {
        return Ok(GrantState::Allowed);
    }
    Ok(GrantState::None)
}

const STORE_UNAVAILABLE: &str = "native_local_cli_grant_store_unavailable";

/// A store written by a newer Guard stays unreadable rather than guessed at.
fn require_supported_schema(connection: &Connection) -> Result<(), &'static str> {
    match local_store_read::schema_version(connection).map_err(store_error)? {
        Some(version) if version > local_store_read::SUPPORTED_SCHEMA_VERSION => {
            Err("native_local_cli_grant_schema_unsupported")
        }
        _ => Ok(()),
    }
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, &'static str> {
    local_store_read::table_exists(connection, table).map_err(store_error)
}

/// A row counts as catalog only when every column has its declared type, so a
/// damaged row cannot pose as scoping.
fn catalog_present(connection: &Connection, cli_id: &str) -> Result<bool, &'static str> {
    if !table_exists(connection, "local_cli_command")? {
        return Ok(false);
    }
    connection
        .query_row(
            "select exists(select 1 from local_cli_command where cli_id = ?1 \
             and typeof(command_id) = 'text' and typeof(name) = 'text' \
             and typeof(usage) = 'text' and typeof(description) = 'text' \
             and (parent_id is null or typeof(parent_id) = 'text'))",
            params![cli_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| STORE_UNAVAILABLE)
}

fn command_state(
    connection: &Connection,
    cli_id: &str,
    command_id: &str,
) -> Result<CommandState, &'static str> {
    if !table_exists(connection, "local_cli_command_grant")? {
        return Ok(CommandState::Inherit);
    }
    let raw: Option<String> = connection
        .query_row(
            "select state from local_cli_command_grant where cli_id = ?1 and command_id = ?2",
            params![cli_id, command_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    Ok(match raw.as_deref() {
        Some("allow") => CommandState::Allow,
        Some("block") => CommandState::Block,
        // `review` and anything unknown are not CLI command states.
        _ => CommandState::Inherit,
    })
}

fn observation_surface(connection: &Connection, cli_id: &str) -> Result<String, &'static str> {
    let has_surface =
        local_store_read::column_exists(connection, "local_cli_observation", "surface")
            .map_err(store_error)?;
    if !has_surface {
        return Ok("cli".to_owned());
    }
    let surface: Option<String> = connection
        .query_row(
            "select surface from local_cli_observation where cli_id = ?1",
            params![cli_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    Ok(surface.unwrap_or_else(|| "cli".to_owned()))
}

#[cfg(test)]
#[path = "local_cli_grant_op_tests.rs"]
mod tests;
