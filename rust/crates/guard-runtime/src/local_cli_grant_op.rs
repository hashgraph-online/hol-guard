//! `LocalCliGrantDecide` — the native decision for this-device local CLI
//! allow and block grants.
//!
//! Rust derives the CLI identity from the verified launch material, reads the
//! grant, command catalog, per-command states, and observation surface from
//! `guard.db` itself, and composes the result. The caller supplies only the
//! launch material, the action being refined, and the command id it resolved
//! from the command model; none of those can create a grant.

use std::path::{Path, PathBuf};

use guard_contracts::{
    LocalCliGrantRequestV1, LocalCliGrantResultV1, LocalCliIdentitySourceV1,
    LOCAL_CLI_GRANT_REQUEST_SCHEMA, LOCAL_CLI_GRANT_RESULT_SCHEMA,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};

const STORE_FILE_NAME: &str = "guard.db";
const ROOT_COMMAND_ID: &str = "root";
const OTHER_COMMAND_ID: &str = "other";
const PACKAGE_SCRIPT_SURFACE: &str = "package-scripts";
const SUPPORTED_SCHEMA_VERSION: i64 = 11;
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
    let store_path = require_store_path(&request.store_path, &request.guard_home)?;
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
    let Some(connection) = open_read_only(&store_path)? else {
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

/// `store_path` must be `guard.db` directly under `guard_home`, so a request
/// cannot point the resident at another database.
fn require_store_path(store_path: &str, guard_home: &str) -> Result<PathBuf, &'static str> {
    const INVALID: &str = "native_local_cli_grant_path_invalid";
    let (store, home) = (Path::new(store_path), Path::new(guard_home));
    if !store.is_absolute() || !home.is_absolute() {
        return Err(INVALID);
    }
    if store.file_name().and_then(|name| name.to_str()) != Some(STORE_FILE_NAME) {
        return Err(INVALID);
    }
    let parent = store.parent().ok_or(INVALID)?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(|_| INVALID)?;
    let canonical_home = std::fs::canonicalize(home).map_err(|_| INVALID)?;
    if canonical_parent != canonical_home {
        return Err(INVALID);
    }
    Ok(canonical_home.join(STORE_FILE_NAME))
}

/// `Ok(None)` means the store does not exist yet, so no grant can either.
fn open_read_only(store_path: &Path) -> Result<Option<Connection>, &'static str> {
    if !store_path.exists() {
        return Ok(None);
    }
    let connection = Connection::open_with_flags(store_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| "native_local_cli_grant_store_unavailable")?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| "native_local_cli_grant_store_unavailable")?;
    Ok(Some(connection))
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

/// A store written by a newer Guard stays unreadable rather than guessed at,
/// and a marker whose checksum does not match its version is treated as
/// damage, the same way the store's own schema validator treats it.
fn require_supported_schema(connection: &Connection) -> Result<(), &'static str> {
    if !table_exists(connection, "local_cli_schema_migration")? {
        return Ok(());
    }
    let marker: Option<(i64, String)> = connection
        .query_row(
            "select version, checksum from local_cli_schema_migration where singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| STORE_UNAVAILABLE)?;
    let Some((version, checksum)) = marker else {
        return Ok(());
    };
    if version > SUPPORTED_SCHEMA_VERSION {
        return Err("native_local_cli_grant_schema_unsupported");
    }
    if version < 1 || checksum != schema_checksum(version) {
        return Err("native_local_cli_grant_schema_invalid");
    }
    Ok(())
}

pub(crate) fn schema_checksum(version: i64) -> String {
    guard_policy_snapshot::digest_bytes(
        format!("hol-guard.local-cli-allowlist.schema.v{version}").as_bytes(),
    )
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, &'static str> {
    connection
        .query_row(
            "select 1 from sqlite_master where type = 'table' and name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()
        .map(|found| found.is_some())
        .map_err(|_| STORE_UNAVAILABLE)
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
    let has_surface = table_exists(connection, "local_cli_observation")?
        && connection
            .query_row(
                "select 1 from pragma_table_info('local_cli_observation') where name = 'surface'",
                [],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| STORE_UNAVAILABLE)?
            .is_some();
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
