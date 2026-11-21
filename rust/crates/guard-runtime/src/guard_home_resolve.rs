//! `guard-home-resolve --stdin`: pick the Guard home beneath one user home,
//! moving a legacy home with state into `.hol-guard` first (`config.py`
//! before it moved here).
//!
//! The canonical home wins whenever it already holds state or sync
//! credentials. Otherwise a legacy home with either is staged into a private
//! folder beside the canonical home and renamed over it; if any step fails,
//! the legacy home stays in use and the canonical home is untouched.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use serde_json::json;

#[path = "guard_home_migration.rs"]
mod migration;

#[cfg(test)]
#[path = "guard_home_resolve_tests.rs"]
mod tests;

const SCHEMA: &str = "guard-home-resolve.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const CANONICAL_DIRNAME: &str = ".hol-guard";
/// Older Guard homes, in the order Guard looks for them.
const LEGACY_DIRNAMES: [&str; 3] = [
    ".config/.ai-plugin-scanner-guard",
    ".ai-plugin-scanner-guard",
    ".holguard",
];
/// Live process files that never move between homes.
const NON_MIGRATED_FILES: [&str; 6] = [
    "daemon-state.json",
    "guard.db-journal",
    "guard.db-shm",
    "guard.db-wal",
    "schema-migration.lock",
    "storage-access.lock",
];
/// Files any started Guard writes before it holds real state.
const METADATA_FILES: [&str; 4] = [
    "oauth-keychain-access.json",
    "schema-migration.lock",
    "storage-access.lock",
    "system-keyring-availability.json",
];
/// Tables whose first row means the database holds real state.
const STATE_TABLES: [&str; 16] = [
    "harness_installations",
    "artifact_snapshots",
    "artifact_hashes",
    "artifact_diffs",
    "artifact_inventory",
    "policy_decisions",
    "runtime_receipts",
    "publisher_cache",
    "guard_events",
    "managed_installs",
    "guard_sessions",
    "guard_operations",
    "guard_operation_items",
    "guard_client_attachments",
    "guard_surface_opens",
    "approval_requests",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    user_home: PathBuf,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "guard-home-resolve"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "guard_home_resolve_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("guard_home_resolve_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "guard_home_resolve_request_invalid".to_owned())?;
    if request.schema != SCHEMA || !request.user_home.is_absolute() {
        return Err("guard_home_resolve_request_invalid".to_owned());
    }
    let guard_home = resolve(&request.user_home);
    serde_json::to_vec(&json!({ "guard_home": guard_home.to_string_lossy() }))
        .map_err(|_| "guard_home_resolve_response_unencodable".to_owned())
}

/// The Guard home to use beneath `user_home`, after moving legacy state.
fn resolve(user_home: &Path) -> PathBuf {
    let canonical = user_home.join(CANONICAL_DIRNAME);
    let Some(legacy) = LEGACY_DIRNAMES
        .iter()
        .map(|relative| user_home.join(relative))
        .find(|candidate| candidate.exists())
    else {
        return canonical;
    };
    if has_sync_credentials(&canonical) || has_state(&canonical) {
        return canonical;
    }
    if has_sync_credentials(&legacy) || has_state(&legacy) {
        return match migration::migrate_transactionally(&legacy, &canonical) {
            Ok(()) => canonical,
            Err(migration::Failed) => legacy,
        };
    }
    canonical
}

/// Whether `home`'s database holds a signed-in Guard Cloud connection.
fn has_sync_credentials(home: &Path) -> bool {
    let database = home.join("guard.db");
    if !database.is_file() {
        return false;
    }
    open_read_only(&database)
        .and_then(|connection| {
            connection
                .query_row(
                    "select 1 from sync_state where state_key = 'oauth_local_credentials' limit 1",
                    [],
                    |_| Ok(()),
                )
                .optional()
        })
        .is_ok_and(|row| row.is_some())
}

/// Whether `home` holds anything beyond what a freshly started Guard
/// writes; anything unreadable counts as state.
fn has_state(home: &Path) -> bool {
    if !home.exists() {
        return false;
    }
    let Ok(names) = entry_names(home) else {
        return true;
    };
    if names.is_empty() {
        return false;
    }
    let bookkeeping = |name: &str| {
        name == "guard.db"
            || name == "secrets"
            || METADATA_FILES.contains(&name)
            || NON_MIGRATED_FILES.contains(&name)
    };
    if names.iter().any(|name| !bookkeeping(name.as_str())) {
        return true;
    }
    let secrets = home.join("secrets");
    if secrets.is_dir() {
        match entry_names(&secrets) {
            Ok(names) => {
                if names
                    .iter()
                    .any(|name| name != "key.bin" && name != ".key-init.lock")
                {
                    return true;
                }
            }
            Err(_) => return true,
        }
    }
    let database = home.join("guard.db");
    if !database.is_file() {
        return true;
    }
    database_has_state(&database).unwrap_or(true)
}

fn entry_names(folder: &Path) -> std::io::Result<Vec<String>> {
    std::fs::read_dir(folder)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect()
}

fn database_has_state(database: &Path) -> rusqlite::Result<bool> {
    let connection = open_read_only(database)?;
    let tables: HashSet<String> = {
        let mut statement =
            connection.prepare("select name from sqlite_master where type = 'table'")?;
        let names = statement.query_map([], |row| row.get::<_, String>(0))?;
        names.collect::<rusqlite::Result<_>>()?
    };
    for table in STATE_TABLES {
        if !tables.contains(table) {
            continue;
        }
        let row = connection
            .query_row(&format!("select 1 from {table} limit 1"), [], |_| Ok(()))
            .optional()?;
        if row.is_some() {
            return Ok(true);
        }
    }
    has_custom_extension_state(&connection, &tables)
}

/// A saved extension-control authority with at least one layer is state;
/// an unreadable one counts as state too.
fn has_custom_extension_state(
    connection: &Connection,
    tables: &HashSet<String>,
) -> rusqlite::Result<bool> {
    if !tables.contains("extension_control_authority_snapshot") {
        return Ok(false);
    }
    let snapshot: Option<rusqlite::types::Value> = connection
        .query_row(
            "select layers_json from extension_control_authority_snapshot where singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match snapshot {
        None => false,
        Some(rusqlite::types::Value::Text(text)) => {
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(serde_json::Value::Array(layers)) => !layers.is_empty(),
                Ok(_) => false,
                Err(_) => true,
            }
        }
        Some(rusqlite::types::Value::Integer(_) | rusqlite::types::Value::Real(_)) => false,
        Some(rusqlite::types::Value::Null | rusqlite::types::Value::Blob(_)) => true,
    })
}

fn open_read_only(database: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}
