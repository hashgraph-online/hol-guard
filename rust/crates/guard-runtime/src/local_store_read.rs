//! Shared read-only access to `guard.db` for native grant decisions.
//!
//! A request names the store, but only `guard.db` directly under the Guard
//! home can be opened, and only read-only. A store written by a newer schema
//! is refused instead of guessed at.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

const STORE_FILE_NAME: &str = "guard.db";
/// Highest `local_cli_schema_migration` version this build reads.
pub(crate) const SUPPORTED_SCHEMA_VERSION: i64 = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreReadError {
    PathInvalid,
    StoreUnavailable,
    /// The schema marker is damaged: its checksum does not match its version.
    SchemaInvalid,
}

/// `store_path` must be `guard.db` directly under `guard_home`, so a request
/// cannot point the resident at another database.
pub(crate) fn require_store_path(
    store_path: &str,
    guard_home: &str,
) -> Result<PathBuf, StoreReadError> {
    let (store, home) = (Path::new(store_path), Path::new(guard_home));
    if !store.is_absolute() || !home.is_absolute() {
        return Err(StoreReadError::PathInvalid);
    }
    if store.file_name().and_then(|name| name.to_str()) != Some(STORE_FILE_NAME) {
        return Err(StoreReadError::PathInvalid);
    }
    let parent = store.parent().ok_or(StoreReadError::PathInvalid)?;
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|_| StoreReadError::PathInvalid)?;
    let canonical_home = std::fs::canonicalize(home).map_err(|_| StoreReadError::PathInvalid)?;
    if canonical_parent != canonical_home {
        return Err(StoreReadError::PathInvalid);
    }
    Ok(canonical_home.join(STORE_FILE_NAME))
}

/// `Ok(None)` means the store does not exist yet, so no grant can either.
pub(crate) fn open_read_only(store_path: &Path) -> Result<Option<Connection>, StoreReadError> {
    if !store_path.exists() {
        return Ok(None);
    }
    let connection = Connection::open_with_flags(store_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| StoreReadError::StoreUnavailable)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| StoreReadError::StoreUnavailable)?;
    Ok(Some(connection))
}

pub(crate) fn table_exists(connection: &Connection, table: &str) -> Result<bool, StoreReadError> {
    connection
        .query_row(
            "select 1 from sqlite_master where type = 'table' and name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()
        .map(|found| found.is_some())
        .map_err(|_| StoreReadError::StoreUnavailable)
}

/// Digest the schema marker must carry for `version`.
pub(crate) fn schema_checksum(version: i64) -> String {
    guard_policy_snapshot::digest_bytes(
        format!("hol-guard.local-cli-allowlist.schema.v{version}").as_bytes(),
    )
}

/// Version recorded by the local CLI schema marker, when the store has one.
///
/// A marker newer than this build is returned as-is so the caller can report
/// it as unsupported. Any other marker whose checksum does not match its
/// version is treated as damage, the same way the store's own schema
/// validator treats it, and is never trusted to authorize a grant.
pub(crate) fn schema_version(connection: &Connection) -> Result<Option<i64>, StoreReadError> {
    if !table_exists(connection, "local_cli_schema_migration")? {
        return Ok(None);
    }
    let marker: Option<(i64, String)> = connection
        .query_row(
            "select version, checksum from local_cli_schema_migration where singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| StoreReadError::StoreUnavailable)?;
    let Some((version, checksum)) = marker else {
        return Ok(None);
    };
    if version > SUPPORTED_SCHEMA_VERSION {
        return Ok(Some(version));
    }
    if version < 1 || checksum != schema_checksum(version) {
        return Err(StoreReadError::SchemaInvalid);
    }
    Ok(Some(version))
}

/// Whether `table` carries `column`.
pub(crate) fn column_exists(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, StoreReadError> {
    if !table_exists(connection, table)? {
        return Ok(false);
    }
    connection
        .query_row(
            "select 1 from pragma_table_info(?1) where name = ?2",
            params![table, column],
            |_| Ok(()),
        )
        .optional()
        .map(|found| found.is_some())
        .map_err(|_| StoreReadError::StoreUnavailable)
}
