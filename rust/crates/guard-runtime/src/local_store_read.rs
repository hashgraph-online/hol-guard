//! Shared read-only access to `guard.db` for native grant decisions.
//!
//! A request names the store, but only `guard.db` directly under the Guard
//! home can be opened, and only read-only. A store written by a newer schema
//! is refused instead of guessed at.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

#[path = "local_store_read_cache.rs"]
mod cache;
pub(crate) use cache::{open_read_only_cached, CachedConnection};

pub(crate) const STORE_FILE_NAME: &str = "guard.db";
/// Highest `local_cli_schema_migration` version this build reads.
pub(crate) const SUPPORTED_SCHEMA_VERSION: i64 = 14;

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
        .prepare_cached("select 1 from sqlite_master where type = 'table' and name = ?1")
        .and_then(|mut statement| statement.query_row(params![table], |_| Ok(())))
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
        .prepare_cached(
            "select version, checksum from local_cli_schema_migration where singleton = 1",
        )
        .and_then(|mut statement| statement.query_row([], |row| Ok((row.get(0)?, row.get(1)?))))
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

/// How long a hook-path probe waits on a writer before giving up.
const HOOK_PROBE_BUSY_TIMEOUT_MS: u64 = 50;

/// What the daemon reads from the store before a hook reaches the edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HookStoreProbe {
    /// A custom command-line block rule exists, answered the way
    /// `GuardStore.has_local_cli_block_rules` answers it.
    pub(crate) local_cli_block_rules: bool,
    /// The hook belongs to an app Guard is not protecting, answered the way
    /// `_hook_harness_is_unmanaged` answers it, so the daemon passes it
    /// through. A manifest the daemon could not parse counts as unmanaged
    /// here, while the daemon would review it: that only sends the hook to
    /// the daemon.
    pub(crate) harness_unmanaged: bool,
}

/// Read the store state the daemon checks for one hook of `harness`. A
/// missing store or table holds no rule and no managed install, since the
/// daemon would create them empty.
pub(crate) fn hook_store_probe(
    guard_home: &Path,
    harness: &str,
) -> Result<HookStoreProbe, StoreReadError> {
    let mut probe = HookStoreProbe {
        local_cli_block_rules: false,
        harness_unmanaged: false,
    };
    let Some(connection) = open_read_only(&guard_home.join(STORE_FILE_NAME))? else {
        return Ok(probe);
    };
    connection
        .busy_timeout(std::time::Duration::from_millis(HOOK_PROBE_BUSY_TIMEOUT_MS))
        .map_err(|_| StoreReadError::StoreUnavailable)?;
    for (table, query) in [
        (
            "local_cli_grant",
            "select exists(select 1 from local_cli_grant where state = 'blocked')",
        ),
        (
            "local_cli_command_grant",
            "select exists(select 1 from local_cli_command_grant where state = 'block')",
        ),
    ] {
        if probe.local_cli_block_rules || !table_exists(&connection, table)? {
            continue;
        }
        probe.local_cli_block_rules = connection
            .query_row(query, [], |row| row.get(0))
            .map_err(|_| StoreReadError::StoreUnavailable)?;
    }
    if table_exists(&connection, "managed_installs")? {
        // Its own row decides; without one, another app's active install
        // means this app's hooks are leftovers.
        probe.harness_unmanaged = connection
            .query_row(
                "select case \
                   when exists(select 1 from managed_installs where harness = ?1) \
                     then exists(select 1 from managed_installs where harness = ?1 and active = 0) \
                   else exists(select 1 from managed_installs where harness <> ?1 and active <> 0) \
                 end",
                params![harness],
                |row| row.get(0),
            )
            .map_err(|_| StoreReadError::StoreUnavailable)?;
    }
    Ok(probe)
}

/// Whether `sync_state` holds a Claude Code permission notice for
/// `session_id`, under its session key or any of its tool keys. A row that
/// fails verification counts too: only the daemon, which holds the key,
/// can tell a valid notice from one it must invalidate.
pub(crate) fn claude_permission_notice_present(
    guard_home: &Path,
    session_id: &str,
) -> Result<bool, StoreReadError> {
    let Some(connection) = open_read_only(&guard_home.join(STORE_FILE_NAME))? else {
        return Ok(false);
    };
    connection
        .busy_timeout(std::time::Duration::from_millis(HOOK_PROBE_BUSY_TIMEOUT_MS))
        .map_err(|_| StoreReadError::StoreUnavailable)?;
    if !table_exists(&connection, "sync_state")? {
        return Ok(false);
    }
    // Under the binary collation every `<session key>:<tool>` key sorts at or
    // after `<session key>:` and before `<session key>;`.
    let session_key = format!("claude_permission_notice:{session_id}");
    connection
        .query_row(
            "select exists(select 1 from sync_state \
               where state_key = ?1 or (state_key >= ?2 and state_key < ?3))",
            params![
                session_key,
                format!("{session_key}:"),
                format!("{session_key};")
            ],
            |row| row.get(0),
        )
        .map_err(|_| StoreReadError::StoreUnavailable)
}
