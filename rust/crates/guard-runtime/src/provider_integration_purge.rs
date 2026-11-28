//! Forgetting every provider integration on this device (BP-T128, PRD 6.7).
//!
//! Disconnect forgets one provider. Uninstall and "forget this device" forget all of them: every
//! provider key first, then every connection row, capability setting and cached signal. The keys
//! go first for the reason disconnect deletes its key first: a row without a key is harmless, a
//! key without a row is a secret nobody can see or remove.
//!
//! The purge never creates the provider tables. A Guard home that never connected a provider, or
//! has no store at all, is left as it is.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Serialize;

use crate::provider_integration_secret::delete_all_provider_keys;
use crate::provider_integration_store::{in_write_savepoint, ProviderStoreResult};

/// What a purge removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderPurge {
    pub keys_deleted: usize,
    pub providers_forgotten: usize,
}

/// The rows a purge removes, child tables first.
const PURGED_TABLES: [&str; 3] = [
    "provider_signals",
    "provider_capability_settings",
    "provider_connections",
];

fn has_provider_tables(connection: &Connection) -> rusqlite::Result<bool> {
    connection
        .query_row(
            "select 1 from sqlite_master where type = 'table' and name = 'provider_connections'",
            [],
            |_| Ok(()),
        )
        .optional()
        .map(|found| found.is_some())
}

/// Drops every provider connection, setting and cached signal in one savepoint. Returns how many
/// providers were connected. A store without the provider tables is left untouched.
pub fn forget_all_providers(connection: &Connection) -> ProviderStoreResult<usize> {
    if !has_provider_tables(connection)? {
        return Ok(0);
    }
    in_write_savepoint(connection, || {
        let mut forgotten = 0;
        for table in PURGED_TABLES {
            let removed = connection.execute(&format!("delete from {table}"), [])?;
            if table == "provider_connections" {
                forgotten = removed;
            }
        }
        Ok(forgotten)
    })
}

/// Why a purge stopped. Codes only: no path, key or row text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderPurgeError {
    Keys,
    Store,
}

impl ProviderPurgeError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Keys => "provider_keys_not_deleted",
            Self::Store => "provider_store_not_purged",
        }
    }
}

/// Uninstall and "forget this device": deletes every provider key under `guard_home`, then every
/// provider row in its store (`guard.db`). Keys are deleted even when the store cannot be opened.
pub fn purge_provider_integrations(guard_home: &Path) -> Result<ProviderPurge, ProviderPurgeError> {
    let keys_deleted =
        delete_all_provider_keys(guard_home).map_err(|_| ProviderPurgeError::Keys)?;
    let store_path = guard_home.join("guard.db");
    if !store_path.is_file() {
        return Ok(ProviderPurge {
            keys_deleted,
            providers_forgotten: 0,
        });
    }
    let connection = Connection::open_with_flags(
        &store_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ProviderPurgeError::Store)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(2))
        .map_err(|_| ProviderPurgeError::Store)?;
    let providers_forgotten =
        forget_all_providers(&connection).map_err(|_| ProviderPurgeError::Store)?;
    Ok(ProviderPurge {
        keys_deleted,
        providers_forgotten,
    })
}

#[cfg(test)]
#[path = "provider_integration_purge_tests.rs"]
mod tests;
