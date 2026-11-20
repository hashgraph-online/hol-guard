//! One immediate SQLite transaction over the Guard store's `sync_state` rows.
//!
//! Native ports of Python read-modify-write state (the command ledger, the
//! auto-update state) share this: hold the storage gate, open the Python
//! store's own file without creating it, and run the whole change in one
//! immediate transaction so concurrent writers in any process cannot drop
//! each other's rows.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::Value;

use crate::local_store_read::STORE_FILE_NAME;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The refusal codes one caller reports for a busy gate and an unusable store.
#[derive(Clone, Copy)]
pub(crate) struct LedgerCodes {
    pub(crate) busy: &'static str,
    pub(crate) unavailable: &'static str,
}

pub(crate) struct SyncStateLedger {
    home: PathBuf,
    codes: LedgerCodes,
}

impl SyncStateLedger {
    pub(crate) fn new(guard_home: &Path, codes: LedgerCodes) -> Self {
        Self {
            home: guard_home.to_path_buf(),
            codes,
        }
    }

    pub(crate) fn store_exists(&self) -> bool {
        self.home.join(STORE_FILE_NAME).is_file()
    }

    /// Runs `update` in one immediate transaction while holding the shared
    /// storage gate, so a recovery that moves the database waits for it. An
    /// error from `update` rolls the whole transaction back.
    pub(crate) fn transact<T>(
        &self,
        update: impl FnOnce(&Connection) -> Result<T, String>,
    ) -> Result<T, String> {
        let unavailable = || self.codes.unavailable.to_owned();
        let _gate = crate::hook_evidence_store_gate::hold_storage_gate(&self.home, BUSY_TIMEOUT)
            .map_err(|_| self.codes.busy.to_owned())?;
        // The store is the Python store's own file. Opening it without the
        // create flag never leaves an empty database where none was.
        let mut conn = Connection::open_with_flags(
            self.home.join(STORE_FILE_NAME),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| unavailable())?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(|_| unavailable())?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let value = update(&tx)?;
        tx.commit().map_err(|_| unavailable())?;
        Ok(value)
    }
}

/// The raw `payload_json` text saved under `key`, if any.
pub(crate) fn read_payload(conn: &Connection, key: &str) -> Result<Option<String>, ()> {
    conn.query_row(
        "SELECT payload_json FROM sync_state WHERE state_key = ?1",
        [key],
        |row| row.get(0),
    )
    .optional()
    .map_err(drop)
}

/// `GuardStore.set_sync_payload(key, payload, now)`.
pub(crate) fn write_payload(
    conn: &Connection,
    key: &str,
    payload: &Value,
    now: &str,
) -> Result<(), ()> {
    conn.execute(
        "INSERT INTO sync_state (state_key, payload_json, updated_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT(state_key) DO UPDATE SET \
           payload_json = excluded.payload_json, updated_at = excluded.updated_at",
        rusqlite::params![key, payload.to_string(), now],
    )
    .map(drop)
    .map_err(drop)
}

/// `GuardStore.delete_sync_payload(key)`.
pub(crate) fn delete_payload(conn: &Connection, key: &str) -> Result<(), ()> {
    conn.execute("DELETE FROM sync_state WHERE state_key = ?1", [key])
        .map(drop)
        .map_err(drop)
}
