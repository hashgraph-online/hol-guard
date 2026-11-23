//! `ensure_schema`: create or upgrade a Guard store's whole schema in one
//! call, the way the Python store's `_initialize_schema` did.
//!
//! A store file with no pages yet is new, so it gets incremental vacuum
//! before anything else is written. WAL is enabled before the schema
//! transaction starts, because SQLite cannot change the journal mode inside
//! one; a busy store is retried until the connection's busy timeout runs out.
//! The base statements and every family then run inside one immediate
//! transaction, so a failure leaves the store as it was.
//!
//! The method takes the write lock itself, so the store op holds no
//! transaction around it.

use std::thread;
use std::time::{Duration, Instant};

use rusqlite::{Connection, ErrorCode};
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::StoreResult;
use crate::guard_store_op::schema;

pub(crate) const METHOD: &str = "ensure_schema";
/// The longest single wait for the WAL switch, as in `sqlite_tuning`.
const WAL_BUSY_TIMEOUT_MS: u64 = 1000;
/// The pause between WAL attempts on a locked store.
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(100);

pub(crate) fn handles(method: &str) -> bool {
    method == METHOD
}

/// `{"created": bool}`: whether the store file was new.
pub(crate) fn dispatch(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let now = args.str("now")?;
    let page_count: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    let created = page_count == 0;
    if created {
        connection.execute_batch("pragma auto_vacuum=incremental")?;
    }
    enable_wal(connection)?;
    connection.execute_batch("BEGIN IMMEDIATE")?;
    let outcome = schema::create_base(connection)
        .map_err(Into::into)
        .and_then(|()| schema::ensure_families(connection, now))
        .and_then(|()| connection.execute_batch("COMMIT").map_err(Into::into));
    if outcome.is_err() {
        // The original error is the one to report.
        let _ = connection.execute_batch("ROLLBACK");
    }
    outcome?;
    Ok(json!({ "created": created }))
}

/// Switch to WAL, retrying a locked store until the connection's busy
/// timeout has passed, then restore that timeout.
fn enable_wal(connection: &Connection) -> StoreResult<()> {
    let original: i64 = connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    let original = Duration::from_millis(u64::try_from(original).unwrap_or(0));
    let outcome = wal_until(connection, Instant::now() + original);
    connection.busy_timeout(original)?;
    outcome
}

fn wal_until(connection: &Connection, deadline: Instant) -> StoreResult<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        connection.busy_timeout(remaining.min(Duration::from_millis(WAL_BUSY_TIMEOUT_MS)))?;
        match connection.query_row("pragma journal_mode=WAL", [], |row| row.get::<_, String>(0)) {
            Ok(_) => return Ok(()),
            Err(error) if locked(&error) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(error.into());
                }
                thread::sleep(left.min(LOCK_RETRY_DELAY));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn locked(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(failure.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

#[cfg(test)]
#[path = "guard_store_schema_op_tests.rs"]
mod tests;
