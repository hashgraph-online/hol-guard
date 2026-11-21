//! Commit a resident fence-window batch to the local event log.

use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::{Transaction, TransactionBehavior};

use super::FenceEvent;
use crate::guard_store_cloud_events::append_event;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_json::dumps_default;
use crate::hook_evidence_store_gate::hold_storage_gate;
use crate::local_store_read::{require_store_path, STORE_FILE_NAME};

const WRITE_BUDGET: Duration = Duration::from_millis(25);
const PATH_INVALID: StoreError = StoreError::Invalid("native_guard_store_path_invalid");

pub(super) fn write<'a>(
    guard_home: &str,
    events: impl IntoIterator<Item = &'a FenceEvent>,
) -> StoreResult<()> {
    let path = Path::new(guard_home).join(STORE_FILE_NAME);
    let path = require_store_path(path.to_str().ok_or(PATH_INVALID)?, guard_home)
        .map_err(|_| PATH_INVALID)?;
    let deadline = Instant::now() + WRITE_BUDGET;
    let home = path.parent().ok_or(PATH_INVALID)?;
    let _gate = hold_storage_gate(home, WRITE_BUDGET)
        .map_err(|_| StoreError::Invalid("hook_policy_fence_window_storage_unavailable"))?;
    let connection = crate::guard_store_write_cache::open_read_write_cached(&path)?;
    connection.busy_timeout(deadline.saturating_duration_since(Instant::now()))?;
    // Fail and retry the whole batch on contention. No time is spent holding
    // the mutex that serves other hooks' in-memory window accounting.
    let transaction = Transaction::new_unchecked(&connection, TransactionBehavior::Immediate)?;
    for event in events {
        let payload = dumps_default(&event.payload).ok_or(StoreError::Invalid(
            "native_guard_store_payload_unencodable",
        ))?;
        append_event(
            &transaction,
            event.event_name,
            &payload,
            &event.occurred_at,
            false,
        )?;
    }
    transaction.commit()?;
    Ok(())
}
