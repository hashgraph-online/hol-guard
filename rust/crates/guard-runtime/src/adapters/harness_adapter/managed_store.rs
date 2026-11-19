//! The Guard store's `managed_installs` rows and `sync_state` payloads, read
//! straight from the store file under a Guard home.
//!
//! Python used to open its `GuardStore` and hand these rows to the adapter ops
//! as facts. The runtime now reads them itself, read-only: a Guard home with
//! no store yet has no rows and no payloads, as a freshly created store would
//! answer, and nothing is created or migrated by asking.

use std::ops::Deref;
use std::path::Path;
use std::time::Duration;

use rusqlite::Connection;
use serde_json::{json, Value};

use super::{Failure, Step};
use crate::guard_store_db::{int, is_null, query_all, query_one, text, Row};
use crate::hook_evidence_store_gate::{hold_storage_gate, StorageGateHold, STORAGE_GATE_FILE_NAME};
use crate::local_store_read::{open_read_only, table_exists, STORE_FILE_NAME};

fn unavailable() -> Failure {
    Failure::Runtime("Guard store is unavailable.".to_owned())
}

/// How long a read waits for an exclusive maintenance hold on the store.
const GATE_WAIT: Duration = Duration::from_secs(5);

/// A read-only connection and the shared storage gate held for as long as it
/// lives. Recovery holds the gate exclusively while it moves `guard.db` and
/// its sidecars, so a read waits for it rather than finding no store.
pub(super) struct Reader {
    connection: Connection,
    _gate: StorageGateHold,
}

impl Deref for Reader {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.connection
    }
}

/// The store's read-only connection, or `None` when the home has no store.
///
/// Absence is decided under the gate: recovery moves `guard.db` away while it
/// holds the gate exclusively, so a missing file seen outside the gate may be
/// a store in the middle of recovery. The gate is skipped only when neither
/// the store nor the gate file exists, a home that was never opened (asking
/// creates nothing).
fn open(home: &Path) -> Step<Option<Reader>> {
    let path = home.join(STORE_FILE_NAME);
    if !path.exists() && !home.join(STORAGE_GATE_FILE_NAME).exists() {
        return Ok(None);
    }
    let gate = hold_storage_gate(home, GATE_WAIT).map_err(|_| unavailable())?;
    Ok(open_read_only(&path)
        .map_err(|_| unavailable())?
        .map(|connection| Reader {
            connection,
            _gate: gate,
        }))
}

/// `_managed_install_row`: the row with its manifest decoded.
fn install(row: &Row) -> Step<Value> {
    let manifest = serde_json::from_str::<Value>(text(row, "manifest_json"))
        .map_err(|error| Failure::Runtime(format!("Guard managed install manifest: {error}")))?;
    Ok(json!({
        "harness": text(row, "harness"),
        "active": int(row, "active") != 0,
        "workspace": if is_null(row, "workspace") {
            Value::Null
        } else {
            row.get("workspace").cloned().unwrap_or(Value::Null)
        },
        "manifest": manifest,
        "updated_at": text(row, "updated_at"),
    }))
}

const COLUMNS: &str = "select harness, active, workspace, manifest_json, updated_at \
                       from managed_installs";

/// `get_managed_install`: the harness's row, or `None`.
pub(super) fn managed_install(home: &Path, harness: &str) -> Step<Option<Value>> {
    let Some(connection) = open(home)? else {
        return Ok(None);
    };
    if !table_exists(&connection, "managed_installs").map_err(|_| unavailable())? {
        return Ok(None);
    }
    query_one(
        &connection,
        &format!("{COLUMNS} where harness = ?"),
        &[Value::from(harness)],
    )
    .map_err(|error| Failure::Runtime(error.message()))?
    .as_ref()
    .map(install)
    .transpose()
}

/// `list_managed_installs`: every row, by harness.
pub(super) fn managed_installs(home: &Path) -> Step<Vec<Value>> {
    let Some(connection) = open(home)? else {
        return Ok(Vec::new());
    };
    if !table_exists(&connection, "managed_installs").map_err(|_| unavailable())? {
        return Ok(Vec::new());
    }
    query_all(&connection, &format!("{COLUMNS} order by harness asc"), &[])
        .map_err(|error| Failure::Runtime(error.message()))?
        .iter()
        .map(install)
        .collect()
}

/// `get_sync_payload`: the stored object or list, or `None`. A store that
/// cannot be read or a payload that is not JSON answers `None`, which is how
/// the one caller that reads it (`fleet_status`) already treated a failure.
pub(super) fn sync_payload(home: &Path, state_key: &str) -> Option<Value> {
    let connection = open(home).ok()??;
    if !table_exists(&connection, "sync_state").ok()? {
        return None;
    }
    let row = query_one(
        &connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(state_key)],
    )
    .ok()??;
    let payload = serde_json::from_str::<Value>(text(&row, "payload_json")).ok()?;
    (payload.is_object() || payload.is_array()).then_some(payload)
}
