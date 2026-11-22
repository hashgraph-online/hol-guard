//! `cloud_workspace_id`: the Guard Cloud workspace this install is connected
//! to, read from the stored OAuth credential record.
//!
//! Port of `get_cloud_workspace_id`, which read the record on its own SQLite
//! connection. Only the workspace id leaves the store; the rest of the record
//! stays here. A record that is not JSON (or is not stored as text) is
//! reported as malformed rather than as "not connected", so a damaged record
//! still surfaces as an error the way the Python decoder raised one.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_db::{query_one, StoreResult};

const OAUTH_STATE_KEY: &str = "oauth_local_credentials";

pub(crate) fn handles(method: &str) -> bool {
    method == "cloud_workspace_id"
}

/// `{"state": "present", "workspace_id": str | null}`, or
/// `{"state": "malformed"}` when the credential record cannot be decoded.
pub(crate) fn dispatch(connection: &Connection) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select case when typeof(payload_json) = 'text' then payload_json end as payload_json \
         from sync_state where state_key = ?",
        &[Value::from(OAUTH_STATE_KEY)],
    )?;
    let Some(row) = row else {
        return Ok(json!({"state": "present", "workspace_id": null}));
    };
    let Some(stored) = row.get("payload_json").and_then(Value::as_str) else {
        return Ok(json!({"state": "malformed"}));
    };
    let Ok(payload) = serde_json::from_str::<Value>(stored) else {
        return Ok(json!({"state": "malformed"}));
    };
    Ok(json!({"state": "present", "workspace_id": workspace_id(&payload)}))
}

fn workspace_id(payload: &Value) -> Option<&str> {
    payload
        .as_object()?
        .get("workspace_id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
}

#[cfg(test)]
#[path = "guard_store_cloud_workspace_id_tests.rs"]
mod tests;
