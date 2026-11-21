//! `record_policy_bundle_rejection`: the `sync_state` row and events the cloud
//! sync writes when Cloud's policy bundle is rejected.
//!
//! The caller passes the payload already encoded, so the stored row and the
//! event carry the same text the runner wrote before. The last-error row, the
//! rejection event and the optional approval-gate event run in the one store
//! write, so a reader never sees the last error without its event.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_cloud_events::append_event;
use crate::guard_store_db::{value_error, StoreResult};
use crate::guard_store_sync_state::write_encoded;

const LAST_ERROR: &str = "policy_bundle_last_error";
const REJECTED_EVENT: &str = "policy_bundle/rejected";
const GATE_BLOCKED_EVENT: &str = "approval_gate/remote_policy_sync_blocked";

/// Encoded JSON text that decodes to an object.
fn object_text<'a>(args: &Args<'a>, key: &str) -> StoreResult<&'a str> {
    let text = args.str(key)?;
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(_)) => Ok(text),
        _ => value_error("invalid_payload"),
    }
}

/// The `record_policy_bundle_rejection` store method.
///
/// `persist_last_error` is false for the rejections that only record the
/// event. `gate_blocked_payload_json` is given when the approval gate stopped
/// the remote policy sync.
pub(crate) fn method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let payload = object_text(args, "payload_json")?;
    let now = args.str("now")?;
    let persist = args.flag("persist_last_error")?;
    let gate_blocked = match args.raw("gate_blocked_payload_json") {
        None | Some(Value::Null) => None,
        Some(_) => Some(object_text(args, "gate_blocked_payload_json")?),
    };
    if persist {
        write_encoded(connection, LAST_ERROR, payload, now)?;
    }
    append_event(connection, REJECTED_EVENT, payload, now, false)?;
    if let Some(blocked) = gate_blocked {
        append_event(connection, GATE_BLOCKED_EVENT, blocked, now, false)?;
    }
    Ok(Value::Null)
}

#[cfg(test)]
#[path = "guard_store_policy_bundle_rejection_tests.rs"]
mod tests;
