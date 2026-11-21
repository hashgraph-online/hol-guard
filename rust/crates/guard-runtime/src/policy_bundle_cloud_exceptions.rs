//! `GuardStore.list_cloud_exceptions`: the Cloud exceptions the cached
//! signed policy bundle carries that are still in force, read as the Python
//! store reads them.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::claim_reuse_binding::local_device;
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::policy_bundle_store_identities::{sync_payload, validated_synced_bundle};

/// `_CLOUD_EXCEPTION_BUNDLE_KEYS` (`runner_native_sync.py`).
const BUNDLE_KEYS: [&str; 4] = [
    "bundleHash",
    "bundleVersion",
    "cloudExceptions",
    "acknowledgements",
];
/// `_CLOUD_EXCEPTION_ACK_KEYS` (`runner_native_sync.py`).
const ACK_KEYS: [&str; 5] = [
    "status",
    "bundleHash",
    "bundleVersion",
    "deviceId",
    "appliedAt",
];
const UNDECIDED: StoreError = StoreError::Invalid("native_guard_store_cloud_exceptions_undecided");

/// The exception records, or an error where the Python store would have
/// written a missing device row first or the resident cannot validate the
/// bundle as the Python store would.
pub(crate) fn list(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let harness = args.opt_str("harness")?;
    let Some(bundle) = validated_synced_bundle(connection).ok_or(UNDECIDED)? else {
        return Ok(json!([]));
    };
    let (device_id, _) = local_device(connection)?.ok_or(UNDECIDED)?;
    let acknowledgement = match sync_payload(connection, "policy_bundle_ack").ok_or(UNDECIDED)? {
        Some(Value::Object(ack)) => Value::Object(subset(&ack, &ACK_KEYS)),
        _ => Value::Null,
    };
    let active_at = now().ok_or(UNDECIDED)?;
    let request = json!({
        "policy_bundle": Value::Object(subset(&bundle, &BUNDLE_KEYS)),
        "device_id": device_id,
        "policy_bundle_ack": acknowledgement,
        "harness": harness,
        "active_at": active_at,
    });
    // An exception only ever widens what runs, so one the runtime could not
    // read is not listed as in force.
    let Ok(answer) = crate::runner_cloud_exceptions::cloud_exceptions(&request) else {
        return Ok(json!([]));
    };
    match answer.get("items") {
        Some(Value::Array(items)) if items.iter().all(Value::is_object) => {
            Ok(Value::Array(items.clone()))
        }
        _ => Ok(json!([])),
    }
}

fn subset(map: &Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    keys.iter()
        .filter_map(|key| Some(((*key).to_owned(), map.get(*key)?.clone())))
        .collect()
}

/// `datetime.now(timezone.utc).isoformat()`.
fn now() -> Option<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    crate::policy_bundle_time::micros_to_utc_isoformat(i64::try_from(micros).ok()?, "+00:00")
}

#[cfg(test)]
#[path = "policy_bundle_cloud_exceptions_tests.rs"]
mod tests;
