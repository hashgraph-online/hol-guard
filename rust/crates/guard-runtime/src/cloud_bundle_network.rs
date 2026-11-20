//! The workspace's signed network protection bundle
//! (`runner.sync_network_protection_bundle`) and the status the CLI reads from
//! the saved copy.

use guard_command::local_supply_chain::{utc_now_iso, SupplyChainStore};
use guard_command::network_protection_bundle::verify_network_protection_response;
use guard_command::supply_chain_bundle::RingRsaPssVerify;
use serde_json::{json, Value};

use crate::cloud_bundle_fetch::{brokered, fetch_bundle, resolve_auth, FetchError, SyncError};
use crate::cloud_bundle_sync::{base_url, workspace_url, BundleStore, KEYRING_KEY, NETWORK_KEY};

const NETWORK_MAX_AGE_SECONDS: i64 = 7 * 24 * 60 * 60;

/// `runner.sync_network_protection_bundle`, one round.
pub(crate) fn sync_network(store: &BundleStore) -> Result<Value, SyncError> {
    let auth = resolve_auth(&store.resident, false, store.auth.as_ref())?;
    let workspace_id = store.workspace_id()?;
    let saved = store.resident.get_sync_payload(NETWORK_KEY);
    let mut saved_bundle = saved
        .as_ref()
        .and_then(|saved| saved.get("bundle"))
        .filter(|bundle| bundle.is_object());
    if saved_bundle.is_some_and(|bundle| {
        bundle.get("workspaceId").and_then(Value::as_str) != Some(workspace_id.as_str())
    }) {
        // Another workspace's rules must not stay in force, or anchor its
        // rollback check, once this device is connected elsewhere.
        store.delete_payload(NETWORK_KEY)?;
        saved_bundle = None;
    }
    let cached_version = saved_bundle
        .and_then(|bundle| bundle.get("bundleVersion"))
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty());
    let url = workspace_url(
        "network_protection_bundle",
        &base_url(&auth)?,
        &workspace_id,
    )?;
    let payload = match fetch_bundle(&auth, &url) {
        Ok(payload) => payload,
        Err(FetchError::Unauthorized(_)) => {
            // The access token may have lapsed since it was resolved. Refresh
            // once; a second refusal stands, and a refresh that finds the
            // device signed out reports that rather than "never connected".
            // Each broker round replays the first refusal, so the refreshed
            // sign-in is kept for later rounds instead of refreshing again with
            // the rotated grant.
            let refreshed = store.refreshed_auth.borrow().clone();
            let auth = match refreshed {
                Some(auth) => auth,
                None => {
                    let auth =
                        resolve_auth(&store.resident, true, None).map_err(|error| match error {
                            SyncError::NotConfigured(message) | SyncError::AuthExpired(message) => {
                                SyncError::Failed(message)
                            }
                            other => other,
                        })?;
                    *store.refreshed_auth.borrow_mut() = Some(auth.clone());
                    auth
                }
            };
            let url = workspace_url(
                "network_protection_bundle",
                &base_url(&auth)?,
                &workspace_id,
            )?;
            fetch_bundle(&auth, &url).map_err(SyncError::from)?
        }
        Err(FetchError::Sync(error)) => return Err(error),
    };
    let network_failed = |message: String| {
        SyncError::Failed(format!(
            "Guard network protection bundle sync failed: {message}"
        ))
    };
    let keyring = store.resident.get_sync_payload(KEYRING_KEY);
    let trusted = crate::network_protection_verify_op::trusted_keys(keyring.as_ref())
        .map_err(|error| network_failed(error.to_string()))?;
    let verified = verify_network_protection_response(
        &payload,
        &workspace_id,
        &trusted,
        cached_version,
        None,
        &RingRsaPssVerify,
    )
    .map_err(|error| network_failed(error.to_string()))?;
    let synced_at = utc_now_iso();
    store.set_payload(NETWORK_KEY, &verified, &synced_at)?;
    let mut status = network_status(&verified, now_seconds());
    status["status"] = json!("synced");
    status["synced_at"] = json!(synced_at);
    Ok(status)
}

/// `sync_network_protection_bundle_best_effort`: `None` when no workspace is
/// connected, a `failed` status when the fetch or verification fails.
pub(crate) fn sync_network_best_effort(store: &BundleStore) -> Option<Value> {
    match brokered(|| sync_network(store)) {
        Ok(status) => Some(status),
        Err(SyncError::NotConfigured(_) | SyncError::AuthExpired(_)) => None,
        Err(error) => Some(json!({"status": "failed", "error": error.message()})),
    }
}

/// `network_protection_bundle.network_protection_status`.
pub(crate) fn network_status(saved: &Value, now: f64) -> Value {
    let Some(bundle) = saved.get("bundle").and_then(Value::as_object) else {
        return json!({"configured": false});
    };
    let rules = bundle
        .get("workspaceRules")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let count_rules = |action: &str| {
        rules
            .iter()
            .filter(|rule| rule.get("action").and_then(Value::as_str) == Some(action))
            .count()
    };
    let indicators = |key: &str| -> usize {
        bundle
            .get(key)
            .and_then(Value::as_object)
            .map(|groups| {
                groups
                    .values()
                    .filter_map(Value::as_array)
                    .map(Vec::len)
                    .sum()
            })
            .unwrap_or_default()
    };
    // `isinstance(expires_at_epoch, int)`: a float or a bool is not one.
    let fresh = saved
        .get("expiresAtEpoch")
        .filter(|value| value.is_i64() || value.is_u64())
        .and_then(Value::as_i64)
        .is_some_and(|expires| now <= expires.saturating_add(NETWORK_MAX_AGE_SECONDS) as f64);
    json!({
        "configured": true,
        "bundle_version": bundle.get("bundleVersion").cloned().unwrap_or(Value::Null),
        "generated_at": bundle.get("generatedAt").cloned().unwrap_or(Value::Null),
        "expires_at": bundle.get("expiresAt").cloned().unwrap_or(Value::Null),
        "block_rules": count_rules("block"),
        "allow_rules": count_rules("allow"),
        "known_bad_urls": indicators("threatUrls"),
        "known_bad_hosts": indicators("threatHosts"),
        "indicators_applied": fresh,
    })
}

fn now_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

#[cfg(test)]
#[path = "cloud_bundle_network_tests.rs"]
mod tests;
