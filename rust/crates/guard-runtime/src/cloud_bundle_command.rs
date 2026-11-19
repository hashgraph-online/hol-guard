//! The `cloud-bundle-sync` command: the CLI's `hol-guard sync` and the
//! daemon's bundle refresh ask the native runtime to fetch, verify and save the
//! workspace's signed bundles.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::cloud_bundle_fetch::{brokered, SyncError};
use crate::cloud_bundle_network::{sync_network, sync_network_best_effort};
use crate::cloud_bundle_sync::{bundle_refresh, sync_supply_chain, BundleStore};

pub(crate) const COMMAND: &str = "cloud-bundle-sync";
pub(crate) const FEATURE: &str = "cloud-bundle-sync-v1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    guard_home: String,
    action: Action,
    /// A sign-in the caller already resolved.
    #[serde(default)]
    auth_context: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    /// `sync_supply_chain_bundle`.
    SupplyChain,
    /// `sync_network_protection_bundle`.
    Network,
    /// `sync_network_protection_bundle_best_effort`.
    NetworkBestEffort,
    /// The daemon's `bundle_refresh` tick.
    Refresh,
}

/// The store a Guard home keeps its sync state in.
pub(crate) fn store_for(guard_home: &Path, auth: Option<Map<String, Value>>) -> BundleStore {
    BundleStore::new(guard_home, &guard_home.join("guard.db"), auth)
}

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return failure(&SyncError::Failed(
            "The bundle sync request was not understood.".to_owned(),
        ));
    };
    let guard_home = PathBuf::from(request.guard_home);
    let store = store_for(&guard_home, request.auth_context);
    let answer = match request.action {
        Action::SupplyChain => brokered(|| sync_supply_chain(&store)),
        Action::Network => brokered(|| sync_network(&store)),
        Action::NetworkBestEffort => Ok(sync_network_best_effort(&store).unwrap_or(Value::Null)),
        Action::Refresh => Ok(bundle_refresh(&store)),
    };
    match answer {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => failure(&error),
    }
}

/// The class the CLI raises and whether the next attempt may succeed.
pub(crate) fn failure(error: &SyncError) -> Value {
    let (outcome, retryable) = match error {
        SyncError::NotConfigured(_) => ("not_configured", false),
        SyncError::EndpointUntrusted(_) => ("endpoint_untrusted", false),
        SyncError::AuthExpired(_) => ("auth_expired", false),
        SyncError::NotAvailable { retryable, .. } => ("not_available", *retryable),
        SyncError::Failed(_) | SyncError::Pending => ("failed", false),
    };
    json!({
        "ok": false,
        "outcome": outcome,
        "error": error.message(),
        "retryable": retryable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_request_is_a_failure() {
        let answer = run_command(b"{\"guardHome\": 1}");
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(answer["outcome"], json!("failed"));
    }

    #[test]
    fn outcome_carries_the_error_class() {
        let answer = failure(&SyncError::NotAvailable {
            message: "down".to_owned(),
            retryable: true,
        });
        assert_eq!(answer["outcome"], json!("not_available"));
        assert_eq!(answer["retryable"], json!(true));
        assert_eq!(answer["error"], json!("down"));
        let answer = failure(&SyncError::AuthExpired("signed out".to_owned()));
        assert_eq!(answer["outcome"], json!("auth_expired"));
    }
}
