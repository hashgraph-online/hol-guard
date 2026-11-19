//! The `cloud-event-sync` command: `hol-guard sync` asks the native runtime
//! to upload the local Guard event queue and the cloud pain signals.

use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::cloud_bundle_command::{failure, store_for};
use crate::cloud_bundle_fetch::{brokered, SyncError};
use crate::cloud_event_sync::{event_store, sync_guard_events};
use crate::cloud_pain_signal_sync::sync_pain_signals;

pub(crate) const COMMAND: &str = "cloud-event-sync";
pub(crate) const FEATURE: &str = "cloud-event-sync-v1";

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
    /// `sync_guard_events`.
    GuardEvents,
    /// `sync_pain_signals`.
    PainSignals,
}

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return failure(&SyncError::Failed(
            "The event sync request was not understood.".to_owned(),
        ));
    };
    let guard_home = PathBuf::from(request.guard_home);
    let bundle = store_for(&guard_home, request.auth_context);
    let store = event_store(&guard_home, &bundle);
    let answer = match request.action {
        Action::GuardEvents => brokered(|| sync_guard_events(&store)),
        Action::PainSignals => brokered(|| sync_pain_signals(&store)),
    };
    match answer {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => failure(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_request_is_a_failure() {
        let answer = run_command(b"{\"guardHome\": \"/nonexistent\", \"action\": \"receipts\"}");
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(answer["outcome"], json!("failed"));
    }
}
