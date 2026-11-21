//! The `cloud-event-sync` command: `hol-guard sync` asks the native runtime
//! to upload the local receipts, the Guard event queue and the cloud pain
//! signals, and to publish the runtime session.

use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::cloud_bundle_command::{failure, store_for};
use crate::cloud_bundle_fetch::{brokered, SyncError};
use crate::cloud_command_lease::{lease, LeaseCall};
use crate::cloud_command_report::{report, ReportCall};
use crate::cloud_event_sync::{event_store, sync_guard_events};
use crate::cloud_json_request::{send, JsonRequest};
use crate::cloud_oauth_refresh::{refresh, RefreshCall};
use crate::cloud_pain_signal_sync::sync_pain_signals;
use crate::cloud_receipt_upload::{upload_receipts, UploadRequest, UploadState};
use crate::cloud_runtime_session_sync::sync_runtime_session;
use crate::oauth_refresh_circuit::{self as circuit, CircuitCall};

pub(crate) const COMMAND: &str = "cloud-event-sync";
pub(crate) const FEATURE: &str = "cloud-event-sync-v1";
/// The `receipts` action.
pub(crate) const RECEIPTS_FEATURE: &str = "cloud-receipt-upload-v1";
/// The `request` action.
pub(crate) const REQUEST_FEATURE: &str = "cloud-json-request-v4";
/// The `oauth_refresh` action.
pub(crate) const OAUTH_REFRESH_FEATURE: &str = "cloud-oauth-refresh-v1";
/// The `oauth_refresh_circuit` action.
pub(crate) const OAUTH_REFRESH_CIRCUIT_FEATURE: &str = "cloud-oauth-refresh-circuit-v1";
/// The `command_lease` action.
pub(crate) const COMMAND_LEASE_FEATURE: &str = "cloud-command-lease-v1";
/// The `command_report` action.
pub(crate) const COMMAND_REPORT_FEATURE: &str = "cloud-command-report-v1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    guard_home: String,
    action: Action,
    /// A sign-in the caller already resolved.
    #[serde(default)]
    auth_context: Option<Map<String, Value>>,
    /// The session payload for `runtime_session`.
    #[serde(default)]
    session: Option<Value>,
    /// What the caller built for `receipts`.
    #[serde(default)]
    upload: Option<UploadRequest>,
    /// What the caller built for `request`.
    #[serde(default)]
    request: Option<JsonRequest>,
    /// What the caller asked to lease for `command_lease`.
    #[serde(default)]
    command_lease: Option<LeaseCall>,
    /// The job ack or result the caller asked to send for `command_report`.
    #[serde(default)]
    command_report: Option<ReportCall>,
    /// What the caller built for `oauth_refresh`.
    #[serde(default)]
    oauth_refresh: Option<RefreshCall>,
    /// What the caller asked of the refresh circuit for `oauth_refresh_circuit`.
    #[serde(default)]
    oauth_refresh_circuit: Option<CircuitCall>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    /// `sync_guard_events`.
    GuardEvents,
    /// `sync_pain_signals`.
    PainSignals,
    /// `sync_runtime_session`, up to the Cloud answer.
    RuntimeSession,
    /// `sync_receipts`, up to the Cloud answers.
    Receipts,
    /// One authenticated JSON request the caller built.
    Request,
    /// Lease the next Guard Cloud command job, exact Review jobs first.
    CommandLease,
    /// Ack a leased Guard Cloud command job or send its result.
    CommandReport,
    /// One refresh-token exchange for a grant the caller owns.
    OauthRefresh,
    /// Read or record the refresh circuit for the stored grant.
    OauthRefreshCircuit,
}

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return failure(&SyncError::Failed(
            "The event sync request was not understood.".to_owned(),
        ));
    };
    let answer = match request.action {
        // A request carries its own sign-in and endpoint; it reads no store.
        Action::Request => match &request.request {
            Some(call) => brokered(|| send(request.auth_context.as_ref(), call)),
            None => Err(SyncError::Failed(
                "The Guard Cloud request is missing.".to_owned(),
            )),
        },
        Action::CommandLease => match &request.command_lease {
            Some(call) => brokered(|| lease(request.auth_context.as_ref(), call)),
            None => Err(SyncError::Failed(
                "The Guard command lease is missing.".to_owned(),
            )),
        },
        Action::CommandReport => match &request.command_report {
            Some(call) => brokered(|| report(request.auth_context.as_ref(), call)),
            None => Err(SyncError::Failed(
                "The Guard command report is missing.".to_owned(),
            )),
        },
        Action::OauthRefresh => match &request.oauth_refresh {
            Some(call) => brokered(|| refresh(call)),
            None => Err(SyncError::Failed(
                "The Guard OAuth refresh request is missing.".to_owned(),
            )),
        },
        // The circuit is local state; it never reaches Guard Cloud. It runs
        // under the storage gate the other store writers hold.
        Action::OauthRefreshCircuit => match &request.oauth_refresh_circuit {
            Some(call) => {
                let guard_home = PathBuf::from(&request.guard_home);
                let bundle = store_for(&guard_home, None);
                event_store(&guard_home, &bundle)
                    .hold_gate()
                    .and_then(|_gate| {
                        let breaker =
                            circuit::Circuit::new(&guard_home, circuit::Backoff::from_env());
                        circuit::dispatch(&breaker, call).map_err(SyncError::Failed)
                    })
            }
            None => Err(SyncError::Failed(
                "The Guard OAuth refresh circuit call is missing.".to_owned(),
            )),
        },
        action => {
            let guard_home = PathBuf::from(request.guard_home);
            let bundle = store_for(&guard_home, request.auth_context);
            let store = event_store(&guard_home, &bundle);
            match action {
                Action::GuardEvents => brokered(|| sync_guard_events(&store)),
                Action::PainSignals => brokered(|| sync_pain_signals(&store)),
                Action::RuntimeSession => {
                    let session = request.session.unwrap_or(Value::Null);
                    brokered(|| sync_runtime_session(&store, &session))
                }
                Action::Receipts => match request.upload {
                    Some(upload) => {
                        let mut state = UploadState::default();
                        brokered(|| upload_receipts(&store, &upload, &mut state))
                    }
                    None => Err(SyncError::Failed(
                        "The receipt upload request is missing.".to_owned(),
                    )),
                },
                Action::Request
                | Action::CommandLease
                | Action::CommandReport
                | Action::OauthRefresh
                | Action::OauthRefreshCircuit => Err(SyncError::Failed(
                    "The Guard Cloud request is missing.".to_owned(),
                )),
            }
        }
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
        let answer = run_command(b"{\"guardHome\": \"/nonexistent\", \"action\": \"inventory\"}");
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(answer["outcome"], json!("failed"));
    }

    #[test]
    fn a_request_without_its_call_is_a_failure() {
        let answer = run_command(b"{\"guardHome\": \"/nonexistent\", \"action\": \"request\"}");
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(
            answer["error"],
            json!("The Guard Cloud request is missing.")
        );
    }

    #[test]
    fn a_report_without_its_call_is_a_failure() {
        let answer =
            run_command(b"{\"guardHome\": \"/nonexistent\", \"action\": \"command_report\"}");
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(
            answer["error"],
            json!("The Guard command report is missing.")
        );
    }

    #[test]
    fn a_circuit_action_without_its_call_is_a_failure() {
        let answer = run_command(
            b"{\"guardHome\": \"/nonexistent\", \"action\": \"oauth_refresh_circuit\"}",
        );
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(
            answer["error"],
            json!("The Guard OAuth refresh circuit call is missing.")
        );
    }
}
