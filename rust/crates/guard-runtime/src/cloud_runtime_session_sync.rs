//! Publish the active Guard runtime session (`runner.sync_runtime_session`)
//! so the dashboard shows the machine right away. The caller builds the
//! session payload and finishes the Extension catalog step with the answer.

use guard_command::cloud_scrub::redact_sensitive_text;
use guard_command::local_supply_chain::utc_now_iso;
use serde_json::{json, Value};

use crate::cloud_bundle_fetch::{resolve_auth, unreachable_message, SyncError};
use crate::cloud_event_sync::{
    answer_text, post, retry_after_seconds, route_url, trusted_base, EventStore, Refusal, Timeouts,
};

pub(crate) const RUNTIME_SESSION_SUMMARY_KEY: &str = "runtime_session_summary";
const ENDPOINT_UNAVAILABLE: &str = "runtime_session_endpoint_unavailable";
const RATE_LIMITED: &str = "runtime_session_rate_limited";
/// `_RUNTIME_SYNC_TIMEOUT_SECONDS` / `_RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS`.
const RUNTIME_SESSION_TIMEOUTS: Timeouts = (10.0, 90.0);

/// The summary saved when Cloud has no runtime session route (404) or asks
/// the device to slow down (429). The session stays local until the next sync.
fn skipped_summary(session: &Value, reason: &str, recorded_at: &str) -> Value {
    json!({
        "synced_at": null,
        "runtime_session_synced_at": null,
        "runtime_session_id": session.get("sessionId").cloned().unwrap_or(Value::Null),
        "runtime_sessions_visible": 0,
        "runtime_session_sync_skipped": true,
        "runtime_session_sync_reason": reason,
        "local_guard_online_at": recorded_at,
        "runtime_harness": session.get("harness").cloned().unwrap_or(Value::Null),
        "runtime_surface": session.get("surface").cloned().unwrap_or(Value::Null),
        "runtime_workspace": session.get("workspace").cloned().unwrap_or(Value::Null),
        "runtime_device_id": session.get("deviceId").cloned().unwrap_or(Value::Null),
    })
}

/// `sync_runtime_session` up to the Cloud answer. A delivered session returns
/// `{"status": "synced", "response": ...}` with the Cloud reply, which the
/// caller needs for the catalog handshake. A 404 or 429 saves and returns
/// `{"status": "skipped", "summary": ...}`.
pub(crate) fn sync_runtime_session(
    store: &EventStore<'_>,
    session: &Value,
) -> Result<Value, SyncError> {
    if !session.is_object() {
        return Err(SyncError::Failed(
            "The runtime session payload must be an object.".to_owned(),
        ));
    }
    let supplied = store.bundle.auth.as_ref().filter(|auth| !auth.is_empty());
    crate::cloud_event_sync::screen_supplied(supplied)?;
    let auth = resolve_auth(&store.bundle.resident, false, supplied)?;
    let url = route_url("runtime_sessions", &trusted_base(&auth)?)?;
    let refusal = match post(
        &auth,
        &url,
        &json!({"session": session}),
        true,
        RUNTIME_SESSION_TIMEOUTS,
    ) {
        Ok(Some(response)) if response.is_object() => {
            return Ok(json!({"status": "synced", "response": response}));
        }
        Ok(_) => return Err(SyncError::Failed("Invalid sync response".to_owned())),
        Err(Err(error)) => return Err(error),
        Err(Ok(refusal)) => refusal,
    };
    match refusal {
        Refusal::Http {
            status: status @ (404 | 429),
            retry_after,
            ..
        } => {
            let recorded_at = utc_now_iso();
            let reason = if status == 404 {
                ENDPOINT_UNAVAILABLE
            } else {
                RATE_LIMITED
            };
            let mut summary = skipped_summary(session, reason, &recorded_at);
            if status == 429 {
                summary["retry_after_seconds"] = json!(retry_after_seconds(retry_after.as_deref()));
            }
            store.save(RUNTIME_SESSION_SUMMARY_KEY, &summary, &recorded_at)?;
            Ok(json!({"status": "skipped", "summary": summary}))
        }
        Refusal::Http { status, answer, .. } => Err(SyncError::Failed(redact_sensitive_text(
            &answer_text(answer.as_ref(), "sync_message", status),
        ))),
        Refusal::Transport(reason) => Err(SyncError::Failed(unreachable_message(&reason))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_skipped_session_keeps_its_identity_and_names_the_reason() {
        let session = json!({
            "sessionId": "session-1",
            "harness": "hol-guard",
            "surface": "cli",
            "workspace": "local-machine",
            "deviceId": "device-1",
        });
        let summary = skipped_summary(&session, RATE_LIMITED, "2026-11-19T00:00:00+00:00");
        assert_eq!(summary["runtime_session_id"], json!("session-1"));
        assert_eq!(summary["runtime_device_id"], json!("device-1"));
        assert_eq!(summary["runtime_sessions_visible"], json!(0));
        assert_eq!(summary["runtime_session_sync_reason"], json!(RATE_LIMITED));
        assert_eq!(summary["synced_at"], Value::Null);
        assert_eq!(
            summary["local_guard_online_at"],
            json!("2026-11-19T00:00:00+00:00")
        );
    }
}
