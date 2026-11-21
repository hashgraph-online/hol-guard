//! The `command_report` action of `cloud-event-sync`: tell Guard Cloud a
//! leased command job was taken up or how it ended. Ported from `_heartbeat`
//! and `_post_result` in `runtime/command_queue.py`.
//!
//! The runtime picks the route the job was leased on (the exact Cloud Review
//! route or the generic queue), names the job's report path, builds the ack
//! body and sends it through the `request` action's signed transport. A
//! result body is the caller's: it is sent byte for byte, inline or from a
//! private file when it is too large for the command's stdin. The answer
//! carries the URL the report went to beside the `request` action's reply, so
//! the caller raises a refusal against the route it reached.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::cloud_bundle_fetch::SyncError;
use crate::cloud_command_lease::{
    origin, EXACT_BASE, EXACT_PROTOCOL_VERSION, QUEUE_BASE, RETRY_TIMEOUT_SECONDS, TIMEOUT_SECONDS,
};
use crate::cloud_event_sync::trusted_base;
use crate::cloud_json_request::{send, JsonRequest};

/// Which report the caller sends for the job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReportKind {
    /// The job was taken up: an exact job's ack, a generic job's heartbeat.
    Ack,
    /// How the job ended.
    Result,
}

/// The job a report is about and what it carries.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReportCall {
    job_id: String,
    /// Whether the job was leased on the exact Cloud Review route.
    exact: bool,
    kind: ReportKind,
    /// The lease an ack renews.
    #[serde(default)]
    lease_id: Option<String>,
    /// A result body, inline.
    #[serde(default)]
    body: Option<String>,
    /// A private file holding a result body too large for the command's stdin.
    #[serde(default)]
    body_file: Option<String>,
}

/// Where a report goes, below the connected Guard Cloud's origin, and what it
/// carries: an inline body or the file holding it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Planned {
    pub(crate) path: String,
    pub(crate) body: Option<String>,
    pub(crate) body_file: Option<String>,
}

/// Send the report through the signed transport, to the connected Guard
/// Cloud's origin, and answer `{"url", "reply"}`.
pub(crate) fn report(
    auth: Option<&serde_json::Map<String, Value>>,
    call: &ReportCall,
) -> Result<Value, SyncError> {
    let signed_in = auth.ok_or_else(|| {
        SyncError::NotConfigured("A Guard Cloud request needs a resolved sign-in.".to_owned())
    })?;
    let base = trusted_base(signed_in)?;
    let origin = origin(&base)
        .ok_or_else(|| SyncError::Failed(format!("Guard sync URL is invalid: {base}")))?;
    let planned = plan(call)?;
    let url = format!("{origin}{}", planned.path);
    let request: JsonRequest = serde_json::from_value(json!({
        "url": url,
        "method": "POST",
        "body": planned.body,
        "bodyFile": planned.body_file,
        "timeoutSeconds": TIMEOUT_SECONDS,
        "retryTimeoutSeconds": RETRY_TIMEOUT_SECONDS,
    }))
    .map_err(|_| SyncError::Failed("The Guard command report was not built.".to_owned()))?;
    let reply = send(auth, &request)?;
    Ok(json!({"url": url, "reply": reply}))
}

/// The route, path and body of the report `call` asks for.
pub(crate) fn plan(call: &ReportCall) -> Result<Planned, SyncError> {
    let refused = |reason: &str| Err(SyncError::Failed(reason.to_owned()));
    if !is_path_segment(&call.job_id) {
        return refused("The Guard command job id cannot name a report path.");
    }
    let route = if call.exact { EXACT_BASE } else { QUEUE_BASE };
    let job = &call.job_id;
    match call.kind {
        ReportKind::Ack => {
            let lease = match call.lease_id.as_deref() {
                Some(lease) if !lease.is_empty() => lease,
                _ => return refused("A Guard command ack needs the job's lease id."),
            };
            if call.body.is_some() || call.body_file.is_some() {
                return refused("A Guard command ack carries no result body.");
            }
            let (path, body) = if call.exact {
                (
                    "ack",
                    json!({"leaseId": lease, "protocolVersion": EXACT_PROTOCOL_VERSION}),
                )
            } else {
                ("heartbeat", json!({"leaseId": lease}))
            };
            Ok(Planned {
                path: format!("{route}/{job}/{path}"),
                body: Some(body.to_string()),
                body_file: None,
            })
        }
        ReportKind::Result => {
            if call.lease_id.is_some() {
                return refused("A Guard command result carries its lease in its body.");
            }
            match (&call.body, &call.body_file) {
                (Some(_), Some(_)) | (None, None) => {
                    refused("A Guard command result carries one body.")
                }
                (body, body_file) => Ok(Planned {
                    path: format!("{route}/{job}/result"),
                    body: body.clone(),
                    body_file: body_file.clone(),
                }),
            }
        }
    }
}

/// One URL path segment Guard Cloud issued: no separator, query, fragment,
/// escape, whitespace or dot segment that would send the report elsewhere.
fn is_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|ch| ch.is_ascii_graphic() && !matches!(ch, '/' | '\\' | '?' | '#' | '%'))
}

#[cfg(test)]
#[path = "cloud_command_report_tests.rs"]
mod tests;
