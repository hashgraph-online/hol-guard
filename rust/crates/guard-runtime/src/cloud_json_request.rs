//! The `request` action of `cloud-event-sync`: one authenticated JSON POST to
//! Guard Cloud for a caller that already resolved the sign-in and built the
//! endpoint and body (the command queue, the Cloud Review event batches, the
//! workspace-review enrollment and the extension catalog upload).
//!
//! The runtime signs the request (DPoP included), runs the shared retry
//! machine under the machine's managed network policy and reports what came
//! back. A refusal is returned with its status, headers and body, so the caller
//! keeps reading Guard Cloud's error fields the way it did before.

use guard_command::egress_broker;
use guard_command::guard_sync_transport::{self as gst, SyncBudget, SyncFetchError};
use guard_command::supply_chain_package_eval::EvalError;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::cloud_bundle_fetch::SyncError;
use crate::cloud_event_sync::trusted_base;

/// The time one request, retries and their pauses included, may take.
const REQUEST_BUDGET_SECONDS: f64 = 300.0;
const INVALID_RESPONSE: &str = "Guard Cloud sync returned an invalid response payload.";

/// What the caller built.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct JsonRequest {
    url: String,
    /// The exact body, sent byte for byte: a catalog page is bound to its digest.
    body: String,
    timeout_seconds: f64,
    retry_timeout_seconds: f64,
    /// Refuse an answer larger than this many bytes.
    #[serde(default)]
    max_response_bytes: Option<usize>,
}

/// `_urlopen_json_with_timeout_retry(_guard_sync_request(...))`, one round.
///
/// `{"response": ...}` is Guard Cloud's object answer, `{"refusal": ...}` an
/// HTTP error that survived the retries, and `{"transport": ...}` a failure
/// with no HTTP answer.
pub(crate) fn send(
    auth: Option<&Map<String, Value>>,
    request: &JsonRequest,
) -> Result<Value, SyncError> {
    let auth = auth.ok_or_else(|| {
        SyncError::NotConfigured("A Guard Cloud request needs a resolved sign-in.".to_owned())
    })?;
    check_endpoint(auth, &request.url)?;
    let signed = gst::guard_sync_request(
        &Value::Object(auth.clone()),
        &request.url,
        "POST",
        Some(request.body.as_bytes()),
        None,
        None,
    )
    .map_err(|error| SyncError::Failed(error.to_string()))?;
    let budget = SyncBudget::new(REQUEST_BUDGET_SECONDS);
    let answer = gst::urlopen_json_detailed(
        &signed,
        request.timeout_seconds,
        request.retry_timeout_seconds,
        &budget,
    );
    if answer.is_err() && egress_broker::needs_pending() {
        return Err(SyncError::Pending);
    }
    match answer {
        Ok(answer) => accepted(answer, request.max_response_bytes),
        Err(SyncFetchError::Http(failure)) => Ok(json!({"refusal": {
            "status": failure.status,
            "headers": failure.headers,
            "body": String::from_utf8_lossy(&failure.body),
        }})),
        Err(SyncFetchError::Other(EvalError::Internal(reason))) if reason == INVALID_RESPONSE => {
            Err(SyncError::Failed(reason))
        }
        Err(SyncFetchError::Other(error)) => Ok(transport(&match error {
            EvalError::Internal(reason) => reason,
            other => other.to_string(),
        })),
    }
}

/// The request may only go to the origin the trusted sync URL names, so a
/// caller cannot send the sign-in anywhere else.
fn check_endpoint(auth: &Map<String, Value>, url: &str) -> Result<(), SyncError> {
    let base = trusted_base(auth)?;
    let issuer = auth
        .get("issuer")
        .and_then(Value::as_str)
        .filter(|issuer| !issuer.trim().is_empty());
    gst::validate_guard_sync_endpoint(url, issuer).map_err(SyncError::EndpointUntrusted)?;
    match (origin(&base), origin(url)) {
        (Some(expected), Some(actual)) if expected == actual => Ok(()),
        _ => Err(SyncError::EndpointUntrusted(
            "The Guard Cloud request does not go to the connected Guard Cloud.".to_owned(),
        )),
    }
}

/// `scheme://authority`, lowercased, of an absolute URL.
fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    (!scheme.is_empty() && !authority.is_empty())
        .then(|| format!("{scheme}://{authority}").to_ascii_lowercase())
}

/// An object answer within the caller's byte budget. The budget is checked on
/// the compact encoding, which is never longer than what Guard Cloud sent.
fn accepted(answer: Value, max_response_bytes: Option<usize>) -> Result<Value, SyncError> {
    if !answer.is_object() {
        return Err(SyncError::Failed(INVALID_RESPONSE.to_owned()));
    }
    if let Some(limit) = max_response_bytes {
        if answer.to_string().len() > limit {
            return Err(SyncError::Failed(
                "Guard Cloud sync response exceeds its byte budget.".to_owned(),
            ));
        }
    }
    Ok(json!({"response": answer}))
}

/// A failure with no HTTP answer, classed the way `_is_timeout_error` and
/// `_is_network_outage_error` read the `OSError` it used to raise.
fn transport(reason: &str) -> Value {
    json!({"transport": {
        "reason": reason,
        "timeout": reason.starts_with("timeout:"),
        "outage": gst::is_network_outage_reason(reason),
    }})
}

#[cfg(test)]
#[path = "cloud_json_request_tests.rs"]
mod tests;
