//! The `request` action of `cloud-event-sync`: one authenticated JSON GET or
//! POST to Guard Cloud for a caller that already resolved the sign-in and built
//! the endpoint and body (the command queue, the Cloud Review event batches,
//! the workspace-review enrollment, Cloud exception requests, the insights
//! share, the policy delivery status and the machine health lease channel).
//!
//! The runtime signs the request (DPoP included), runs the shared retry
//! machine under the machine's managed network policy and reports what came
//! back. A refusal is returned with its status, headers and body, so the caller
//! keeps reading Guard Cloud's error fields the way it did before.

use std::fs;
use std::io::Read;
use std::path::Path;

use guard_command::egress_broker;
use guard_command::guard_sync_transport::{self as gst, SyncBudget, SyncFetchError};
use guard_command::supply_chain_package_eval::EvalError;
use guard_contracts::EGRESS_MAX_IN_PROCESS_NEED_BODY_BYTES;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::cloud_bundle_fetch::SyncError;
use crate::cloud_event_sync::trusted_base;

/// The time one request, retries and their pauses included, may take.
const REQUEST_BUDGET_SECONDS: f64 = 300.0;
const INVALID_RESPONSE: &str = "Guard Cloud sync returned an invalid response payload.";

/// The two methods a Guard Cloud JSON request uses.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum Method {
    Get,
    #[default]
    Post,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// What the caller built.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct JsonRequest {
    url: String,
    #[serde(default)]
    method: Method,
    /// The exact body, sent byte for byte. A POST carries this or
    /// `body_file`, and a GET neither.
    #[serde(default)]
    body: Option<String>,
    /// A private file holding a body too large for the command's stdin, such
    /// as an extension catalog page. Read once, byte for byte.
    #[serde(default)]
    body_file: Option<String>,
    timeout_seconds: f64,
    retry_timeout_seconds: f64,
    /// How the success is reported: Guard Cloud's object answer, or the status
    /// and body as they came back.
    #[serde(default)]
    answer: Answer,
    /// The largest raw body the caller reads. A longer body is reported as
    /// oversized instead of returned, so a small channel keeps its own limit.
    #[serde(default)]
    max_response_bytes: Option<u64>,
}

/// What the caller reads from a successful exchange.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Answer {
    /// `{"response": ...}`: the body parsed as a JSON object.
    #[default]
    Json,
    /// `{"raw": {"status", "body"}}`: the 2xx status and the UTF-8 body
    /// unread, for an endpoint that may answer `204 No Content` or whose body
    /// the caller parses under its own limits.
    Raw,
}

/// `_urlopen_json_with_timeout_retry(_guard_sync_request(...))`, one round.
///
/// `{"response": ...}` is Guard Cloud's object answer (`{"raw": ...}` when the
/// caller asked for the status and body unread), `{"refusal": ...}` an
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
    let body = request_body(request)?;
    let signed = gst::guard_sync_request(
        &Value::Object(auth.clone()),
        &request.url,
        request.method.as_str(),
        body.as_deref(),
        None,
        None,
    )
    .map_err(|error| SyncError::Failed(error.to_string()))?;
    let budget = SyncBudget::new(REQUEST_BUDGET_SECONDS);
    let answer = match request.answer {
        Answer::Json => gst::urlopen_json_detailed(
            &signed,
            request.timeout_seconds,
            request.retry_timeout_seconds,
            &budget,
        )
        .map(Answered::Json),
        Answer::Raw => gst::urlopen_raw_detailed(
            &signed,
            request.timeout_seconds,
            request.retry_timeout_seconds,
            &budget,
        )
        .map(|(status, body)| Answered::Raw(status, body)),
    };
    if answer.is_err() && egress_broker::needs_pending() {
        return Err(SyncError::Pending);
    }
    match answer {
        Ok(Answered::Json(answer)) => accepted(answer),
        Ok(Answered::Raw(status, body)) => raw(status, body, request.max_response_bytes),
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

/// The body the method calls for: one for a POST, none for a GET.
fn request_body(request: &JsonRequest) -> Result<Option<Vec<u8>>, SyncError> {
    let failed = |reason: &str| Err(SyncError::Failed(reason.to_owned()));
    match (
        request.method,
        request.body.as_deref(),
        request.body_file.as_deref(),
    ) {
        (Method::Post, Some(body), None) => Ok(Some(body.as_bytes().to_vec())),
        (Method::Post, None, Some(path)) => read_body_file(Path::new(path)).map(Some),
        (Method::Post, None, None) => failed("A Guard Cloud POST needs a body."),
        (Method::Post, Some(_), Some(_)) => failed("A Guard Cloud POST carries one body."),
        (Method::Get, None, None) => Ok(None),
        (Method::Get, _, _) => failed("A Guard Cloud GET carries no body."),
    }
}

/// A regular file, never a link, no larger than an in-process request body.
fn read_body_file(path: &Path) -> Result<Vec<u8>, SyncError> {
    let unreadable =
        || SyncError::Failed("The Guard Cloud request body could not be read.".to_owned());
    if !path.is_absolute() {
        return Err(unreadable());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| unreadable())?;
    let limit = EGRESS_MAX_IN_PROCESS_NEED_BODY_BYTES as u64;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(unreadable());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|_| unreadable())?;
    if bytes.len() as u64 > limit {
        return Err(unreadable());
    }
    Ok(bytes)
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

/// `scheme://authority`, lowercased, of an absolute URL, without the
/// scheme's default port, so `https://hol.org:443` and `https://hol.org` match.
fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => Some(":443"),
        "http" => Some(":80"),
        _ => None,
    };
    let authority = default_port
        .and_then(|port| authority.strip_suffix(port))
        .unwrap_or(&authority);
    (!scheme.is_empty() && !authority.is_empty()).then(|| format!("{scheme}://{authority}"))
}

/// Guard Cloud's answer, which must be an object.
fn accepted(answer: Value) -> Result<Value, SyncError> {
    if !answer.is_object() {
        return Err(SyncError::Failed(INVALID_RESPONSE.to_owned()));
    }
    Ok(json!({"response": answer}))
}

/// A successful exchange, in the form the caller asked for.
enum Answered {
    Json(Value),
    Raw(u16, Vec<u8>),
}

/// The status and body as they came back; the body must be UTF-8.
fn raw(status: u16, body: Vec<u8>, max_bytes: Option<u64>) -> Result<Value, SyncError> {
    if max_bytes.is_some_and(|max| body.len() as u64 > max) {
        return Ok(json!({"raw": {"status": status, "oversized": true}}));
    }
    let body =
        String::from_utf8(body).map_err(|_| SyncError::Failed(INVALID_RESPONSE.to_owned()))?;
    Ok(json!({"raw": {"status": status, "body": body}}))
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
