//! How a Guard Cloud HTTP error reads to the user, for `RunnerAuthority`.
//!
//! Python reads the error's status, reason, Cloudflare headers and body once
//! and ships them here. The answer carries every reading a caller takes from
//! one error: the sync message, the retryable classification, the 403
//! plan-restriction verdict and the Cloudflare edge-block message.

use serde_json::{json, Map, Value};

use super::cloud_request_text::{optional_string, py_strip};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

/// Start of the message for a request Cloudflare blocked or challenged; it
/// matches `CLOUD_EDGE_BLOCK_REASON_PREFIX` in guard_sync_transport.rs.
const CLOUD_EDGE_BLOCK_REASON_PREFIX: &str = "Guard Cloud is unreachable from this network";
/// Characters of a body searched for a Cloudflare block or challenge page.
const EDGE_PAGE_CHARS: usize = 64 * 1024;
const RETRYABLE_STATUSES: [u64; 3] = [429, 503, 524];
const UNAVAILABLE_CODES: [&str; 2] = ["guard_unavailable", "guard_cloud_unavailable"];
const PLAN_403_KEYWORDS: [&str; 9] = [
    "sync_not_available",
    "plan_restriction",
    "requires a pro",
    "requires a team",
    "upgrade your plan",
    "upgrade to",
    "subscription required",
    "not included in your plan",
    "guard sync requires",
];

struct HttpError<'a> {
    status: u64,
    reason: &'a str,
    /// `None` when the error carried no headers at all.
    headers: Option<&'a Map<String, Value>>,
    body: &'a str,
}

pub(crate) fn cloud_http_error(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let headers = match args.get("headers") {
        None | Some(Value::Null) => None,
        Some(Value::Object(headers)) => Some(headers),
        Some(_) => return Err(ERR_INVALID),
    };
    let error = HttpError {
        status: args
            .get("status")
            .and_then(Value::as_u64)
            .ok_or(ERR_INVALID)?,
        reason: args
            .get("reason")
            .and_then(Value::as_str)
            .ok_or(ERR_INVALID)?,
        headers,
        body: args
            .get("body")
            .and_then(Value::as_str)
            .ok_or(ERR_INVALID)?,
    };
    let payload = match serde_json::from_str::<Value>(error.body) {
        Ok(Value::Object(payload)) => Some(payload),
        _ => None,
    };
    let edge_block = edge_block_message(&error);
    let (message, retryable) = error_details(&error, payload.as_ref());
    let (plan_restricted, plan_message) = match &edge_block {
        Some(edge_block) => (false, edge_block.clone()),
        None => plan_restriction(&error, payload.as_ref()),
    };
    let sync_message = match &edge_block {
        Some(edge_block) => edge_block.clone(),
        None => payload
            .as_ref()
            .and_then(guard_cloud_error_message)
            .unwrap_or_else(|| fallback_message(&error)),
    };
    Ok(json!({
        "message": message,
        "retryable": retryable,
        "sync_message": sync_message,
        "plan_restricted": plan_restricted,
        "plan_message": plan_message,
        "edge_block": edge_block,
    }))
}

/// The stripped body, or the status line when the body is blank.
fn fallback_message(error: &HttpError<'_>) -> String {
    let body = py_strip(error.body);
    if body.is_empty() {
        format!("HTTP Error {}: {}", error.status, error.reason)
    } else {
        body.to_owned()
    }
}

/// The message Guard Cloud put in its JSON error body, if any.
fn guard_cloud_error_message(payload: &Map<String, Value>) -> Option<String> {
    if let Some(Value::Object(guard_error)) = payload.get("guardError") {
        for key in ["msg", "message"] {
            if let Some(message) = optional_string(guard_error.get(key)) {
                return Some(message.to_owned());
            }
        }
    }
    ["err", "message", "error"]
        .into_iter()
        .find_map(|key| optional_string(payload.get(key)))
        .map(str::to_owned)
}

fn error_details(error: &HttpError<'_>, payload: Option<&Map<String, Value>>) -> (String, bool) {
    let mut retryable = RETRYABLE_STATUSES.contains(&error.status);
    let mut message = None;
    if let Some(payload) = payload {
        message = guard_cloud_error_message(payload);
        if let Some(Value::Object(guard_error)) = payload.get("guardError") {
            if guard_error.get("retryable") == Some(&Value::Bool(true)) {
                retryable = true;
            }
            if let Some(Value::String(code)) = guard_error.get("code") {
                let code = py_strip(code).to_lowercase();
                if UNAVAILABLE_CODES.contains(&code.as_str()) {
                    retryable = true;
                }
            }
        }
    }
    (
        message.unwrap_or_else(|| fallback_message(error)),
        retryable,
    )
}

/// Whether a 403 says the plan lacks the feature, checking both the
/// machine-readable fields and the human-readable error for that signal.
fn plan_restriction(error: &HttpError<'_>, payload: Option<&Map<String, Value>>) -> (bool, String) {
    let fallback = fallback_message(error);
    let Some(payload) = payload else {
        return (false, fallback);
    };
    let message = optional_string(payload.get("error"))
        .map(str::to_owned)
        .unwrap_or(fallback);
    if payload.get("syncEnabled") == Some(&Value::Bool(false)) {
        return (true, message);
    }
    let combined = format!(
        "{} {}",
        python_text(payload.get("error")),
        python_text(payload.get("code"))
    );
    let restricted = PLAN_403_KEYWORDS
        .iter()
        .any(|keyword| combined.contains(keyword));
    (restricted, message)
}

/// `str(value or "").lower()`: a falsy value reads as empty, anything else as
/// its text. A container's text is its JSON, which carries the same words.
fn python_text(value: Option<&Value>) -> String {
    let text = match value {
        None | Some(Value::Null | Value::Bool(false)) => String::new(),
        Some(Value::Bool(true)) => "true".to_owned(),
        Some(Value::Number(number)) if number.as_f64() == Some(0.0) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) if items.is_empty() => String::new(),
        Some(Value::Object(fields)) if fields.is_empty() => String::new(),
        Some(other) => other.to_string(),
    };
    text.to_lowercase()
}

/// Cloudflare's own block or challenge page instead of a Guard Cloud answer.
/// The page is HTML a client cannot pass, so its raw text is no use as an error.
fn edge_block_message(error: &HttpError<'_>) -> Option<String> {
    let headers = error.headers?;
    let header = |name: &str| headers.get(name).and_then(Value::as_str);
    let challenged = header("cf-mitigated").is_some();
    let from_cloudflare = header("cf-ray").is_some()
        || header("server").is_some_and(|server| server.to_lowercase() == "cloudflare");
    let html =
        header("content-type").is_some_and(|kind| kind.to_lowercase().starts_with("text/html"));
    let page = match error.body.char_indices().nth(EDGE_PAGE_CHARS) {
        Some((end, _)) => &error.body[..end],
        None => error.body,
    };
    let challenge_page = page.contains("Just a moment...") || page.contains("challenge-platform");
    let block_page = page.contains("Attention Required! | Cloudflare")
        || page.contains("Sorry, you have been blocked");
    if !challenged && !(from_cloudflare && html && (challenge_page || block_page)) {
        return None;
    }
    let action = if challenged || challenge_page {
        "challenged"
    } else {
        "blocked"
    };
    let ray = header("cf-ray")
        .unwrap_or_default()
        .split('-')
        .next()
        .unwrap_or_default();
    let (ray_detail, ray_hint) =
        if !ray.is_empty() && ray.bytes().all(|b| b.is_ascii_alphanumeric()) {
            (
                format!(", Ray ID {ray}"),
                "; the Guard Cloud operator can look up that Ray ID",
            )
        } else {
            (String::new(), "")
        };
    Some(format!(
        "{CLOUD_EDGE_BLOCK_REASON_PREFIX}: Cloudflare in front of Guard Cloud {action} the request \
         (HTTP {}{ray_detail}). This is not a sign-in problem, so reconnecting will not help{ray_hint}.",
        error.status
    ))
}
