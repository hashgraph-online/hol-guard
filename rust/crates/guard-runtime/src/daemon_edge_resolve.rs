//! `POST /v1/requests/{id}/approve|block` and `POST [/v1]/approvals/{id}/decision`:
//! resolving a pending approval request.
//!
//! The route is matched and its scope fields checked natively. The decision
//! itself (scope selection, the approval gate, the policy write, matching
//! requests and the harness continuation) is the Guard library's
//! `approval.resolve` call. This module turns its answer or error into the
//! daemon's reply, including the recovery copy the approval page shows.

use std::net::{IpAddr, SocketAddr};

use guard_contracts::{DaemonRoutePayloadV1, DaemonTextFieldV1};
use serde_json::{json, Map, Value};

use super::super::super::library::{self, CallError};
use super::DROPPED;
use crate::guard_store_json::py_strip;

/// `_HARNESS_RETRY_COPY`.
const HARNESS_RETRY_COPY: [(&str, &str); 6] = [
    ("codex", "Return to Codex and retry"),
    ("claude-code", "Return to Claude and retry"),
    ("opencode", "Return to OpenCode and retry"),
    ("copilot", "Return to Copilot and retry"),
    ("pi", "Return to Pi and retry"),
    ("omp", "Return to Oh My Pi and retry"),
];
/// `_DEFAULT_RETRY_COPY`.
const DEFAULT_RETRY_COPY: &str = "Return to your AI assistant and retry";

/// Whether `path` is one of the resolution routes.
pub(in crate::daemon_edge) fn owns(path: &str) -> bool {
    !matches!(
        resolve(path, &Map::new()),
        DaemonRoutePayloadV1::ResolveRequest { ref outcome, .. } if outcome == "not_matched"
    )
}

fn text_field(value: Option<&Value>) -> DaemonTextFieldV1 {
    match value {
        None | Some(Value::Null) => DaemonTextFieldV1::Absent,
        Some(Value::String(text)) => DaemonTextFieldV1::Text {
            value: py_strip(text).to_owned(),
        },
        Some(_) => DaemonTextFieldV1::Invalid,
    }
}

fn resolve(path: &str, payload: &Map<String, Value>) -> DaemonRoutePayloadV1 {
    crate::daemon_route_resolve::resolve_request(
        path,
        &text_field(payload.get("action")),
        &text_field(payload.get("scope")),
        &text_field(payload.get("scope_contract_version")),
        &text_field(payload.get("scope_contract_digest")),
    )
}

/// `_build_resolution_copy` for every harness, keyed by harness name; the
/// empty key is the copy for any other harness.
pub(in crate::daemon_edge) fn copy_table(action: &str) -> Value {
    let title = if action == "allow" {
        "Approved. Retry in chat."
    } else {
        "Blocked. Decision saved."
    };
    let mut table = Map::new();
    for (harness, body) in HARNESS_RETRY_COPY {
        table.insert(harness.to_owned(), json!({"title": title, "body": body}));
    }
    table.insert(
        String::new(),
        json!({"title": title, "body": DEFAULT_RETRY_COPY}),
    );
    Value::Object(table)
}

/// `_build_local_url`.
fn local_url(local: SocketAddr, path: &str) -> String {
    match local.ip() {
        IpAddr::V6(address) => format!("http://[{address}]:{}{path}", local.port()),
        IpAddr::V4(address) => format!("http://{address}:{}{path}", local.port()),
    }
}

/// The reply: status, body and whether it must not be cached. `None` when
/// the library could not be reached, so the request is relayed untouched.
pub(in crate::daemon_edge) fn respond(
    path: &str,
    payload: &Map<String, Value>,
    local: SocketAddr,
    resolve_scope_matches: bool,
    call: impl FnOnce(Value) -> Result<Value, CallError>,
) -> Option<(u16, Value, bool)> {
    let DaemonRoutePayloadV1::ResolveRequest {
        outcome,
        request_id,
        action,
        scope,
        scope_contract_version,
        scope_contract_digest,
    } = resolve(path, payload)
    else {
        return None;
    };
    if outcome == "not_matched" {
        return None;
    }
    let (true, Some(request_id), Some(action), Some(scope)) =
        (outcome == "resolved", request_id, action, scope)
    else {
        return Some((400, json!({"resolved": false, "error": outcome}), false));
    };
    let queue_url = local_url(local, "/#/inbox");
    let args = json!({
        "request_id": request_id,
        "action": action,
        "scope": scope,
        "scope_contract_version": scope_contract_version,
        "scope_contract_digest": scope_contract_digest,
        "payload": Value::Object(payload.clone()),
        // A session opened from an approval link settles only its own
        // request; any other caller's scoped decision also settles the
        // other pending requests it matches.
        "resolve_scope_matches": resolve_scope_matches,
        "copy": copy_table(&action),
    });
    let answer = match call(args) {
        Ok(Value::Object(answer)) => answer,
        Ok(_) => return Some((DROPPED, Value::Null, false)),
        Err(CallError::Unavailable) => return None,
        Err(CallError::Raised(error)) => return Some(raised(error, &queue_url)),
    };
    if let Some(body) = answer.get("idempotent").filter(|body| body.is_object()) {
        return Some((200, body.clone(), false));
    }
    if answer.get("already_resolved") == Some(&Value::Bool(true)) {
        return Some((
            409,
            json!({
                "resolved": false,
                "error": "already_resolved",
                "recovery": {
                    "code": "request_resolved",
                    "title": "This request has already been resolved.",
                    "body": "If the action is blocked and you believe it should be allowed, \
                             you can re-submit from your AI assistant.",
                    "queue_url": queue_url,
                },
            }),
            false,
        ));
    }
    match answer.get("updated") {
        Some(updated @ Value::Object(_)) => Some((200, updated.clone(), false)),
        _ => Some((DROPPED, Value::Null, false)),
    }
}

/// The reply for an error the library raised.
fn raised(mut error: Map<String, Value>, queue_url: &str) -> (u16, Value, bool) {
    let message = error
        .get("message")
        .cloned()
        .unwrap_or(Value::String(String::new()));
    match error.get("kind").and_then(Value::as_str) {
        Some("approval_gate") => {
            let status = error
                .get("status")
                .and_then(Value::as_u64)
                .and_then(|status| u16::try_from(status).ok())
                .filter(|status| (100..600).contains(status));
            match (status, error.remove("payload")) {
                (Some(status), Some(Value::Object(mut body))) => {
                    body.insert("resolved".to_owned(), Value::Bool(false));
                    (status, Value::Object(body), false)
                }
                _ => (DROPPED, Value::Null, false),
            }
        }
        Some("not_found") => (
            404,
            json!({
                "resolved": false,
                "error": "not_found",
                "recovery": {
                    "code": "request_unknown",
                    "title": "This request is no longer waiting.",
                    "body": "The request was either already resolved or expired. You can close this tab.",
                    "queue_url": queue_url,
                },
            }),
            false,
        ),
        Some("stale_scope_contract") => {
            let mut body = Map::new();
            body.insert("resolved".to_owned(), Value::Bool(false));
            body.insert("error".to_owned(), message);
            extend(&mut body, error.remove("contract"));
            (409, Value::Object(body), false)
        }
        Some("ineligible_scope") => {
            let mut body = Map::new();
            body.insert("resolved".to_owned(), Value::Bool(false));
            body.insert("error".to_owned(), message);
            for key in ["action", "requested_scope"] {
                body.insert(key.to_owned(), error.remove(key).unwrap_or(Value::Null));
            }
            extend(&mut body, error.remove("contract"));
            (422, Value::Object(body), false)
        }
        Some("scope_unavailable") => (
            503,
            json!({"resolved": false, "error": "native_approval_scope_unavailable"}),
            true,
        ),
        Some("local_tool_grant_unavailable") => {
            (503, json!({"resolved": false, "error": message}), true)
        }
        Some("value") => (400, json!({"resolved": false, "error": message}), false),
        // The daemon's handler raised: the connection closes unanswered.
        _ => (DROPPED, Value::Null, false),
    }
}

fn extend(body: &mut Map<String, Value>, extra: Option<Value>) {
    if let Some(Value::Object(extra)) = extra {
        body.extend(extra);
    }
}

/// Runs the resolution through the Guard CLI.
pub(in crate::daemon_edge) fn call_library(
    config: &super::super::ReadConfig,
) -> impl FnOnce(Value) -> Result<Value, CallError> + '_ {
    move |args| library::call(config, "approval.resolve", args)
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_resolve_tests.rs"]
mod tests;
