//! `POST /v1/hooks/<harness>` and `POST /v1/hooks/<harness>/readiness`: the
//! daemon's own review of a hook the resident's direct lane did not answer.
//!
//! The edge owns the caller check: a Codex or Claude Code hook must present
//! the identity proof it redeemed on this connection, and every other hook
//! the daemon's token. The hook worker reviews it through the
//! `route.hook_post` library call, which admits it under its deadline and the
//! scheduler's capacity and answers the harness's response. A call that
//! cannot run answers the harness's fail-safe instead, so a hook is never
//! left without a decision.

use serde_json::{json, Map, Value};

use super::super::http::Request;
use super::super::library::{self, CallError};
use super::{authorize_token, json_response, NativeReads, ReadConfig};
use crate::claude_hook_bridge_render::py_strip;

/// The daemon's fixed hook replies, declared once for every harness.
const ENVELOPES: &str = include_str!(
    "../../../../src/codex_plugin_scanner/guard/contracts/hook-fail-closed-envelopes.v1.json"
);
/// `availability_harness_response`'s reason for a hook the worker never reviewed.
const WORKER_UNAVAILABLE_REASON: &str =
    "HOL Guard could not complete the native hook decision safely.";
const WORKER_UNAVAILABLE_CODE: &str = "native_hook_worker_unavailable";

/// `CHALLENGE_HOOK_PATHS`: the hooks only an identity proof admits.
const CHALLENGE_PATHS: [&str; 2] = ["/v1/hooks/codex", "/v1/hooks/claude-code"];

/// The harness a hook path names, and whether it is the readiness route.
fn route(path: &str) -> Option<(&str, bool)> {
    let rest = path.strip_prefix("/v1/hooks/")?;
    let (harness, readiness) = match rest.split_once('/') {
        None => (rest, false),
        Some((harness, "readiness")) => (harness, true),
        Some(_) => return None,
    };
    (!harness.is_empty()).then_some((harness, readiness))
}

/// Whether the daemon reviews `POST path` here.
pub(in crate::daemon_edge) fn owns(path: &str) -> bool {
    route(path).is_some()
}

/// The request body as the daemon's handler reads it, or `None` for a body it
/// reads some other way.
fn payload(request: &Request<'_>, body: &[u8]) -> Option<Result<Map<String, Value>, ()>> {
    if body.is_empty() {
        return Some(Ok(Map::new()));
    }
    if !request
        .single_header("Content-Type")?
        .contains("application/json")
    {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    // A body serde rejects may still be one `json.loads` reads (`NaN`, a lone
    // surrogate escape); only a body neither reads is refused here.
    Some(match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(payload)) => Ok(payload),
        Ok(_) => Ok(Map::new()),
        Err(_) => Err(()),
    })
}

/// The response to the hook, or `None` for a request the daemon refuses on
/// its usual path (a caller without the credential, a disallowed origin).
pub(in crate::daemon_edge) fn respond(
    request: &Request<'_>,
    body: &[u8],
    port: u16,
    config: &ReadConfig,
    reads: &NativeReads,
    proof_verified: bool,
) -> Option<Vec<u8>> {
    let (harness, readiness) = route(request.path)?;
    if request.has_header("Transfer-Encoding") {
        return None;
    }
    let challenge = CHALLENGE_PATHS.contains(&request.path);
    let proven = challenge && proof_verified;
    if !proven {
        authorize_token(request, &config.token)?;
    }
    let answer = |status: u16, body: &Value, no_store: bool| {
        json_response(
            status,
            body,
            config.dashboard_build.as_deref(),
            None,
            no_store,
        )
    };
    if challenge && !proven {
        return Some(answer(
            401,
            &json!({
                "error": "daemon_identity_required",
                "repair": "Run `hol-guard daemon repair`.",
            }),
            false,
        ));
    }
    let payload = match payload(request, body)? {
        Ok(payload) => payload,
        Err(()) => {
            return Some(answer(
                400,
                &json!({ "error": "invalid_request_body" }),
                false,
            ))
        }
    };
    let event = payload
        .get("hook_event_name")
        .or_else(|| payload.get("event"))
        .and_then(Value::as_str)
        .map(|event| py_strip(event).to_owned())
        .filter(|event| !event.is_empty())
        .unwrap_or_else(|| "PreToolUse".to_owned());
    let mut args = Map::new();
    args.insert("path".to_owned(), request.path.into());
    args.insert("query".to_owned(), request.query.into());
    args.insert("payload".to_owned(), Value::Object(payload));
    args.insert("port".to_owned(), port.into());
    args.insert("daemon_pid".to_owned(), reads.daemon_pid().into());
    args.insert("home_dir".to_owned(), config.user_home.clone().into());
    args.insert("proof_verified".to_owned(), proven.into());
    if let Some(miss) = request.single_header("X-Guard-Direct-Miss") {
        args.insert("direct_miss".to_owned(), miss.into());
    }
    reads.report_activity();
    let reply = library::call(config, "route.hook_post", Value::Object(args));
    let (status, body, no_store) = match reply.as_ref().map(reply_parts) {
        Ok(Some(parts)) => parts,
        Ok(None) | Err(CallError::Raised(_)) | Err(CallError::Unavailable) if readiness => (
            503,
            json!({ "ready": false, "reason_code": "native_policy_not_ready" }),
            true,
        ),
        _ => (200, fail_safe(harness, &event), false),
    };
    Some(answer(status, &body, no_store))
}

/// The status, body and cache rule a `route.hook_post` answer carries.
fn reply_parts(answer: &Value) -> Option<(u16, Value, bool)> {
    let status = answer
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .filter(|status| (100..600).contains(status))?;
    let body = answer.get("body").filter(|body| body.is_object())?.clone();
    let no_store = answer.get("no_store").and_then(Value::as_bool)?;
    Some((status, body, no_store))
}

/// The harness's answer when the hook worker could not review the hook:
/// `fail_closed_response` with `native_hook_worker_unavailable`. Tool,
/// permission and prompt events get a constant deny in the harness envelope;
/// other events a constant payload that carries no verdict.
fn fail_safe(harness: &str, event: &str) -> Value {
    let contract: Value = serde_json::from_str(ENVELOPES).unwrap_or(Value::Null);
    let kind = event_kind(&contract, event);
    let reason = if kind == "prompt" {
        contract["defaults"]["prompt_reason"]
            .as_str()
            .unwrap_or(WORKER_UNAVAILABLE_REASON)
    } else {
        WORKER_UNAVAILABLE_REASON
    };
    let table = &contract["envelopes"][kind.as_str()];
    let harness = harness.trim().to_lowercase().replace('_', "-");
    let template = table
        .get(harness.as_str())
        .or_else(|| table.get("*"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    fill(
        template,
        &[
            ("$reason", reason),
            ("$reason_code", WORKER_UNAVAILABLE_CODE),
            ("$event_name", event),
        ],
    )
}

/// `_event_kind`: the envelope family an event name belongs to.
fn event_kind(contract: &Value, event: &str) -> String {
    let compact: String = event
        .trim()
        .to_lowercase()
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .collect();
    if let Some(kind) = contract["events"]
        .get(compact.as_str())
        .and_then(Value::as_str)
    {
        return kind.to_owned();
    }
    contract["event_prefixes"]
        .as_object()
        .into_iter()
        .flatten()
        .find(|(prefix, _)| compact.starts_with(prefix.as_str()))
        .and_then(|(_, kind)| kind.as_str())
        .unwrap_or("lifecycle")
        .to_owned()
}

/// The envelope with its whole-string placeholders filled.
fn fill(template: Value, values: &[(&str, &str)]) -> Value {
    match template {
        Value::String(text) => values
            .iter()
            .find(|(placeholder, _)| *placeholder == text)
            .map_or(Value::String(text), |(_, value)| json!(value)),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, fill(value, values)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|item| fill(item, values)).collect())
        }
        other => other,
    }
}

#[cfg(test)]
#[path = "daemon_edge_hook_review_tests.rs"]
mod tests;
