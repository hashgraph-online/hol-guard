//! `mcp_policy_input` runner-authority kind: the argument checks the MCP
//! policy authoring tools run before they parse a policy.
//!
//! `{"tool": "validate_policy" | "create_policy" | "get_policy_creation",
//! "arguments": {...}}` carries the tool call's arguments as the client sent
//! them. Every field is bounded, type-checked, and refused when unknown; no
//! caller-supplied path, URL, origin, environment override, or credential is
//! accepted. The answer is `{"value": {...}}` with the checked fields, or
//! `{"error": {"code", "message"}}` with the first refusal in the order the
//! tools always checked. The value never repeats the policy text: the caller
//! keeps the `policyYaml` it sent once the check passes.
//!
//! - `validate_policy`: `{"mode"}`, `merge` when absent.
//! - `create_policy`: `{"mode", "candidate_digest", "expected_current_digest",
//!   "idempotency_key"}`, with `mode` required.
//! - `get_policy_creation`: `{"request_id"}`.

use std::sync::LazyLock;

use guard_contracts::python_strip;
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

/// The largest policy document Guard accepts (`MAX_POLICY_BYTES`).
const MAX_POLICY_BYTES: usize = 1_048_576;
const INVALID_ARGUMENTS: &str = "invalid_arguments";

static DIGEST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{64}$").expect("policy digest pattern"));
static IDEMPOTENCY_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._~-]{8,128}$").expect("idempotency key pattern"));
static REQUEST_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9]{16,64}$").expect("policy request id pattern"));

type Checked<T> = Result<T, (&'static str, String)>;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let arguments = args
        .get("arguments")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let checked = match args.get("tool").and_then(Value::as_str) {
        Some("validate_policy") => validate_policy(arguments),
        Some("create_policy") => create_policy(arguments),
        Some("get_policy_creation") => get_policy_creation(arguments),
        _ => return Err(ERR_INVALID),
    };
    Ok(match checked {
        Ok(value) => json!({ "value": value }),
        Err((code, message)) => json!({ "error": { "code": code, "message": message } }),
    })
}

fn invalid(message: impl Into<String>) -> (&'static str, String) {
    (INVALID_ARGUMENTS, message.into())
}

fn reject_unknown_keys(arguments: &Map<String, Value>, allowed: &[&str]) -> Checked<()> {
    let mut unknown: Vec<&str> = arguments
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    // Byte order is code point order for UTF-8, as Python's `sorted` uses.
    unknown.sort_unstable();
    let listed: Vec<String> = unknown
        .into_iter()
        .map(crate::claude_hook_bridge_render::py_repr_str)
        .collect();
    Err(invalid(format!(
        "Unknown arguments: [{}]",
        listed.join(", ")
    )))
}

fn policy_yaml(raw: Option<&Value>) -> Checked<()> {
    let Some(Value::String(text)) = raw else {
        return Err(invalid("policyYaml must be a string."));
    };
    if python_strip(text).is_empty() {
        return Err(invalid("policyYaml must not be empty."));
    }
    if text.len() > MAX_POLICY_BYTES {
        return Err((
            "policy_too_large",
            "policyYaml exceeds the maximum document size.".to_owned(),
        ));
    }
    Ok(())
}

fn mode(raw: Option<&Value>, required: bool) -> Checked<&'static str> {
    match raw {
        None | Some(Value::Null) if !required => Ok("merge"),
        Some(Value::String(text)) if text == "merge" => Ok("merge"),
        Some(Value::String(text)) if text == "replace" => Ok("replace"),
        _ => Err(invalid("mode must be 'merge' or 'replace'.")),
    }
}

fn matching<'a>(raw: Option<&'a Value>, pattern: &Regex, message: &str) -> Checked<&'a str> {
    raw.and_then(Value::as_str)
        .filter(|text| pattern.is_match(text))
        .ok_or_else(|| invalid(message))
}

fn digest<'a>(raw: Option<&'a Value>, field: &str) -> Checked<&'a str> {
    matching(
        raw,
        &DIGEST,
        &format!("{field} must be 64 lowercase hex characters."),
    )
}

fn validate_policy(arguments: &Map<String, Value>) -> Checked<Value> {
    reject_unknown_keys(arguments, &["policyYaml", "mode"])?;
    policy_yaml(arguments.get("policyYaml"))?;
    let mode = mode(arguments.get("mode"), false)?;
    Ok(json!({ "mode": mode }))
}

fn create_policy(arguments: &Map<String, Value>) -> Checked<Value> {
    reject_unknown_keys(
        arguments,
        &[
            "policyYaml",
            "mode",
            "candidateDigest",
            "expectedCurrentDigest",
            "idempotencyKey",
        ],
    )?;
    policy_yaml(arguments.get("policyYaml"))?;
    let mode = mode(arguments.get("mode"), true)?;
    let candidate_digest = digest(arguments.get("candidateDigest"), "candidateDigest")?;
    let expected_current_digest = match arguments.get("expectedCurrentDigest") {
        None | Some(Value::Null) => None,
        raw => Some(digest(raw, "expectedCurrentDigest")?),
    };
    let idempotency_key = matching(
        arguments.get("idempotencyKey"),
        &IDEMPOTENCY_KEY,
        "idempotencyKey must be 8-128 URL-safe characters [A-Za-z0-9._~-].",
    )?;
    Ok(json!({
        "mode": mode,
        "candidate_digest": candidate_digest,
        "expected_current_digest": expected_current_digest,
        "idempotency_key": idempotency_key,
    }))
}

fn get_policy_creation(arguments: &Map<String, Value>) -> Checked<Value> {
    reject_unknown_keys(arguments, &["requestId"])?;
    let request_id = matching(
        arguments.get("requestId"),
        &REQUEST_ID,
        "requestId must be 16-64 alphanumeric characters.",
    )?;
    Ok(json!({ "request_id": request_id }))
}

#[cfg(test)]
#[path = "mcp_policy_input_tests.rs"]
mod tests;
