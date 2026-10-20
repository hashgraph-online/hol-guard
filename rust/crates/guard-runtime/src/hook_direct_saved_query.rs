//! The exact-action query the daemon asks for a reviewed `PreToolUse`.
//!
//! This ports `native_exact_action` (`hook_native_exact_action.py`) for the
//! reviews whose token the daemon can bind: `native_review_policy_binding`
//! (`hook_native_review_binding.py`) on the edge's own receipt, the request
//! fields as `hook_request_parsing.py` reads them, and the environment and
//! extension-control digest the daemon published. Every other shape defers.

use super::super::workspace::python_strip;
use super::super::{HookDirectDefer, PRE_TOOL_USE};
use guard_command::hook_responses::Object;
use guard_contracts::{NativeExactActionQueryV1, NativePolicyBindingV1, NativeReviewFactsV1};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

// v2 drops `policy_digest`: it is `H(config_digest, rule_digest)` over the
// whole compiled snapshot, so it moves on every republish, including one that
// only recorded observed state. The retry's own anchor digest covers the
// configured policy, `rule_digest` and `runtime_identity` instead. The receipt
// is still required to carry a well-formed `policy_digest`.
const POLICY_BINDING_SCHEMA: &str = "guard.native-review-policy-binding.v2";
const EXACT_ACTION_BUDGET_MS: u64 = 4_000;
const TOOL_NAME_FIELDS: [&str; 3] = ["tool_name", "toolName", "tool"];
const TOOL_INPUT_FIELDS: [&str; 2] = ["tool_input", "toolInput"];
const COMMAND_FIELDS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];
/// The receipt fields `receipt_matches_edge` compares with the result.
const RECEIPT_RESULT_FIELDS: [&str; 5] = [
    "decision",
    "policy_action",
    "observed_policy_action",
    "reason_code",
    "reviewed_output_sha256",
];

/// The request facts outside the edge that the query carries.
pub(super) struct QueryInput<'a> {
    pub(super) harness: &'a str,
    pub(super) payload: &'a Map<String, Value>,
    pub(super) workspace: &'a str,
    pub(super) home_dir: &'a str,
    pub(super) environment: &'a BTreeMap<String, String>,
    pub(super) control_digest: &'a str,
}

/// The decision's artifact id and the daemon's exact-action query.
pub(super) fn exact_action(
    input: &QueryInput<'_>,
    result: &Object,
    receipt: Option<&Value>,
) -> Result<(String, NativeExactActionQueryV1), HookDirectDefer> {
    if !clean_path(input.workspace) || !clean_path(input.home_dir) {
        return Err(HookDirectDefer::SavedDecision);
    }
    let policy_binding = policy_binding(input.harness, result, receipt)?;
    let tool_name = tool_name(input.payload)?;
    let artifact_id = format!("{}:native-pretool:{tool_name}", input.harness);
    let query = NativeExactActionQueryV1::ExactAction {
        harness: input.harness.to_owned(),
        tool_name,
        command: pre_tool_command(input.payload)?,
        tool_input: tool_input_pairs(input.payload)?,
        raw_tool_input: raw_tool_input(input.payload)?,
        payload_cwd: payload_cwd(input.payload)?,
        workspace: Some(input.workspace.to_owned()),
        home_dir: Some(input.home_dir.to_owned()),
        environment: input.environment.clone(),
        facts: facts(result)?,
        policy_binding,
        extension_control_digest: input.control_digest.to_owned(),
        budget_ms: EXACT_ACTION_BUDGET_MS,
    };
    Ok((artifact_id, query))
}

/// Whether `str(Path(path))` is `path` for an absolute POSIX path, so the
/// daemon sends the same text.
fn clean_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    rest.split('/')
        .all(|component| !component.is_empty() && component != ".")
}

/// `native_review_policy_binding` for a receipt the in-process edge produced:
/// only a bound review has a persistent token, so anything else defers.
fn policy_binding(
    harness: &str,
    result: &Object,
    receipt: Option<&Value>,
) -> Result<NativePolicyBindingV1, HookDirectDefer> {
    let receipt = receipt
        .and_then(Value::as_object)
        .ok_or(HookDirectDefer::SavedDecision)?;
    if !result.contains_key("command_extensions") && !receipt.contains_key("command_extensions") {
        return Err(HookDirectDefer::SavedDecision);
    }
    if !receipt_matches_edge(harness, result, receipt) {
        return Err(HookDirectDefer::SavedDecision);
    }
    let text = |key: &str| receipt.get(key).filter(|value| value.is_string()).cloned();
    let (Some(_policy_digest), Some(rule_digest), Some(runtime_identity)) = (
        text("policy_digest"),
        text("rule_digest"),
        text("runtime_identity"),
    ) else {
        return Err(HookDirectDefer::SavedDecision);
    };
    let command_extensions = receipt
        .get("command_extensions")
        .and_then(Value::as_object)
        .filter(|binding| {
            binding
                .get("uncertainty_count")
                .is_some_and(|count| count.as_u64().is_some())
        })
        .ok_or(HookDirectDefer::SavedDecision)?;
    Ok(NativePolicyBindingV1::Bound {
        value: json!({
            "schema": POLICY_BINDING_SCHEMA,
            "rule_digest": rule_digest,
            "runtime_identity": runtime_identity,
            "command_extensions": command_extensions,
        }),
    })
}

/// The identity checks of `receipt_matches_edge` for a `PreToolUse`.
fn receipt_matches_edge(harness: &str, result: &Object, receipt: &Object) -> bool {
    let field = |fields: &Object, key: &str| fields.get(key).cloned().unwrap_or(Value::Null);
    if receipt.get("event_name").and_then(Value::as_str) != Some(PRE_TOOL_USE)
        || receipt.get("harness").and_then(Value::as_str) != Some(harness)
        || receipt.get("model_output_action").and_then(Value::as_str) != Some("not_applicable")
        || receipt.get("observe_mode")
            != Some(&Value::Bool(
                result.get("observe_mode") == Some(&Value::Bool(true)),
            ))
    {
        return false;
    }
    if RECEIPT_RESULT_FIELDS
        .iter()
        .any(|key| field(receipt, key) != field(result, key))
    {
        return false;
    }
    let extensions_match = match result.get("command_extensions") {
        None | Some(Value::Null) => !receipt.contains_key("command_extensions"),
        Some(evidence) => evidence
            .get("binding")
            .is_some_and(|binding| receipt.get("command_extensions") == Some(binding)),
    };
    extensions_match
        && field(result, "prompt_risk_classes").is_null()
        && !receipt.contains_key("prompt_risk_classes")
}

/// `_native_review_tool_name`.
pub(super) fn tool_name(payload: &Map<String, Value>) -> Result<String, HookDirectDefer> {
    for key in TOOL_NAME_FIELDS {
        if let Some(value) = payload.get(key).and_then(Value::as_str) {
            if let Some(stripped) = strip(value)? {
                return Ok(stripped.to_owned());
            }
        }
    }
    Ok("tool".to_owned())
}

pub(super) fn pre_tool_input(payload: &Map<String, Value>) -> Option<&Map<String, Value>> {
    TOOL_INPUT_FIELDS
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_object))
}

/// `pre_tool_command`: the first non-blank command text, unstripped.
pub(super) fn pre_tool_command(
    payload: &Map<String, Value>,
) -> Result<Option<String>, HookDirectDefer> {
    let arguments = payload.get("arguments").and_then(Value::as_object);
    for candidate in [pre_tool_input(payload), arguments, Some(payload)]
        .into_iter()
        .flatten()
    {
        for key in COMMAND_FIELDS {
            if let Some(value) = candidate.get(key).and_then(Value::as_str) {
                if strip(value)?.is_some() {
                    return Ok(Some(value.to_owned()));
                }
            }
        }
    }
    Ok(None)
}

/// `_tool_input_pairs`, deferring on a number the daemon's JSON round trip
/// could spell differently (Python reads `1e5` and `1.50` as floats and
/// writes them back as `100000.0` and `1.5`). The pairs come in key order,
/// not the payload's: the token sorts what it reads from them, so it does not
/// depend on the order.
fn tool_input_pairs(
    payload: &Map<String, Value>,
) -> Result<Option<Vec<(String, Value)>>, HookDirectDefer> {
    let Some(input) =
        pre_tool_input(payload).or_else(|| payload.get("arguments").and_then(Value::as_object))
    else {
        return Ok(None);
    };
    if !input.values().all(plain_numbers) {
        return Err(HookDirectDefer::SavedDecision);
    }
    Ok(Some(
        input
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    ))
}

/// `_raw_tool_input`: the first tool input the payload sent that is not an
/// object, when it sent no object, deferring on the same numbers as
/// [`tool_input_pairs`].
fn raw_tool_input(payload: &Map<String, Value>) -> Result<Option<Value>, HookDirectDefer> {
    if pre_tool_input(payload).is_some() || payload.get("arguments").is_some_and(Value::is_object) {
        return Ok(None);
    }
    let raw = TOOL_INPUT_FIELDS
        .iter()
        .chain(["arguments"].iter())
        .find_map(|key| payload.get(*key).filter(|value| !value.is_null()));
    match raw {
        Some(value) if !plain_numbers(value) => Err(HookDirectDefer::SavedDecision),
        raw => Ok(raw.cloned()),
    }
}

/// Whether every number in `value` is an integer in its canonical spelling.
fn plain_numbers(value: &Value) -> bool {
    match value {
        Value::Number(number) => {
            let text = number.to_string();
            number.as_i64().map(|integer| integer.to_string()) == Some(text.clone())
                || number.as_u64().map(|integer| integer.to_string()) == Some(text)
        }
        Value::Array(items) => items.iter().all(plain_numbers),
        Value::Object(fields) => fields.values().all(plain_numbers),
        _ => true,
    }
}

fn payload_cwd(payload: &Map<String, Value>) -> Result<Option<String>, HookDirectDefer> {
    match payload.get("cwd").and_then(Value::as_str) {
        Some(cwd) if strip(cwd)?.is_some() => Ok(Some(cwd.to_owned())),
        _ => Ok(None),
    }
}

/// `_facts`: `str(value or "")` for text, and only text, so any other value
/// the daemon would stringify defers.
fn facts(result: &Object) -> Result<NativeReviewFactsV1, HookDirectDefer> {
    let text = |key: &str| match result.get(key) {
        None | Some(Value::Null) => Ok(Some(String::new())),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(HookDirectDefer::SavedDecision),
    };
    let action_type = result
        .get("action")
        .and_then(Value::as_object)
        .and_then(|action| action.get("action_type"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(NativeReviewFactsV1 {
        decision: text("decision")?,
        minimum_action: text("minimum_action")?,
        policy_action: text("policy_action")?,
        reason_code: text("reason_code")?,
        action_type,
    })
}

/// Python's `str.strip`, deferring on the separators it treats as blank.
pub(super) fn strip(value: &str) -> Result<Option<&str>, HookDirectDefer> {
    python_strip(value).map_err(|_| HookDirectDefer::SavedDecision)
}

#[cfg(test)]
#[path = "hook_direct_saved_query_tests.rs"]
mod tests;
