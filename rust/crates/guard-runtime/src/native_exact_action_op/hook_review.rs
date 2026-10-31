//! `HookReview` — the ReviewBinding and ExactAction queries of one reviewed
//! `PreToolUse`, derived from the hook request itself.
//!
//! The daemon used to read the hook payload, the native verdict and its
//! receipt into both queries, checking the receipt's policy binding with a
//! separate resident ask for each. The resident reads them here instead and
//! checks the receipt once; each half is then answered exactly as its own
//! query would be.

use crate::daemon_lifecycle_text::py_strip;
use crate::hook_adapter_op::review_request::{pre_tool_command, pre_tool_input, tool_name};
use guard_contracts::{NativeExactActionQueryV1, NativePolicyBindingV1, NativeReviewFactsV1};
use serde_json::{json, Map, Value};

const INVALID: &str = "native_exact_action_query_invalid";
const PRE_TOOL_USE: &str = "PreToolUse";
/// The hook's stamp of the agent's own `PATH`, `HOME` and variable names.
const EXECUTION_ENVIRONMENT_KEY: &str = "guard_execution_environment";
/// v2 drops `policy_digest`: it is `H(config_digest, rule_digest)` over the
/// whole compiled snapshot, so it moves on every republish, including one
/// that only recorded observed state. The retry's own anchor covers the
/// configured policy, `rule_digest` and `runtime_identity` instead. The
/// receipt is still required to carry a well-formed `policy_digest`.
const POLICY_BINDING_SCHEMA: &str = "guard.native-review-policy-binding.v2";

/// The two queries of one review and whether its policy binding held.
pub(super) struct HookReview {
    pub(super) policy_binding_valid: bool,
    pub(super) binding: NativeExactActionQueryV1,
    pub(super) action: NativeExactActionQueryV1,
}

pub(super) fn derive(query: &NativeExactActionQueryV1) -> Result<HookReview, &'static str> {
    let NativeExactActionQueryV1::HookReview {
        harness,
        payload,
        result,
        receipt,
        workspace,
        home_dir,
        environment,
        extension_control_digest,
        budget_ms,
    } = query
    else {
        return Err(INVALID);
    };
    let facts = facts(result)?;
    let policy_binding = policy_binding(harness, result, receipt.as_ref());
    let command = pre_tool_command(payload);
    let cwd = payload_cwd(payload);
    let binding = NativeExactActionQueryV1::ReviewBinding {
        harness: harness.clone(),
        command: command.clone(),
        cwd: cwd.clone(),
        workspace_bound: workspace.is_some(),
        facts: facts.clone(),
        receipt: receipt.clone().map(Value::Object),
        policy_binding: policy_binding.clone(),
        workspace: workspace.clone(),
        execution_environment: payload
            .get(EXECUTION_ENVIRONMENT_KEY)
            .filter(|stamped| stamped.is_object())
            .cloned(),
    };
    let action = NativeExactActionQueryV1::ExactAction {
        harness: harness.clone(),
        tool_name: tool_name(payload),
        command,
        tool_input: tool_input_pairs(payload),
        raw_tool_input: raw_tool_input(payload),
        payload_cwd: cwd,
        workspace: workspace.clone(),
        home_dir: home_dir.clone(),
        environment: environment.clone(),
        facts,
        policy_binding: policy_binding.clone(),
        extension_control_digest: extension_control_digest.clone(),
        budget_ms: *budget_ms,
    };
    Ok(HookReview {
        policy_binding_valid: policy_binding != NativePolicyBindingV1::Invalid,
        binding,
        action,
    })
}

/// Whether the receipt's policy binding holds for a `HookReview` query,
/// including one `derive` rejects.
pub(super) fn policy_binding_valid(query: &NativeExactActionQueryV1) -> bool {
    let NativeExactActionQueryV1::HookReview {
        harness,
        result,
        receipt,
        ..
    } = query
    else {
        return false;
    };
    policy_binding(harness, result, receipt.as_ref()) != NativePolicyBindingV1::Invalid
}

/// Whether a queued review's receipt holds the policy binding its verdict
/// claims, as a `HookReview` query checks it.
pub(crate) fn policy_binding_holds(
    harness: &str,
    result: &Map<String, Value>,
    receipt: Option<&Map<String, Value>>,
) -> bool {
    policy_binding(harness, result, receipt) != NativePolicyBindingV1::Invalid
}

/// A verdict that claims no extension policy, on either the verdict or its
/// receipt, binds none. One that does binds only through a receipt that
/// records this very `PreToolUse` result and carries a well-formed command
/// binding; anything partial or inconsistent is invalid, never unbound.
fn policy_binding(
    harness: &str,
    result: &Map<String, Value>,
    receipt: Option<&Map<String, Value>>,
) -> NativePolicyBindingV1 {
    let receipt_bound = receipt.is_some_and(|receipt| receipt.contains_key("command_extensions"));
    if !result.contains_key("command_extensions") && !receipt_bound {
        return NativePolicyBindingV1::Unbound;
    }
    let Some(receipt) = receipt else {
        return NativePolicyBindingV1::Invalid;
    };
    let mut edge = Map::new();
    edge.insert("harness".to_owned(), json!(harness));
    edge.insert("event_name".to_owned(), json!(PRE_TOOL_USE));
    if let Some(kind) = receipt.get("payload_kind").filter(|kind| !kind.is_null()) {
        edge.insert("payload_kind".to_owned(), kind.clone());
    }
    edge.insert("result".to_owned(), Value::Object(result.clone()));
    if !crate::edge::standalone_receipt(&Value::Object(receipt.clone()), &Value::Object(edge)) {
        return NativePolicyBindingV1::Invalid;
    }
    let text = |key: &str| receipt.get(key).filter(|value| value.is_string());
    let (Some(_policy_digest), Some(rule_digest), Some(runtime_identity)) = (
        text("policy_digest"),
        text("rule_digest"),
        text("runtime_identity"),
    ) else {
        return NativePolicyBindingV1::Invalid;
    };
    let Some(command_extensions) = receipt
        .get("command_extensions")
        .and_then(Value::as_object)
        .filter(|binding| {
            binding
                .get("uncertainty_count")
                .is_some_and(|count| count.as_u64().is_some())
        })
    else {
        return NativePolicyBindingV1::Invalid;
    };
    NativePolicyBindingV1::Bound {
        value: json!({
            "schema": POLICY_BINDING_SCHEMA,
            "rule_digest": rule_digest,
            "runtime_identity": runtime_identity,
            "command_extensions": command_extensions,
        }),
    }
}

/// The verdict's text facts: an absent or empty value is `""`. A verdict
/// spells each as text, so any other value is a malformed request.
fn facts(result: &Map<String, Value>) -> Result<NativeReviewFactsV1, &'static str> {
    let text = |key: &str| match result.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(value) if !falsy(value) => Err(INVALID),
        _ => Ok(Some(String::new())),
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

/// Python's falsiness for a decoded JSON value.
fn falsy(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(fields) => fields.is_empty(),
    }
}

/// The tool input object, else the `arguments` object, as key/value pairs.
/// The token sorts what it reads from them, so their order does not matter.
fn tool_input_pairs(payload: &Map<String, Value>) -> Option<Vec<(String, Value)>> {
    let input =
        pre_tool_input(payload).or_else(|| payload.get("arguments").and_then(Value::as_object))?;
    Some(
        input
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

/// The first tool input the payload sent that is not an object, when it
/// sent no object, so that input still binds the command hash.
fn raw_tool_input(payload: &Map<String, Value>) -> Option<Value> {
    if pre_tool_input(payload).is_some() || payload.get("arguments").is_some_and(Value::is_object) {
        return None;
    }
    ["tool_input", "toolInput", "arguments"]
        .iter()
        .find_map(|key| payload.get(*key).filter(|value| !value.is_null()))
        .cloned()
}

/// The payload's own `cwd`, when it is non-blank text.
fn payload_cwd(payload: &Map<String, Value>) -> Option<String> {
    payload
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|cwd| !py_strip(cwd).is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "hook_review_tests.rs"]
mod tests;
