//! `HookArtifactFacts` - resident op deriving the per-artifact facts the
//! native configured-policy action reads.
//!
//! Faithful port of `commands_support_runtime_artifact_policy
//! .runtime_policy_artifact_facts` and the artifact readers it calls in
//! `commands_support_runtime_policy` and `commands_support_prompts`.
//!
//! Every one of these facts decided part of a verdict the resident then
//! applied: whether a prompt asks to bypass Guard, which risk classes the
//! artifact carries, whether its evidence is strong, whether it installs a
//! boot item. A caller that derived them could weaken a stop without the
//! resident seeing a different artifact, so the resident now reads the
//! metadata itself and the caller ships the artifact as it stands.
//!
//! `configured_override` stays with the caller: it is the artifact, publisher
//! or harness setting the config resolves, not a reading of the artifact, and
//! it rides through this op so the facts leave here complete.

use guard_command::command_action_risk_classes::risk_classes_for_command_action;
use guard_contracts::{
    normalize_guard_action_result, GuardAction, HookArtifactFactsRequestV1,
    HookArtifactFactsResultV1, HookArtifactV1, PolicyArtifactFactsV1,
    HOOK_ARTIFACT_FACTS_MAX_ARTIFACTS, HOOK_ARTIFACT_FACTS_MAX_BYTES,
    HOOK_ARTIFACT_FACTS_REQUEST_SCHEMA, HOOK_ARTIFACT_FACTS_RESULT_SCHEMA,
};
use serde_json::{Map, Value};

use crate::context_digest::{is_python_space, python_strip};
use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_hook_artifact_facts_request(
    request: &HookArtifactFactsRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, HOOK_ARTIFACT_FACTS_MAX_BYTES)
        .map_err(|_| "native_hook_artifact_facts_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate_request(request))),
    };
    crate::encode_response(&HookArtifactFactsResultV1 {
        schema: HOOK_ARTIFACT_FACTS_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &HookArtifactFactsRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != HOOK_ARTIFACT_FACTS_REQUEST_SCHEMA {
        return Some("native_hook_artifact_facts_schema_mismatch");
    }
    if request.artifacts.len() > HOOK_ARTIFACT_FACTS_MAX_ARTIFACTS {
        return Some("native_hook_artifact_facts_too_many_artifacts");
    }
    None
}

/// One facts object per requested artifact, in the request's order.
pub(crate) fn evaluate_request(request: &HookArtifactFactsRequestV1) -> Value {
    let facts: Vec<Value> = request.artifacts.iter().map(evaluate).collect();
    serde_json::json!({ "facts": facts })
}

pub(crate) fn evaluate(artifact: &HookArtifactV1) -> Value {
    let empty = Map::new();
    let metadata = artifact.metadata.as_object().unwrap_or(&empty);
    let facts = PolicyArtifactFactsV1 {
        hard_block: prompt_requires_hard_block(metadata),
        configured_override: artifact.configured_override.clone(),
        command_action_floor: command_action_floor(metadata),
        explicit_permission_allow: explicit_permission_allow(metadata),
        risk_classes: risk_classes(&artifact.artifact_type, metadata),
        pytest_restricted_sandbox: pytest_restricted_sandbox(metadata),
        shell_local_script_review: metadata.get("reason_code").and_then(Value::as_str)
            == Some("shell_local_script_execution_review"),
        guard_default_action: typed_text(metadata.get("guard_default_action")),
        confidence_text: risk_confidence(metadata),
        writes_launch_agent: metadata.get("persistence_writes_launch_agent")
            == Some(&Value::Bool(true)),
        action_class: metadata
            .get("action_class")
            .and_then(Value::as_str)
            .map(str::to_owned),
        skill_is_known_bad: skill_is_known_bad(metadata),
    };
    serde_json::to_value(facts).unwrap_or(Value::Null)
}

/// `_typed_text`: a present non-string setting normalizes to the unknown
/// action, which is what an empty string does downstream.
fn typed_text(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => Some(String::new()),
    }
}

/// `commands_support_prompts._prompt_requires_hard_block`.
fn prompt_requires_hard_block(metadata: &Map<String, Value>) -> bool {
    if let Some(classes) = metadata
        .get("prompt_request_classes")
        .and_then(Value::as_array)
    {
        // A list is authoritative even when it holds non-strings: the Python
        // reader stringified every entry before looking for the class.
        return classes
            .iter()
            .any(|item| stringify(item) == "guard_bypass_intent");
    }
    metadata.get("prompt_request_class").and_then(Value::as_str) == Some("guard_bypass_intent")
}

/// `commands_support_prompts._prompt_request_classes`.
fn prompt_request_classes(metadata: &Map<String, Value>) -> Vec<String> {
    let values: Vec<&Value> = match metadata.get("prompt_request_classes") {
        Some(Value::Array(items)) => items.iter().collect(),
        _ => metadata.get("prompt_request_class").into_iter().collect(),
    };
    values
        .into_iter()
        .filter_map(|item| item.as_str())
        .filter(|item| !python_strip(item).is_empty())
        .map(str::to_owned)
        .collect()
}

/// `str(item)` over a JSON value, for the one reader that stringifies.
fn stringify(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// `_runtime_artifact_command_action_floor`.
fn command_action_floor(metadata: &Map<String, Value>) -> Option<String> {
    let value = metadata.get("command_action_floor")?;
    Some(
        normalize_guard_action_result(value, GuardAction::Block)
            .action
            .as_str()
            .to_owned(),
    )
}

/// `_runtime_artifact_has_explicit_permission_allow`.
fn explicit_permission_allow(metadata: &Map<String, Value>) -> bool {
    if command_action_floor(metadata).as_deref() != Some("allow") {
        return false;
    }
    let Some(resolution) = metadata
        .get("extension_control_resolution")
        .and_then(Value::as_object)
    else {
        return false;
    };
    if resolution.get("blocked") != Some(&Value::Bool(false)) {
        return false;
    }
    let Some(permission_ids) = resolution
        .get("explicitly_enabled_permission_ids")
        .and_then(Value::as_array)
    else {
        return false;
    };
    if permission_ids.is_empty()
        || !permission_ids.iter().all(|item| {
            item.as_str()
                .is_some_and(|text| text.starts_with("command."))
        })
    {
        return false;
    }
    let Some(decision) = metadata
        .get("command_decision_plane")
        .and_then(Value::as_object)
    else {
        return false;
    };
    if decision.get("action").and_then(Value::as_str) != Some("allow") {
        return false;
    }
    let verified = decision
        .get("proof_routes")
        .and_then(Value::as_array)
        .is_some_and(|routes| {
            routes
                .iter()
                .any(|route| route.as_str() == Some("verified"))
        });
    let controlled = decision
        .get("controlling_reasons")
        .and_then(Value::as_array)
        .is_some_and(|reasons| {
            reasons.iter().any(|reason| {
                reason.as_object().is_some_and(|reason| {
                    reason.get("source").and_then(Value::as_str) == Some("control")
                        && reason.get("reason_code").and_then(Value::as_str)
                            == Some("control.explicitly-enabled-permission")
                })
            })
        });
    verified && controlled
}

/// `_runtime_artifact_risk_classes`.
fn risk_classes(artifact_type: &str, metadata: &Map<String, Value>) -> Vec<String> {
    let mut classes: Vec<String> = Vec::new();
    if let Some(composite) = metadata.get("risk_classes").and_then(Value::as_array) {
        classes.extend(
            composite
                .iter()
                .filter_map(|item| item.as_str())
                .map(python_strip)
                .filter(|item| !item.is_empty())
                .map(str::to_owned),
        );
    }
    match artifact_type {
        "file_read_request" => classes.push("local_secret_read".to_owned()),
        "package_request" => classes.push("package_script".to_owned()),
        "prompt_request" => {
            let prompt_classes = prompt_request_classes(metadata);
            let has = |name: &str| prompt_classes.iter().any(|item| item == name);
            if has("secret_read") {
                classes.push("local_secret_read".to_owned());
            }
            if has("exfil_intent") {
                classes.push("credential_exfiltration".to_owned());
            }
            if has("destructive_intent")
                || has("subprocess_intent")
                || has("prompt_injection_intent")
            {
                classes.push("destructive_shell".to_owned());
            }
        }
        "tool_action_request" => {
            if let Some(action_class) = metadata.get("action_class").and_then(Value::as_str) {
                classes.extend(
                    risk_classes_for_command_action(action_class)
                        .iter()
                        .map(|item| (*item).to_owned()),
                );
            }
        }
        _ => {}
    }
    let mut seen: Vec<String> = Vec::with_capacity(classes.len());
    for class in classes {
        if !seen.contains(&class) {
            seen.push(class);
        }
    }
    seen
}

/// The `pytest_restricted_sandbox` fact.
fn pytest_restricted_sandbox(metadata: &Map<String, Value>) -> bool {
    metadata.get("action_class").and_then(Value::as_str) == Some("pytest repository-code execution")
        && metadata.get("reason_code").and_then(Value::as_str)
            == Some("pytest_restricted_profile_required")
        && metadata
            .get("restricted_profile_version")
            .is_some_and(Value::is_string)
}

/// `_artifact_risk_confidence`, rendered the way `str(confidence or "")` was.
fn risk_confidence(metadata: &Map<String, Value>) -> String {
    let direct = match metadata.get("risk_confidence") {
        None | Some(Value::Null) => metadata.get("confidence"),
        found => found,
    };
    if let Some(text) = direct.and_then(Value::as_str) {
        if !text.trim_matches(is_python_space).is_empty() {
            return text.to_owned();
        }
    }
    if let Some(signals) = metadata.get("risk_signals").and_then(Value::as_array) {
        for signal in signals {
            if let Some(text) = signal
                .as_object()
                .and_then(|signal| signal.get("confidence"))
                .and_then(Value::as_str)
            {
                if !text.trim_matches(is_python_space).is_empty() {
                    return text.to_owned();
                }
            }
        }
    }
    direct.map(python_str_or_empty).unwrap_or_default()
}

/// `str(value or "")` for a confidence that is not a non-empty string.
///
/// Only scalars reach this in practice; a list or mapping renders as JSON
/// rather than as Python's `repr`, which nothing downstream compares.
fn python_str_or_empty(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(false) => String::new(),
        Value::Bool(true) => "True".to_owned(),
        Value::String(text) => text.clone(),
        Value::Number(number) if number.as_f64() == Some(0.0) => String::new(),
        Value::Array(items) if items.is_empty() => String::new(),
        Value::Object(fields) if fields.is_empty() => String::new(),
        other => other.to_string(),
    }
}

/// `_artifact_skill_is_known_bad`.
fn skill_is_known_bad(metadata: &Map<String, Value>) -> bool {
    if metadata.get("known_bad_skill") == Some(&Value::Bool(true))
        || metadata.get("skill_is_known_bad") == Some(&Value::Bool(true))
    {
        return true;
    }
    metadata
        .get("threat_intel")
        .and_then(Value::as_object)
        .is_some_and(|intel| intel.get("known_bad") == Some(&Value::Bool(true)))
}

#[cfg(test)]
#[path = "hook_artifact_facts_op_tests.rs"]
mod tests;
