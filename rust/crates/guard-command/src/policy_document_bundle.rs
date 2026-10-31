//! Device scoping for a canonical managed policy bundle before compilation.
//!
//! A bundle names the devices each rule applies to. Deciding that in the
//! transport would let a client silently drop an administrator's rule for this
//! device, so the selector match, the rule shape and the Extension-target skip
//! are all decided here and the surviving rules are compiled in one pass.

use std::collections::BTreeSet;
use std::time::Instant;

use serde_json::{Map, Value};

use super::{compiler, failure, mapping, text, Error};

#[cfg(test)]
#[path = "policy_document_bundle_tests.rs"]
mod tests;

fn refused(code: &str) -> Error {
    failure(
        "PolicyCompilationError",
        &format!("{code}: policy-bundle"),
        Some((code, "policy-bundle")),
    )
}

/// The rule as it should be compiled locally, or nothing when this device is
/// outside its scope or another authority already owns it.
fn selected(rule: &Map<String, Value>, device_id: &str, device_name: &str) -> Option<Value> {
    // Extension-targeted rules are compiled by the Managed Controls authority
    // path. Materializing them again as generic policy rows can reject valid
    // Extension outcomes (for example `review`) or apply a second,
    // semantically different enforcement decision.
    if rule.contains_key("x-hol-extension-targets") {
        return None;
    }
    let Some(Value::Object(matcher)) = rule.get("match") else {
        return Some(Value::Object(rule.clone()));
    };
    let Some(Value::Array(devices)) = matcher.get("devices") else {
        return Some(Value::Object(rule.clone()));
    };
    if devices.is_empty() {
        return Some(Value::Object(rule.clone()));
    }
    let selectors: BTreeSet<String> = devices.iter().map(text).collect();
    if !selectors.contains(device_id) && !selectors.contains(device_name) {
        return None;
    }
    // The selector has been honoured, so the remaining rule carries no device
    // list into compilation.
    let mut matcher = matcher.clone();
    matcher.remove("devices");
    let mut rule = rule.clone();
    rule.insert("match".to_owned(), Value::Object(matcher));
    Some(Value::Object(rule))
}

fn device(input: &Value, key: &str) -> Result<String, Error> {
    input[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| failure("TypeError", "policy_bundle_device_identity", None))
}

/// Compile the rules of a canonical bundle that apply to one named device.
pub(super) fn compile(input: &Value, deadline: Instant) -> Result<Value, Error> {
    let device_id = device(input, "device_id")?;
    let device_name = device(input, "device_name")?;
    let Some(payload) = input["bundle"]["payload"].as_object() else {
        return Err(refused("missing_policy_bundle_payload"));
    };
    let Some(Value::Object(spec)) = payload.get("spec") else {
        return Err(refused("invalid_policy_spec"));
    };
    let Some(Value::Array(rules)) = spec.get("rules") else {
        return Err(refused("invalid_policy_rules"));
    };
    // An Evaluate policy rolls out its rules to watch them, not to enforce
    // them, so the device keeps its own decisions until the policy is enforced.
    let evaluating = spec
        .get("defaults")
        .and_then(|defaults| defaults.get("mode"))
        .and_then(Value::as_str)
        == Some("observe");
    let local: Vec<Value> = rules
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|rule| selected(rule, &device_id, &device_name))
        .collect();
    let mut spec = spec.clone();
    spec.insert("rules".to_owned(), Value::Array(local));
    let mut document = payload.clone();
    document.insert("spec".to_owned(), Value::Object(spec));
    let rows = compiler::compile(
        &mapping::parse("GuardPolicyDocument", &Value::Object(document))?.mapping,
        deadline,
    )?;
    Ok(if evaluating {
        Value::Array(Vec::new())
    } else {
        rows
    })
}
