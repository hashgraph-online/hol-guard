//! Settle the daemon hook's package review from the native plan, evaluator
//! verdict and saved-policy result. The host forwards evidence when asked.

use guard_command::hook_responses::{pre_tool, Object};
use serde_json::{json, Value};

use crate::local_mcp_grant_identity::shlex_split;
use crate::package_review_plan_op::{settles, PACKAGE_REVIEW_REASON};

const REGISTRY_RETRY_REASON: &str =
    "HOL Guard is still fetching registry metadata for this install. Run the same command again.";

pub(crate) fn registry_retry(harness: &str) -> Value {
    blocked(
        harness,
        &Object::from_iter([("reason_code".to_owned(), json!(PACKAGE_REVIEW_REASON))]),
        REGISTRY_RETRY_REASON,
    )
}

pub(crate) fn answer(harness: &str, inputs: &Object) -> Object {
    let Some(verdict) = inputs
        .get("verdict")
        .and_then(Value::as_object)
        .filter(|v| settles(v))
    else {
        return document(None, None, None);
    };
    let settlement = inputs.get("settlement").unwrap_or(&Value::Null);
    let action = text(settlement, "action");
    let reason = text(settlement, "reason").filter(|text| !text.is_empty());
    if let (Some("block"), Some(reason)) = (action, reason) {
        return document(Some(blocked(harness, verdict, reason)), None, None);
    }

    let package = inputs.get("package").unwrap_or(&Value::Null);
    let package_review =
        verdict.get("reason_code").and_then(Value::as_str) == Some(PACKAGE_REVIEW_REASON);
    let keyed = package_review && inputs.get("keyed") == Some(&Value::Bool(true));
    let mut key = None;
    if keyed {
        if let Some(reuse) = inputs.get("reuse") {
            key = text(reuse, "artifact_hash").and_then(|hash| package_key(package, Some(hash)));
            if key.is_some()
                && reuse.get("found") == Some(&Value::Bool(true))
                && text(reuse, "policy_action") == Some("allow")
            {
                return document(Some(allowed(harness, verdict)), None, None);
            }
        } else if let Some(lookup) = approval_inputs(package, inputs.get("execution_environment")) {
            return document(None, None, Some(lookup));
        }
    }
    let response = if package_review && inputs.get("may_allow") == Some(&Value::Bool(true)) {
        match (action, reason) {
            (Some("allow"), _) => Some(allowed(harness, verdict)),
            (Some("guide"), Some(reason)) => Some(blocked(harness, verdict, reason)),
            _ => None,
        }
    } else {
        None
    };
    document(response, key, None)
}

fn document(response: Option<Value>, key: Option<Value>, lookup: Option<Value>) -> Object {
    Object::from_iter([
        ("response".to_owned(), response.unwrap_or(Value::Null)),
        ("package_approval".to_owned(), key.unwrap_or(Value::Null)),
        ("lookup".to_owned(), lookup.unwrap_or(Value::Null)),
    ])
}

fn text<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value.get(name).and_then(Value::as_str)
}

fn approval_inputs(package: &Value, stamp: Option<&Value>) -> Option<Value> {
    let argv = shlex_split(text(package, "command")?)?;
    if argv.is_empty() {
        return None;
    }
    let mut environment = Object::new();
    if let Some(stamp) = stamp {
        for (name, field) in [("PATH", "path"), ("HOME", "home")] {
            if let Some(value) = text(stamp, field).filter(|value| !value.is_empty()) {
                environment.insert(name.to_owned(), json!(value));
            }
        }
    }
    Some(json!({
        "argv": argv,
        "environment": environment,
        "approval_key": package_key(package, None)?,
    }))
}

fn package_key(package: &Value, artifact_hash: Option<&str>) -> Option<Value> {
    let mut key = json!({
        "harness": text(package, "harness")?,
        "artifact_id": text(package, "artifact_id")?,
    });
    if let Some(hash) = artifact_hash {
        key["artifact_hash"] = json!(hash);
    }
    Some(key)
}

fn allowed(harness: &str, verdict: &Object) -> Value {
    let mut verdict = verdict.clone();
    for field in ["decision", "minimum_action", "policy_action"] {
        verdict.insert(field.to_owned(), json!("allow"));
    }
    Value::Object(pre_tool(harness, &verdict))
}

fn blocked(harness: &str, verdict: &Object, reason: &str) -> Value {
    let mut verdict = verdict.clone();
    verdict.insert("decision".to_owned(), json!("deny"));
    verdict.insert("minimum_action".to_owned(), json!("block"));
    verdict.insert("policy_action".to_owned(), json!("block"));
    verdict.insert("reason".to_owned(), json!(reason));
    let mut response = pre_tool(harness, &verdict);
    response.insert("prompted".to_owned(), Value::Bool(false));
    Value::Object(response)
}

#[cfg(test)]
#[path = "hook_package_review_settlement_tests.rs"]
mod tests;
