//! Read-only containment receipts for harnesses that can route a contained
//! execution (`omp`, `zcode`). A receipt is rendered only for a fully
//! characterised Rust `sandbox-required` verdict; anything else falls back to
//! the ordinary deny rendering.

use serde_json::{json, Map, Value};

const GIT_RULES: [&str; 3] = ["command.git.diff", "command.git.log", "command.git.show"];
const NODE_PERMISSION_CODES: [&str; 4] = [
    "native_vitest_readonly_containment_required",
    "native_package_test_readonly_containment_required",
    "native_node_tool_readonly_containment_required",
    "native_node_build_output_containment_required",
];

fn required_profile(reason_code: &str) -> Option<&'static str> {
    Some(match reason_code {
        "native_python_eval_readonly_containment_required" => "python-eval-readonly-v1",
        "native_node_eval_readonly_containment_required" => "node-eval-readonly-v1",
        "native_package_test_readonly_containment_required" => "package-test-readonly-v1",
        "native_node_build_output_containment_required" => "node-build-output-v1",
        "native_node_tool_readonly_containment_required" => "node-tool-readonly-v1",
        "native_git_readonly_containment_required" => "git-readonly-v1",
        "native_vitest_readonly_containment_required" => "vitest-readonly-v1",
        "native_node_test_readonly_containment_required" => "node-test-readonly-v1",
        "native_pytest_readonly_containment_required" => "pytest-readonly-v2",
        _ => return None,
    })
}

fn is_empty_list(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(items)) if items.is_empty())
}

fn zero_uncertainty(binding: Option<&Value>) -> bool {
    let Some(Value::Object(binding)) = binding else {
        return false;
    };
    matches!(binding.get("uncertainty_count"), Some(Value::Number(count))
        if (count.is_i64() || count.is_u64()) && count.as_i64() == Some(0))
}

fn git_observation(item: &Value) -> bool {
    let Value::Object(item) = item else {
        return false;
    };
    item.get("rule_id")
        .and_then(Value::as_str)
        .is_some_and(|rule| GIT_RULES.contains(&rule))
        && is_empty_list(item.get("uncertainty_reasons"))
        && item.get("effective_segment_indexes") == Some(&json!([0]))
}

fn node_permission(item: &Value) -> bool {
    let Value::Object(item) = item else {
        return false;
    };
    item.get("extension_id").and_then(Value::as_str) == Some("command.package.node")
        && item.get("permission_id").and_then(Value::as_str)
            == Some("command.package.node.permission.package-protection")
        && is_empty_list(item.get("uncertainty_reasons"))
}

fn observations_ok(reason_code: &str, observations: Option<&Value>) -> bool {
    if is_empty_list(observations) {
        return true;
    }
    reason_code == "native_git_readonly_containment_required"
        && matches!(observations, Some(Value::Array(items)) if items.iter().all(git_observation))
}

fn permissions_ok(reason_code: &str, permissions: Option<&Value>) -> bool {
    if is_empty_list(permissions) {
        return true;
    }
    NODE_PERMISSION_CODES.contains(&reason_code)
        && matches!(permissions, Some(Value::Array(items)) if items.iter().all(node_permission))
}

/// Containment receipt for `response`, or `None` when the verdict is not a
/// fully characterised read-only containment requirement.
pub(super) fn receipt(
    canonical: &str,
    response: &Map<String, Value>,
    reason: &str,
    reason_code: &str,
) -> Option<Map<String, Value>> {
    let text = |key: &str| response.get(key).and_then(Value::as_str);
    if !matches!(canonical, "omp" | "zcode")
        || text("minimum_action") != Some("sandbox-required")
        || text("policy_action") != Some("sandbox-required")
        || text("decision") != Some("deny")
        || text("authority") != Some("rust")
        || text("schema") != Some("guard-pre-tool-result.v1")
    {
        return None;
    }
    let profile = required_profile(reason_code)?;
    let Some(Value::Object(extensions)) = response.get("command_extensions") else {
        return None;
    };
    let clean = zero_uncertainty(extensions.get("binding"))
        && matches!(extensions.get("evaluation_error"), None | Some(Value::Null))
        && observations_ok(reason_code, extensions.get("observations"))
        && permissions_ok(reason_code, extensions.get("permission_observations"));
    if !clean {
        return None;
    }
    // This is not permission to execute the original input. New adapters may
    // route it to the protected sink; old adapters still see deny.
    let mut receipt = Map::new();
    receipt.insert("decision".into(), json!("deny"));
    receipt.insert("policy_action".into(), json!("sandbox-required"));
    receipt.insert("reason_code".into(), json!(reason_code));
    receipt.insert("reason".into(), json!(reason));
    receipt.insert("required_execution_profile".into(), json!(profile));
    if canonical == "zcode" {
        receipt.insert(
            "hookSpecificOutput".into(),
            json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }),
        );
    }
    Some(receipt)
}
