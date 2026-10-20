//! Read-only containment receipts for harnesses that can route a contained
//! execution (`omp`, `zcode`). A receipt is rendered only for a fully
//! characterised Rust `sandbox-required` verdict; anything else falls back to
//! the ordinary deny rendering.

use serde_json::{json, Map, Value};

const GIT_RULES: [&str; 3] = ["command.git.diff", "command.git.log", "command.git.show"];
/// Bun inline evaluation reports package protection because Bun is a package
/// manager image; pretool admits that only for an exact, screened `bun -e/-p`
/// argv, under its own reason. `node -e` never carries the permission.
const PACKAGE_PERMISSION_CODES: [&str; 7] = [
    guard_contracts::NATIVE_BASH_DELIVERY_REASON,
    "native_workspace_containment_required",
    "native_bun_eval_readonly_containment_required",
    "native_vitest_readonly_containment_required",
    "native_package_test_readonly_containment_required",
    "native_node_tool_readonly_containment_required",
    "native_node_build_output_containment_required",
];

pub(super) fn required_profile(reason_code: &str) -> Option<&'static str> {
    Some(match reason_code {
        guard_contracts::NATIVE_BASH_DELIVERY_REASON => {
            guard_contracts::NATIVE_BASH_DELIVERY_PROFILE
        }
        "native_python_eval_readonly_containment_required" => "python-eval-readonly-v1",
        "native_node_eval_readonly_containment_required"
        | "native_bun_eval_readonly_containment_required" => "node-eval-readonly-v1",
        "native_package_test_readonly_containment_required" => "package-test-readonly-v1",
        "native_node_build_output_containment_required" => "node-build-output-v1",
        "native_node_tool_readonly_containment_required" => "node-tool-readonly-v1",
        "native_git_readonly_containment_required" => "git-readonly-v1",
        "native_vitest_readonly_containment_required" => "vitest-readonly-v1",
        "native_node_test_readonly_containment_required" => "node-test-readonly-v1",
        "native_pytest_readonly_containment_required" => "pytest-readonly-v2",
        "native_workspace_containment_required" => "workspace-contained-v1",
        _ => return None,
    })
}

fn is_empty_list(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(items)) if items.is_empty())
}

/// Whether the binding counts exactly `expected` uncertain matches.
fn binding_uncertainty(binding: Option<&Value>, expected: usize) -> bool {
    let Some(Value::Object(binding)) = binding else {
        return false;
    };
    matches!(binding.get("uncertainty_count"), Some(Value::Number(count))
        if count.as_u64() == u64::try_from(expected).ok())
}

/// The destructive-shell match on a plain `rm`, `rmdir` or `sed -i`. The rule
/// marks every match uncertain; the Rust classifier admitted it to the
/// workspace sandbox only after proving a removal cannot take uncommitted work.
fn workspace_removal(item: &Value) -> bool {
    matches!(item, Value::Object(item)
        if item.get("rule_id").and_then(Value::as_str)
            == Some("command.shell-mutations.destructive-shell")
            && item.get("uncertainty_reasons") == Some(&json!(["matcher-failure"])))
}

/// Uncertain matches a verdict may carry: workspace removals only.
fn accepted_uncertainty(reason_code: &str, observations: Option<&Value>) -> usize {
    match observations {
        Some(Value::Array(items)) if reason_code == "native_workspace_containment_required" => {
            items.iter().filter(|item| workspace_removal(item)).count()
        }
        _ => 0,
    }
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

/// A package firewall's own permission. It records which ecosystem's manager
/// ran, not a risk the run carries, and the classifier admitted the verb
/// below it; every ecosystem the firewall watches reads the same.
fn package_permission(item: &Value) -> bool {
    let Value::Object(item) = item else {
        return false;
    };
    let (Some(extension), Some(permission)) = (
        item.get("extension_id").and_then(Value::as_str),
        item.get("permission_id").and_then(Value::as_str),
    ) else {
        return false;
    };
    crate::pretool::PACKAGE_EXTENSIONS.contains(&extension)
        && permission
            .strip_prefix(extension)
            .is_some_and(|rest| rest == ".permission.package-protection")
        && is_empty_list(item.get("uncertainty_reasons"))
}

/// The workspace sandbox admits matched command rules; the classifier already
/// vetted their risk classes, and the binding digest pins them at launch.
fn certain_observation(item: &Value) -> bool {
    matches!(item, Value::Object(map) if is_empty_list(map.get("uncertainty_reasons")))
        || workspace_removal(item)
}

fn observations_ok(reason_code: &str, observations: Option<&Value>) -> bool {
    if is_empty_list(observations) {
        return true;
    }
    if matches!(
        reason_code,
        "native_workspace_containment_required" | guard_contracts::NATIVE_BASH_DELIVERY_REASON
    ) {
        return matches!(observations, Some(Value::Array(items)) if items.iter().all(certain_observation));
    }
    reason_code == "native_git_readonly_containment_required"
        && matches!(observations, Some(Value::Array(items)) if items.iter().all(git_observation))
}

fn permissions_ok(reason_code: &str, permissions: Option<&Value>) -> bool {
    if is_empty_list(permissions) {
        return true;
    }
    PACKAGE_PERMISSION_CODES.contains(&reason_code)
        && matches!(permissions, Some(Value::Array(items)) if items.iter().all(package_permission))
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
    if !matches!(canonical, "omp" | "pi" | "zcode" | "claude-code" | "codex")
        || text("minimum_action") != Some("sandbox-required")
        || text("policy_action") != Some("sandbox-required")
        || text("decision") != Some("deny")
        || text("authority") != Some("rust")
        || text("schema") != Some("guard-pre-tool-result.v1")
    {
        return None;
    }
    let profile = required_profile(reason_code)?;
    if reason_code == guard_contracts::NATIVE_BASH_DELIVERY_REASON
        && (!cfg!(target_os = "macos") || !matches!(canonical, "omp" | "pi"))
    {
        return None;
    }
    let Some(Value::Object(extensions)) = response.get("command_extensions") else {
        return None;
    };
    let observations = extensions.get("observations");
    let clean = binding_uncertainty(
        extensions.get("binding"),
        accepted_uncertainty(reason_code, observations),
    ) && matches!(extensions.get("evaluation_error"), None | Some(Value::Null))
        && observations_ok(reason_code, observations)
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
    if reason_code == "native_workspace_containment_required" {
        // Pins the matched extension evidence so the launcher can detect drift
        // between the first receipt and the one taken just before launch.
        let digest = extensions
            .get("binding")
            .and_then(|binding| binding.get("observations_digest"))
            .and_then(Value::as_str)?;
        receipt.insert("command_binding_digest".into(), json!(digest));
    }
    if matches!(canonical, "zcode" | "claude-code" | "codex") {
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
