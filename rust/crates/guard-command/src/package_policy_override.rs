//! Pure stored-policy-override evaluation core ported from
//! `src/codex_plugin_scanner/guard/local_supply_chain.py`.
//!
//! Ported functions (Python line anchors):
//! - `_package_evaluation_with_current_policy_action` (:2609)
//! - `_package_evaluation_with_rejected_reuse` (:2672)
//! - `_approval_reuse_reason_message` (:2709)
//! - `_package_decision_for_action` (:2745)
//! - `_stored_package_policy_evaluation_requires_review` (:2807)
//! - `_saved_package_policy_clear_command` (:2813)
//! - `_evaluation_uses_saved_package_approval` (:3209)
//! - `_package_approval_reuse_evidence` (:3214)
//! - `_package_policy_override_evaluation` (:3224)
//!
//! All inputs are JSON evaluation dicts (`&Value` / `&Map`) mirroring the
//! Python `PackageRequestEvaluation` dataclass: every ported function performs a
//! `dataclasses.replace`-style dict copy, so we deep-copy the map and rewrite
//! only the fields each Python site assigns. `_saved_package_policy_clear_command`
//! takes `&GuardArtifact` (the evaluation-module dataclass already exists in
//! `package_intent_common`); `GuardAction` is `crate::effect_decision::GuardAction`.

use serde_json::{json, Map, Value};

use crate::approval_reuse::ApprovalReuseDecision;
use crate::command_launcher_floors::shlex_join;
use crate::effect_decision::GuardAction;
use crate::local_supply_chain::PackageEvalApi;
use crate::package_intent_common::GuardArtifact;

/// `_package_decision_for_action` (:2745).
pub fn package_decision_for_action(action: GuardAction) -> &'static str {
    if action == GuardAction::Block {
        return "block";
    }
    if matches!(
        action,
        GuardAction::Review | GuardAction::RequireReapproval | GuardAction::SandboxRequired
    ) {
        return "ask";
    }
    if action == GuardAction::Warn {
        return "warn";
    }
    "allow"
}

/// `_stored_package_policy_evaluation_requires_review` (:2807).
///
/// Python `_string_value` returns the string for `str` values, `None` otherwise.
pub fn stored_package_policy_evaluation_requires_review(evaluation: &Value) -> bool {
    let policy_action = string_value(evaluation.get("policy_action"));
    let decision = string_value(evaluation.get("decision"));
    matches!(policy_action, Some("block" | "require-reapproval"))
        || matches!(decision, Some("block" | "ask"))
}

/// `_evaluation_uses_saved_package_approval` (:3209).
pub fn evaluation_uses_saved_package_approval(evaluation: &Value) -> bool {
    evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .is_some_and(|reasons| {
            reasons.iter().any(|reason| {
                reason.get("code").and_then(Value::as_str) == Some("saved_package_approval")
            })
        })
}

/// `_approval_reuse_reason_message` (:2709).
pub fn approval_reuse_reason_message(reuse: &ApprovalReuseDecision) -> String {
    let message = match reuse.reason_code.as_str() {
        "approval_reuse_current_block" => {
            "Saved approval was rejected because current package policy blocks this request."
        }
        "approval_reuse_sandbox_required" => {
            "Saved approval was rejected because current package policy requires sandbox enforcement."
        }
        "approval_reuse_reapproval_required" => {
            "Saved approval was rejected because current package policy requires fresh approval."
        }
        "approval_reuse_integrity_failure" => {
            "Saved approval was rejected because its integrity could not be verified."
        }
        "approval_reuse_identity_changed" => {
            "Saved approval was rejected because the current package identity or scope changed."
        }
        "approval_reuse_content_changed" => {
            "Saved approval was rejected because the current package content or execution context changed."
        }
        "approval_reuse_claim_failed" => {
            "Saved approval was rejected because it changed, expired, or was already consumed."
        }
        "approval_reuse_context_changed_after_claim" => {
            "Saved approval was rejected because retained authority changed after it was claimed."
        }
        "approval_reuse_saved_action_unknown" => {
            "Saved approval was rejected because its action is unknown or malformed."
        }
        _ => {
            return format!(
                "Saved package policy was not reused ({}).",
                reuse.reason_code
            );
        }
    };
    message.to_string()
}

/// `_saved_package_policy_clear_command` (:2813).
///
/// `workspace_dir` is passed as a string matching `str(Path(...))` — callers
/// supply the already-stringified path so this stays pure (no `Path` join).
pub fn saved_package_policy_clear_command(
    artifact: &GuardArtifact,
    _artifact_hash: &str,
    matched_policy: &Map<String, Value>,
    workspace_dir: &str,
) -> String {
    let scope = string_value(matched_policy.get("scope")).unwrap_or("artifact");
    let mut command: Vec<String> = vec![
        "hol-guard".to_string(),
        "policies".to_string(),
        "clear".to_string(),
    ];
    let decision_id = matched_policy.get("decision_id");
    if matches!(decision_id, Some(Value::Number(n)) if n.is_i64() || n.is_u64()) {
        // Python `isinstance(decision_id, int)` accepts bools as ints; serde_json
        // never produces a bool here, so numeric-only is exact.
        if let Some(Value::Number(n)) = decision_id {
            command.push("--decision-id".to_string());
            command.push(n.to_string());
        }
    }
    command.push("--harness".to_string());
    command.push(
        string_value(matched_policy.get("harness"))
            .unwrap_or(artifact.harness.as_str())
            .to_string(),
    );
    command.push("--scope".to_string());
    command.push(scope.to_string());
    let mut artifact_id = string_value(matched_policy.get("artifact_id")).map(str::to_string);
    if artifact_id.is_none() && matches!(scope, "artifact" | "workspace" | "harness" | "global") {
        artifact_id = Some(artifact.artifact_id.clone());
    }
    if let Some(id) = artifact_id {
        command.push("--artifact-id".to_string());
        command.push(id);
    }
    if let Some(matched_hash) = string_value(matched_policy.get("artifact_hash")) {
        command.push("--artifact-hash".to_string());
        command.push(matched_hash.to_string());
    }
    let mut policy_workspace = string_value(matched_policy.get("workspace")).map(str::to_string);
    if policy_workspace.is_none() && matches!(scope, "artifact" | "workspace") {
        policy_workspace = Some(workspace_dir.to_string());
    }
    if let Some(workspace) = policy_workspace {
        command.push("--policy-workspace".to_string());
        command.push(workspace);
    }
    if let Some(publisher) = string_value(matched_policy.get("publisher")) {
        command.push("--publisher".to_string());
        command.push(publisher.to_string());
    }
    shlex_join(&command)
}

/// `_package_approval_reuse_evidence` (:3214).
pub fn package_approval_reuse_evidence(evaluation: &Value) -> Vec<Map<String, Value>> {
    let mut evidence_items = Vec::new();
    if let Some(reasons) = evaluation.get("reasons").and_then(Value::as_array) {
        for reason in reasons {
            let Some(reuse_evidence) = reason.get("approval_reuse") else {
                continue;
            };
            let Some(reuse_map) = reuse_evidence.as_object() else {
                continue;
            };
            let mut evidence = Map::new();
            evidence.insert(
                "source".to_string(),
                Value::String("approval_reuse".to_string()),
            );
            for (key, value) in reuse_map {
                evidence.insert(key.clone(), value.clone());
            }
            evidence_items.push(evidence);
        }
    }
    evidence_items
}

/// `_package_evaluation_with_current_policy_action` (:2609).
///
/// `eval` is the `PackageEvalApi` view of the evaluation; `map` is the raw dict.
/// `eval.supply_chain_user_copy(..)` yields the 5-key `user_copy` Value.
pub fn package_evaluation_with_current_policy_action(
    eval: &dyn PackageEvalApi,
    map: &Map<String, Value>,
    current_action: GuardAction,
) -> Map<String, Value> {
    if map.get("policy_action").and_then(Value::as_str) == Some(current_action.as_str()) {
        return map.clone();
    }
    let decision = package_decision_for_action(current_action);
    let rewritten_packages = rewritten_package_decisions(map, decision);
    let action_label = match current_action {
        GuardAction::Block => "blocks",
        GuardAction::SandboxRequired => "requires sandbox enforcement for",
        GuardAction::RequireReapproval => "requires fresh approval for",
        GuardAction::Review => "requires review for",
        GuardAction::Warn => "warns about",
        GuardAction::Allow => "allows",
    };
    let package_label = package_label(map);
    let summary = format!("HOL Guard's current package policy {action_label} {package_label}.");
    let severity = if matches!(
        current_action,
        GuardAction::Block | GuardAction::SandboxRequired
    ) {
        "high"
    } else {
        "medium"
    };
    let reason = json!({
        "code": "current_package_policy",
        "message": summary,
        "severity": severity,
        "source": "guard-local",
        "policy_action": current_action.as_str(),
    });
    let needs_review = matches!(
        current_action,
        GuardAction::Review
            | GuardAction::RequireReapproval
            | GuardAction::SandboxRequired
            | GuardAction::Block
    );
    let next_step = if needs_review {
        Some("Review the current package request in HOL Guard, then retry.".to_string())
    } else {
        None
    };
    let user_copy = Value::Object(eval.supply_chain_user_copy(
        "Current package policy",
        &summary,
        next_step.as_deref(),
        None,
        Some(&summary),
    ));
    let reasons = prepend_reason(map, reason, "current_package_policy");
    let mut out = map.clone();
    out.insert("decision".to_string(), Value::String(decision.to_string()));
    out.insert(
        "policy_action".to_string(),
        Value::String(current_action.as_str().to_string()),
    );
    out.insert("reasons".to_string(), Value::Array(reasons));
    out.insert("packages".to_string(), Value::Array(rewritten_packages));
    out.insert("risk_summary".to_string(), Value::String(summary.clone()));
    out.insert("user_copy".to_string(), user_copy);
    out.insert("record_monitor_evidence".to_string(), Value::Bool(false));
    out
}

/// `_package_evaluation_with_rejected_reuse` (:2672).
pub fn package_evaluation_with_rejected_reuse(
    eval: &dyn PackageEvalApi,
    map: &Map<String, Value>,
    reuse: &ApprovalReuseDecision,
) -> Map<String, Value> {
    let message = approval_reuse_reason_message(reuse);
    let severity = if reuse.status == "rejected" {
        "high"
    } else {
        "low"
    };
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(reuse.reason_code.clone()));
    reason.insert("message".to_string(), Value::String(message.clone()));
    reason.insert("severity".to_string(), Value::String(severity.to_string()));
    reason.insert(
        "source".to_string(),
        Value::String("guard-local".to_string()),
    );
    reason.insert(
        "approval_reuse".to_string(),
        serde_json::to_value(reuse).unwrap_or(Value::Null),
    );
    let reasons = prepend_reason(map, Value::Object(reason), &reuse.reason_code);
    if map.get("policy_action").and_then(Value::as_str) == Some(reuse.action.as_str()) {
        let mut out = map.clone();
        out.insert("reasons".to_string(), Value::Array(reasons));
        return out;
    }
    let decision = package_decision_for_action(reuse.action);
    let packages = rewritten_package_decisions(map, decision);
    let summary = message.clone();
    let user_copy = Value::Object(eval.supply_chain_user_copy(
        "Saved approval not reusable",
        &summary,
        Some("Review the current package request in HOL Guard, then retry."),
        None,
        Some(&summary),
    ));
    let mut out = map.clone();
    out.insert("decision".to_string(), Value::String(decision.to_string()));
    out.insert(
        "policy_action".to_string(),
        Value::String(reuse.action.as_str().to_string()),
    );
    out.insert("reasons".to_string(), Value::Array(reasons));
    out.insert("packages".to_string(), Value::Array(packages));
    out.insert("risk_summary".to_string(), Value::String(summary));
    out.insert("user_copy".to_string(), user_copy);
    out.insert("record_monitor_evidence".to_string(), Value::Bool(false));
    out
}

/// `_package_policy_override_evaluation` (:3224).
#[allow(clippy::too_many_arguments)]
pub fn package_policy_override_evaluation(
    eval: &dyn PackageEvalApi,
    map: &Map<String, Value>,
    decision: &str,
    policy_action: &str,
    title: &str,
    summary: &str,
    harness_message: &str,
    next_step: Option<&str>,
    reason_code: &str,
    reason_message: &str,
    approval_reuse: Option<&ApprovalReuseDecision>,
    approval_claim_disposition: Option<&str>,
) -> Map<String, Value> {
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(reason_code.to_string()));
    reason.insert(
        "message".to_string(),
        Value::String(reason_message.to_string()),
    );
    reason.insert("severity".to_string(), Value::String("low".to_string()));
    reason.insert(
        "source".to_string(),
        Value::String("guard-local".to_string()),
    );
    if let Some(reuse) = approval_reuse {
        reason.insert(
            "approval_reuse".to_string(),
            serde_json::to_value(reuse).unwrap_or(Value::Null),
        );
    }
    if let Some(disposition) = approval_claim_disposition {
        reason.insert(
            "approval_claim_disposition".to_string(),
            Value::String(disposition.to_string()),
        );
    }
    let packages = rewritten_package_decisions(map, decision);
    let reasons = prepend_reason_unless_equal(map, Value::Object(reason));
    let user_copy = Value::Object(eval.supply_chain_user_copy(
        title,
        summary,
        next_step,
        None,
        Some(harness_message),
    ));
    let mut out = map.clone();
    out.insert("decision".to_string(), Value::String(decision.to_string()));
    out.insert(
        "policy_action".to_string(),
        Value::String(policy_action.to_string()),
    );
    out.insert("reasons".to_string(), Value::Array(reasons));
    out.insert("packages".to_string(), Value::Array(packages));
    out.insert(
        "risk_summary".to_string(),
        Value::String(harness_message.to_string()),
    );
    out.insert("user_copy".to_string(), user_copy);
    out.insert("record_monitor_evidence".to_string(), Value::Bool(false));
    out
}

// ---- private helpers ----

/// Python `_string_value`: returns the `str` value, else `None`.
fn string_value(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
}

/// Rebuild `packages` with every entry's `decision` set (Python
/// `{**package, "decision": decision}` — dicts only; non-dict entries pass
/// through unchanged since Python would raise, matching `dataclasses.replace`
/// on the dataclass where `packages` is a tuple of dicts).
fn rewritten_package_decisions(map: &Map<String, Value>, decision: &str) -> Vec<Value> {
    map.get("packages")
        .and_then(Value::as_array)
        .map(|packages| {
            packages
                .iter()
                .map(|package| {
                    if let Some(pkg) = package.as_object() {
                        let mut pkg = pkg.clone();
                        pkg.insert("decision".to_string(), Value::String(decision.to_string()));
                        Value::Object(pkg)
                    } else {
                        package.clone()
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `package_label` for `_package_evaluation_with_current_policy_action`:
/// uses the first `packages` entry's `name`@`requestedVersion`|`resolvedVersion`,
/// falling back to `"this package request"`.
fn package_label(map: &Map<String, Value>) -> String {
    let default_label = "this package request".to_string();
    let Some(packages) = map.get("packages").and_then(Value::as_array) else {
        return default_label;
    };
    let Some(first) = packages.first() else {
        return default_label;
    };
    let Some(primary) = first.as_object() else {
        return default_label;
    };
    let Some(name) = primary.get("name").and_then(Value::as_str) else {
        return default_label;
    };
    if name.is_empty() {
        return default_label;
    }
    let raw = primary
        .get("requestedVersion")
        .filter(|v| python_truthy(v))
        .or_else(|| primary.get("resolvedVersion"));
    let version = raw.and_then(Value::as_str);
    match version {
        Some(v) if !v.is_empty() => format!("`{name}@{v}`"),
        _ => format!("`{name}`"),
    }
}

/// Python truthiness for a JSON value (`x or y` selection).
fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(items) => !items.is_empty(),
    }
}

/// Build the replacement `reasons` array: prepend `reason`, then keep every
/// existing reason whose `code` differs from `code_to_drop`.
/// Mirrors `(reason, *tuple(item for item in evaluation.reasons if item.get("code") != reason["code"]))`.
fn prepend_reason(map: &Map<String, Value>, reason: Value, code_to_drop: &str) -> Vec<Value> {
    let mut out = Vec::with_capacity(1);
    out.push(reason);
    if let Some(reasons) = map.get("reasons").and_then(Value::as_array) {
        for item in reasons {
            let item_code = item.get("code").and_then(Value::as_str);
            if item_code != Some(code_to_drop) {
                out.push(item.clone());
            }
        }
    }
    out
}

/// `_package_policy_override_evaluation` keeps every existing reason that is
/// not *equal* to the new one (`item != reason`), unlike the code-keyed
/// filter used by the current-policy and rejected-reuse rewrites.
fn prepend_reason_unless_equal(map: &Map<String, Value>, reason: Value) -> Vec<Value> {
    let mut out = vec![reason.clone()];
    if let Some(reasons) = map.get("reasons").and_then(Value::as_array) {
        out.extend(reasons.iter().filter(|item| **item != reason).cloned());
    }
    out
}

#[cfg(test)]
#[path = "package_policy_override_tests.rs"]
mod tests;
