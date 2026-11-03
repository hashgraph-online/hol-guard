//! `review_policy_memory_plan` runner-authority kind: the policy decisions a
//! signed Cloud Review decision-memory bundle leaves behind.
//!
//! `runtime/review_policy_memory_executor.py` verifies the bundle's signature
//! and target, builds the acknowledgement and writes the store. What it asks
//! here is which memory rules become local decisions and what the stored rule
//! registry and decision set look like afterwards.
//!
//! The request is `{"rules": ..., "revocations": ..., "workspace_id": ...,
//! "registry": ..., "policies": [...]}`: the bundle's `memoryRules`,
//! `revocations` and `workspaceId`, the stored rule registry payload, and the
//! stored `policy-bundle` decisions. It answers one of:
//!
//! - `{"rejected_rule_ids": [str, ...]}` when any rule names no harness,
//!   artifact, scope or canonical action, or allows at a scope wider than one
//!   workspace. Nothing is applied, so the registry is not read.
//! - `{"rejected_rule_ids": [], "applied_rule_count": int,
//!   "registry_rule_ids": [str, ...], "decisions": [...]}`: revocations drop
//!   their rules, every rule replaces or joins the registry in order, and the
//!   decisions are the kept `policy-bundle` decisions followed by one decision
//!   per registry rule, in `registry_rule_ids` order. The caller stores those
//!   trailing decisions as the registry, so each decision crosses back once.
//! - `{"error": "invalid_decision_memory_rule"}` when a rule is not an object
//!   or has no `ruleId`, or `{"error": "invalid_decision_memory_registry"}`
//!   when a stored registry decision is unusable.

use guard_command::attestation_timestamp::python_strip;
use guard_contracts::GuardAction;
use serde_json::{json, Map, Value};

use crate::cloud_request_text::py_truthy;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::KindResult;

const DECISION_SCOPE_VALUES: &[&str] = &["global", "harness", "workspace", "artifact", "publisher"];
const MEMORY_SOURCE: &str = "cloud-signed-memory";
const BUNDLE_SOURCE: &str = "policy-bundle";
const DEFAULT_REASON: &str = "Guard Cloud signed decision memory sync";
const INVALID_RULE: &str = "invalid_decision_memory_rule";
const INVALID_REGISTRY: &str = "invalid_decision_memory_registry";

type Registry = Vec<(String, Value)>;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    Ok(plan(args).unwrap_or_else(|code| json!({ "error": code })))
}

fn plan(args: &Map<String, Value>) -> Result<Value, &'static str> {
    let mut rejected: Vec<&str> = Vec::new();
    let mut validated: Vec<(&str, Value)> = Vec::new();
    for rule in list(args.get("rules")) {
        let rule = rule.as_object().ok_or(INVALID_RULE)?;
        let rule_id = text(rule.get("ruleId")).ok_or(INVALID_RULE)?;
        match rule_decision(rule, args.get("workspace_id")) {
            Some(decision) => validated.push((rule_id, decision)),
            None => rejected.push(rule_id),
        }
    }
    if !rejected.is_empty() {
        return Ok(json!({ "rejected_rule_ids": rejected }));
    }
    let mut registry = stored_registry(args.get("registry"));
    for revoked in list(args.get("revocations")) {
        if let Some(rule_id) = text(Some(revoked)) {
            registry.retain(|(id, _)| id != rule_id);
        }
    }
    let applied_rule_count = validated.len();
    for (rule_id, decision) in validated {
        upsert(&mut registry, rule_id, decision);
    }
    let mut decisions: Vec<Value> = list(args.get("policies"))
        .iter()
        .filter_map(bundle_policy)
        .collect();
    let mut registry_rule_ids = Vec::with_capacity(registry.len());
    for (rule_id, decision) in registry {
        decisions.push(registry_decision(&decision).ok_or(INVALID_REGISTRY)?);
        registry_rule_ids.push(rule_id);
    }
    Ok(json!({
        "rejected_rule_ids": [],
        "applied_rule_count": applied_rule_count,
        "registry_rule_ids": registry_rule_ids,
        "decisions": decisions,
    }))
}

fn list(value: Option<&Value>) -> &[Value] {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// Python's `value.strip() if isinstance(value, str) and value.strip()`.
fn text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(python_strip)
        .filter(|text| !text.is_empty())
}

fn guard_action(value: Option<&Value>) -> Option<&str> {
    text(value).filter(|action| GuardAction::from_canonical(action).is_some())
}

fn decision_scope(value: Option<&Value>) -> Option<&str> {
    text(value).filter(|scope| DECISION_SCOPE_VALUES.contains(scope))
}

/// The local decision one memory rule becomes, or `None` when the rule is
/// rejected.
fn rule_decision(rule: &Map<String, Value>, bundle_workspace: Option<&Value>) -> Option<Value> {
    let harness = text(rule.get("harnessId"))?;
    let artifact_id = text(rule.get("artifactId"))?;
    let action = guard_action(rule.get("action"))?;
    let scope = text(rule.get("scope"))?;
    if action == "allow" && !matches!(scope, "artifact" | "workspace") {
        return None;
    }
    let workspace_scope = matches!(
        scope,
        "workspace" | "team" | "policy" | "machine" | "project"
    );
    let workspace = if workspace_scope {
        rule.get("target")
            .and_then(|target| target.get("workspaceIds"))
            .and_then(Value::as_array)
            .and_then(|ids| ids.iter().find_map(|id| text(Some(id))))
            .or_else(|| text(bundle_workspace))
    } else {
        None
    };
    Some(json!({
        "harness": harness,
        "scope": if workspace_scope { "workspace" } else { "artifact" },
        "action": action,
        "artifact_id": artifact_id,
        "artifact_hash": text(rule.get("artifactHash")),
        "workspace": workspace,
        "publisher": null,
        "reason": text(rule.get("reason")).unwrap_or(DEFAULT_REASON),
        "owner": null,
        "source": MEMORY_SOURCE,
        "expires_at": text(rule.get("expiresAt")),
    }))
}

/// The stored registry in order. Entries without a rule id or an object
/// decision are skipped; a repeated rule id keeps its first place and its
/// last decision.
fn stored_registry(payload: Option<&Value>) -> Registry {
    let mut registry = Registry::new();
    for item in list(payload) {
        let decision = item.get("decision").filter(|value| value.is_object());
        if let (Some(rule_id), Some(decision)) = (text(item.get("ruleId")), decision) {
            upsert(&mut registry, rule_id, decision.clone());
        }
    }
    registry
}

fn upsert(registry: &mut Registry, rule_id: &str, decision: Value) {
    match registry.iter_mut().find(|(id, _)| id == rule_id) {
        Some(slot) => slot.1 = decision,
        None => registry.push((rule_id.to_owned(), decision)),
    }
}

/// A stored `policy-bundle` decision, kept only when its harness, scope and
/// action are usable.
fn bundle_policy(item: &Value) -> Option<Value> {
    if item.get("source").and_then(Value::as_str) != Some(BUNDLE_SOURCE) {
        return None;
    }
    policy(item, BUNDLE_SOURCE.to_owned())
}

fn registry_decision(decision: &Value) -> Option<Value> {
    // A missing or falsy source is the memory source; any other non-string
    // source is not one this kind wrote.
    let source = match decision.get("source") {
        Some(Value::String(source)) if !source.is_empty() => source.clone(),
        Some(value) if py_truthy(value) => return None,
        _ => MEMORY_SOURCE.to_owned(),
    };
    policy(decision, source)
}

fn policy(item: &Value, source: String) -> Option<Value> {
    let field = |key: &str| text(item.get(key));
    Some(json!({
        "harness": field("harness")?,
        "scope": decision_scope(item.get("scope"))?,
        "action": guard_action(item.get("action"))?,
        "artifact_id": field("artifact_id"),
        "artifact_hash": field("artifact_hash"),
        "workspace": field("workspace"),
        "publisher": field("publisher"),
        "reason": field("reason"),
        "owner": field("owner"),
        "source": source,
        "expires_at": field("expires_at"),
    }))
}

#[cfg(test)]
#[path = "review_policy_memory_plan_tests.rs"]
mod tests;
