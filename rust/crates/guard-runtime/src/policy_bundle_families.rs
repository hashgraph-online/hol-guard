//! Which policy-bundle rules can be saved as family decisions without
//! broadening their scope (`policy_bundle_rule_saved_decision_families`).

use std::collections::BTreeSet;

use serde_json::Value;

use crate::policy_bundle_py::{has_constraint, non_empty, obj, py_strip, Obj};
use crate::policy_bundle_v1_rules::{BROWSER_SCOPE_KEYS, MATCHER_FAMILIES};

const FAMILY_SCOPE_KEYS: [&str; 5] = [
    "agents",
    "devices",
    "environments",
    "harnesses",
    "locations",
];
const NON_SELECTOR_RULE_KEYS: [&str; 16] = [
    "action",
    "artifactId",
    "artifactType",
    "artifact_id",
    "auditEventIds",
    "expiresAt",
    "matcher",
    "matcherFamilies",
    "reason",
    "ruleId",
    "scope",
    "sourceDecisionId",
    "sourceLocalRequestId",
    "sourceReceiptId",
    "sourceReceiptIds",
    "sourceSuggestionId",
];

pub(crate) fn artifact_type_family(artifact_type: &str) -> Option<&'static str> {
    match artifact_type {
        "file_read_request" => Some("file-read"),
        "package_request" => Some("package-request"),
        "prompt_request" => Some("prompt"),
        "tool_action_request" => Some("tool-action"),
        _ => None,
    }
}

fn dedupe(items: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    items.filter(|item| seen.insert(item.clone())).collect()
}

fn matcher_families(rule: &Obj) -> Vec<String> {
    if let Some(explicit) = rule.get("matcherFamilies") {
        let Value::Array(items) = explicit else {
            return Vec::new();
        };
        let mut valid = Vec::new();
        for item in items {
            match item {
                Value::String(name)
                    if !py_strip(name).is_empty() && MATCHER_FAMILIES.contains(&name.as_str()) =>
                {
                    valid.push(name.clone());
                }
                _ => return Vec::new(),
            }
        }
        return dedupe(valid.into_iter());
    }
    let mut derived: Vec<&str> = Vec::new();
    if let Some(scope) = obj(rule.get("scope")) {
        if matches!(scope.get("ecosystems"), Some(Value::Array(items)) if !items.is_empty()) {
            derived.push("package-request");
        }
        if non_empty(scope.get("mcp")).is_some() || non_empty(scope.get("tool")).is_some() {
            derived.push("mcp");
        }
        if non_empty(scope.get("command")).is_some() {
            derived.push("tool-action");
        }
        if non_empty(scope.get("path")).is_some() || non_empty(scope.get("secretType")).is_some() {
            derived.push("file-read");
        }
    }
    if let Some(family) = non_empty(rule.get("artifactType")).and_then(artifact_type_family) {
        derived.push(family);
    }
    dedupe(derived.into_iter().map(str::to_owned))
}

/// `_rule_scope_is_exactly_representable`.
pub(crate) fn scope_is_representable(rule: &Obj, identity_keys: &[&str]) -> bool {
    let Some(scope) = obj(rule.get("scope")) else {
        return false;
    };
    scope.iter().all(|(key, value)| {
        if identity_keys.contains(&key.as_str()) {
            return non_empty(Some(value)).is_some();
        }
        if !FAMILY_SCOPE_KEYS.contains(&key.as_str()) {
            return !has_constraint(value);
        }
        matches!(value, Value::Array(items) if items.iter().all(|item| non_empty(Some(item)).is_some()))
    })
}

/// `_rule_has_unknown_constraints`.
pub(crate) fn has_unknown_constraints(rule: &Obj) -> bool {
    rule.iter().any(|(key, value)| {
        !NON_SELECTOR_RULE_KEYS.contains(&key.as_str())
            && !BROWSER_SCOPE_KEYS.contains(&key.as_str())
            && has_constraint(value)
    })
}

fn metadata_is_representable(rule: &Obj) -> bool {
    if has_unknown_constraints(rule) {
        return false;
    }
    match rule.get("matcher") {
        None | Some(Value::Null) => {}
        Some(Value::Object(matcher)) => {
            if matcher.values().any(has_constraint) {
                return false;
            }
        }
        Some(_) => return false,
    }
    non_empty(rule.get("artifactType")).is_none_or(|kind| artifact_type_family(kind).is_some())
}

/// `_policy_bundle_rule_declared_commands`; `None` when an alias is malformed.
pub(crate) fn declared_commands(rule: &Obj) -> Option<Vec<String>> {
    let mut commands = Vec::new();
    for source in [rule.get("matcher"), rule.get("scope")] {
        let Some(source) = obj(source) else { continue };
        let Some(value) = source.get("command") else {
            continue;
        };
        match value {
            Value::String(text) if !py_strip(text).is_empty() => commands.push(text.clone()),
            _ => return None,
        }
    }
    Some(dedupe(commands.into_iter()))
}

/// `_policy_bundle_rule_declared_artifact_ids`.
pub(crate) fn declared_artifact_ids(rule: &Obj) -> Option<Vec<String>> {
    let mut ids = Vec::new();
    let mut take = |source: &Obj| -> bool {
        for key in ["artifactId", "artifact_id"] {
            let Some(value) = source.get(key) else {
                continue;
            };
            match non_empty(Some(value)) {
                Some(text) => ids.push(text.to_owned()),
                None => return false,
            }
        }
        true
    };
    if let Some(matcher) = obj(rule.get("matcher")) {
        if !take(matcher) {
            return None;
        }
    }
    if !take(rule) {
        return None;
    }
    Some(dedupe(ids.into_iter()))
}

/// `policy_bundle_rule_saved_decision_families`.
pub(crate) fn saved_families(rule: &Obj) -> Vec<String> {
    let mut families = matcher_families(rule);
    if families.is_empty() {
        return families;
    }
    let (Some(commands), Some(ids)) = (declared_commands(rule), declared_artifact_ids(rule)) else {
        return Vec::new();
    };
    if !commands.is_empty()
        || !ids.is_empty()
        || !scope_is_representable(rule, &[])
        || !metadata_is_representable(rule)
    {
        return Vec::new();
    }
    let artifact_type = non_empty(rule.get("artifactType"));
    if let Some(kind) = artifact_type {
        let keep = artifact_type_family(kind);
        families.retain(|family| Some(family.as_str()) == keep);
    }
    if artifact_type != Some("package_request") {
        families.retain(|family| family != "package-request");
    }
    families
}
