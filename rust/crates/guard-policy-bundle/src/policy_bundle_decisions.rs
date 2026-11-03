//! Canonical materialization of signed policy-bundle rules into persisted
//! decisions (`build_policy_bundle_decisions`).

use std::collections::BTreeSet;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::policy_bundle_families::{
    declared_artifact_ids, declared_commands, has_unknown_constraints, saved_families,
    scope_is_representable,
};
use crate::policy_bundle_py::{has_constraint, in_set, non_empty, obj, py_eq, py_strip, Obj};
use crate::policy_bundle_v1_rules::{BROWSER_SCOPE_KEYS, RULE_ACTIONS};

fn exact_shell_artifact_id(command: &str) -> Option<String> {
    if py_strip(command).is_empty() {
        return None;
    }
    Some(format!(
        "memory:exact-shell-command:{}",
        hex::encode(Sha256::digest(command.as_bytes()))
    ))
}

fn usable(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(text)) if !py_strip(text).is_empty() => Some(text.as_str()),
        _ => None,
    }
}

fn exact_command(rule: &Obj) -> Option<&str> {
    if let Some(command) =
        obj(rule.get("matcher")).and_then(|matcher| usable(matcher.get("command")))
    {
        return Some(command);
    }
    obj(rule.get("scope")).and_then(|scope| usable(scope.get("command")))
}

fn matches_local_scope(rule: &Obj, device_id: &str, device_name: &str) -> bool {
    let Some(scope) = obj(rule.get("scope")) else {
        return false;
    };
    if let Some(Value::Array(devices)) = scope.get("devices") {
        let named = |wanted: &str| devices.iter().any(|item| item.as_str() == Some(wanted));
        if !devices.is_empty() && !named(device_id) && !named(device_name) {
            return false;
        }
    }
    match scope.get("environments") {
        Some(Value::Array(items)) if !items.is_empty() => items
            .iter()
            .any(|item| item.as_str() == Some("development")),
        _ => true,
    }
}

fn locations(rule: &Obj) -> Vec<String> {
    let Some(Value::Array(items)) = obj(rule.get("scope")).and_then(|scope| scope.get("locations"))
    else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .map(py_strip)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn has_browser_scope(rule: &Obj) -> bool {
    let sources = [Some(rule), obj(rule.get("scope"))];
    sources.into_iter().flatten().any(|source| {
        BROWSER_SCOPE_KEYS.iter().any(|key| {
            source
                .get(*key)
                .is_some_and(|value| !py_eq(value, &Value::Array(Vec::new())))
        })
    })
}

fn harnesses(rule: &Obj) -> Vec<String> {
    let Some(scope) = obj(rule.get("scope")) else {
        return vec!["*".to_owned()];
    };
    let mut selector_sets: Vec<BTreeSet<String>> = Vec::new();
    for key in ["harnesses", "agents"] {
        let Some(Value::Array(items)) = scope.get(key) else {
            continue;
        };
        if items.is_empty() {
            continue;
        }
        let normalized: BTreeSet<String> = items
            .iter()
            .filter_map(Value::as_str)
            .map(py_strip)
            .filter(|item| !item.is_empty())
            .map(str::to_lowercase)
            .collect();
        if normalized.contains("custom") {
            return Vec::new();
        }
        selector_sets.push(normalized);
    }
    let Some(first) = selector_sets.first() else {
        return vec!["*".to_owned()];
    };
    first
        .iter()
        .filter(|item| selector_sets.iter().all(|set| set.contains(*item)))
        .cloned()
        .collect()
}

fn exact_rule_is_representable(rule: &Obj) -> bool {
    let Some(commands) = declared_commands(rule) else {
        return false;
    };
    if commands.len() > 1 {
        return false;
    }
    let exact = commands.first();
    let Some(ids) = declared_artifact_ids(rule) else {
        return false;
    };
    if exact.is_none() && ids.len() != 1 {
        return false;
    }
    let identity: &[&str] = if exact.is_some() { &["command"] } else { &[] };
    if !scope_is_representable(rule, identity) || has_unknown_constraints(rule) {
        return false;
    }
    let matcher = match rule.get("matcher") {
        None | Some(Value::Null) => return true,
        Some(Value::Object(matcher)) => matcher,
        Some(_) => return false,
    };
    let identity_keys: &[&str] = if exact.is_some() {
        &["command", "tool"]
    } else {
        &["artifactId", "artifact_id"]
    };
    matcher.iter().all(|(key, value)| {
        if !identity_keys.contains(&key.as_str()) && has_constraint(value) {
            return false;
        }
        key != "tool" || matches!(non_empty(Some(value)), Some("bash" | "shell"))
    })
}

fn exact_artifact_ids(rule: &Obj) -> Vec<String> {
    if let Some(id) = exact_command(rule).and_then(exact_shell_artifact_id) {
        return vec![id];
    }
    declared_artifact_ids(rule).unwrap_or_default()
}

fn reason(rule: &Obj, rule_id: &str) -> String {
    let base = non_empty(rule.get("reason"))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Matched Guard Cloud rule {rule_id}."));
    let diagnostics: Vec<String> = ["sourceDecisionId", "sourceSuggestionId"]
        .iter()
        .filter_map(|key| non_empty(rule.get(*key)).map(|value| format!("{key}={value}")))
        .collect();
    if diagnostics.is_empty() {
        base
    } else {
        format!("{base} ({})", diagnostics.join("; "))
    }
}

struct Row<'a> {
    harness: &'a str,
    scope: &'a str,
    action: &'a str,
    artifact_id: String,
    workspace: Option<&'a str>,
    reason: &'a str,
    owner: &'a str,
    expires_at: &'a Option<String>,
}

fn seed<'a>(
    harness: &'a str,
    action: &'a str,
    reason: &'a str,
    owner: &'a str,
    expires_at: &'a Option<String>,
    artifact_id: String,
) -> Row<'a> {
    Row {
        harness,
        scope: "",
        action,
        artifact_id,
        workspace: None,
        reason,
        owner,
        expires_at,
    }
}

fn row(item: &Row) -> Value {
    json!({
        "harness": item.harness, "scope": item.scope, "action": item.action,
        "artifact_id": item.artifact_id, "workspace": item.workspace, "reason": item.reason,
        "owner": item.owner, "source": "policy-bundle", "expires_at": item.expires_at,
    })
}

fn emit(out: &mut Vec<Value>, base: &Row, places: &[String], broad_scope: &str) {
    if places.is_empty() {
        out.push(row(&Row {
            scope: broad_scope,
            workspace: None,
            artifact_id: base.artifact_id.clone(),
            ..*base
        }));
        return;
    }
    for place in places {
        out.push(row(&Row {
            scope: "workspace",
            workspace: Some(place),
            artifact_id: base.artifact_id.clone(),
            ..*base
        }));
    }
}

/// `build_policy_bundle_decisions`: persisted-decision field maps.
pub(crate) fn build(bundle: &Obj, device_id: &str, device_name: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(Value::Array(rules)) = bundle.get("rules") else {
        return out;
    };
    for rule in rules.iter().filter_map(Value::as_object) {
        if !matches_local_scope(rule, device_id, device_name) || has_browser_scope(rule) {
            continue;
        }
        let Some(action) = rule.get("action").and_then(Value::as_str).filter(|name| {
            *name != "ignore" && in_set(Some(&Value::String((*name).to_owned())), &RULE_ACTIONS)
        }) else {
            continue;
        };
        let rule_id = non_empty(rule.get("ruleId")).unwrap_or("bundle-rule");
        let reason = reason(rule, rule_id);
        let places = locations(rule);
        let expires_at = non_empty(rule.get("expiresAt"))
            .or_else(|| non_empty(bundle.get("expiresAt")))
            .map(str::to_owned);
        let exact_ids = exact_artifact_ids(rule);
        let hosts = harnesses(rule);
        if !exact_ids.is_empty() && exact_rule_is_representable(rule) {
            for harness in &hosts {
                for id in &exact_ids {
                    let start = seed(harness, action, &reason, rule_id, &expires_at, id.clone());
                    emit(&mut out, &start, &places, "artifact");
                }
            }
        }
        for harness in &hosts {
            for family in saved_families(rule) {
                let start = seed(
                    harness,
                    action,
                    &reason,
                    rule_id,
                    &expires_at,
                    format!("family:{family}"),
                );
                emit(&mut out, &start, &places, "harness");
            }
        }
    }
    out
}
