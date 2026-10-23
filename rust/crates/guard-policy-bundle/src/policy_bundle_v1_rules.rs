//! Field-level validators for the v1 policy bundle contract and the shared
//! rule-vocabulary constants the decision materializer reuses.

use serde_json::Value;

use crate::policy_bundle_py::{in_set, non_empty, obj, py_truthy, string_list, text, Obj};
use crate::policy_bundle_time::{replaced_timestamp, v1_timestamp};

pub(crate) const RULE_ACTIONS: [&str; 4] = ["allow", "block", "review", "ignore"];
pub(crate) const MATCHER_FAMILIES: [&str; 7] = [
    "file-read",
    "mcp",
    "mcp-tool",
    "package-request",
    "prompt",
    "prompt-env-read",
    "tool-action",
];
pub(crate) const BROWSER_SCOPE_KEYS: [&str; 6] = [
    "browserIntent",
    "browserOperation",
    "browserProfile",
    "origin",
    "pathPrefix",
    "sensitiveSurface",
];
const OTHER_SCOPE_KEYS: [&str; 6] = [
    "agents",
    "devices",
    "ecosystems",
    "environments",
    "harnesses",
    "locations",
];
const BROWSER_INTENTS: [&str; 5] = [
    "browser.navigation",
    "browser.inspect",
    "browser.interact",
    "browser.transfer",
    "browser.privileged",
];
const BROWSER_PROFILES: [&str; 5] = [
    "isolated",
    "dedicated",
    "shared",
    "remote-debugging",
    "unknown",
];
pub(crate) const ROLLOUT_STATES: [&str; 6] = [
    "draft",
    "simulated",
    "pending_approval",
    "enforcing",
    "enforced",
    "rollback_available",
];
pub(crate) const ENFORCEABLE_ROLLOUT_STATES: [&str; 3] =
    ["enforcing", "enforced", "rollback_available"];
const DEFAULT_ACTIONS: [&str; 3] = ["allow", "warn", "block"];
const MODE_VALUES: [&str; 3] = ["observe", "prompt", "enforce"];
const REVIEW_ACTIONS: [&str; 3] = ["allow", "review", "block"];
const CHANGED_HASH_ACTIONS: [&str; 4] = ["allow", "warn", "require-reapproval", "block"];
const REDACTION_LEVELS: [&str; 3] = ["full", "partial", "none"];
const ACK_STATUSES: [&str; 4] = ["pending", "synced", "failed", "offline"];
const EXCEPTION_SCOPES: [&str; 5] = ["artifact", "publisher", "harness", "workspace", "global"];

fn optional_non_empty(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null)) || non_empty(value).is_some()
}

fn all_in(value: &Value, allowed: &[&str]) -> bool {
    match value {
        Value::Array(items) => items
            .iter()
            .all(|item| item.as_str().is_some_and(|name| allowed.contains(&name))),
        _ => false,
    }
}

/// `_policy_bundle_rule_is_valid`.
pub(crate) fn rule_is_valid(rule: &Value) -> bool {
    let Some(rule) = rule.as_object() else {
        return false;
    };
    if non_empty(rule.get("ruleId")).is_none()
        || !in_set(rule.get("action"), &RULE_ACTIONS)
        || !matches!(rule.get("reason"), Some(Value::String(_)))
        || !optional_non_empty(rule.get("sourceReceiptId"))
        || !optional_non_empty(rule.get("sourceLocalRequestId"))
    {
        return false;
    }
    for key in ["sourceReceiptIds", "auditEventIds"] {
        match rule.get(key) {
            None | Some(Value::Null) => {}
            other if string_list(other) => {}
            _ => return false,
        }
    }
    if let Some(families) = rule.get("matcherFamilies") {
        let Value::Array(items) = families else {
            return false;
        };
        if items.iter().any(|family| {
            non_empty(Some(family)).is_none()
                || !MATCHER_FAMILIES.contains(&text(Some(family)).unwrap_or(""))
        }) {
            return false;
        }
    }
    match rule.get("expiresAt") {
        None | Some(Value::Null) => {}
        other => match non_empty(other) {
            Some(expiry) if v1_timestamp(expiry).is_some() => {}
            _ => return false,
        },
    }
    scope_is_valid(rule.get("scope"))
}

fn scope_is_valid(scope: Option<&Value>) -> bool {
    let Some(scope) = obj(scope) else {
        return false;
    };
    for key in BROWSER_SCOPE_KEYS.iter().chain(OTHER_SCOPE_KEYS.iter()) {
        if scope.contains_key(*key) && !string_list(scope.get(*key)) {
            return false;
        }
    }
    for (key, allowed) in [
        ("browserIntent", &BROWSER_INTENTS[..]),
        ("browserProfile", &BROWSER_PROFILES[..]),
    ] {
        match scope.get(key) {
            None | Some(Value::Null) => {}
            Some(value) => {
                if !string_list(Some(value)) || !all_in(value, allowed) {
                    return false;
                }
            }
        }
    }
    true
}

/// `_policy_bundle_acknowledgement_is_valid`.
pub(crate) fn acknowledgement_is_valid(item: &Value) -> bool {
    let Some(item) = item.as_object() else {
        return false;
    };
    non_empty(item.get("deviceId")).is_some()
        && optional_non_empty(item.get("deviceName"))
        && optional_non_empty(item.get("acknowledgedAt"))
        && in_set(item.get("status"), &ACK_STATUSES)
}

/// The `policyDefaults` block checks.
pub(crate) fn defaults_are_valid(defaults: Option<&Value>) -> bool {
    let Some(defaults) = obj(defaults) else {
        return false;
    };
    in_set(defaults.get("mode"), &MODE_VALUES)
        && in_set(defaults.get("defaultAction"), &DEFAULT_ACTIONS)
        && in_set(defaults.get("unknownPublisherAction"), &REVIEW_ACTIONS)
        && in_set(defaults.get("changedHashAction"), &CHANGED_HASH_ACTIONS)
        && in_set(defaults.get("newNetworkDomainAction"), &DEFAULT_ACTIONS)
        && in_set(defaults.get("subprocessAction"), &DEFAULT_ACTIONS)
        && matches!(defaults.get("telemetryEnabled"), Some(Value::Bool(_)))
        && matches!(defaults.get("syncEnabled"), Some(Value::Bool(_)))
}

pub(crate) fn redaction_level_is_valid(value: Option<&Value>) -> bool {
    in_set(value, &REDACTION_LEVELS)
}

fn exception_is_valid(item: &Value) -> bool {
    let Some(item) = item.as_object() else {
        return false;
    };
    exception_fields_are_valid(item)
}

fn first_truthy<'a>(item: &'a Obj, first: &str, second: &str) -> Option<&'a Value> {
    let primary = item.get(first);
    if py_truthy(primary) {
        primary
    } else {
        item.get(second)
    }
}

fn exception_fields_are_valid(item: &Obj) -> bool {
    if non_empty(first_truthy(item, "exceptionId", "id")).is_none() {
        return false;
    }
    match item.get("effect") {
        Some(effect) if py_truthy(Some(effect)) => {
            if effect.as_str() != Some("allow") {
                return false;
            }
        }
        _ => {}
    }
    let scope = item.get("scope");
    if !in_set(scope, &EXCEPTION_SCOPES) || non_empty(item.get("owner")).is_none() {
        return false;
    }
    let expiry = match non_empty(first_truthy(item, "expiresAt", "expiry")) {
        Some(expiry) => expiry,
        None => return false,
    };
    if replaced_timestamp(expiry).is_none() {
        return false;
    }
    let harness = item.get("harness");
    if scope.and_then(Value::as_str) == Some("harness") {
        if non_empty(harness).is_none() {
            return false;
        }
    } else if !matches!(harness, None | Some(Value::Null) | Some(Value::String(_))) {
        return false;
    }
    optional_non_empty(item.get("approver")) && optional_non_empty(item.get("sourceReceiptId"))
}

/// `policy_bundle_cloud_exceptions_are_valid`.
pub(crate) fn cloud_exceptions_are_valid(bundle: &Obj) -> bool {
    match bundle.get("cloudExceptions") {
        None => true,
        Some(Value::Array(items)) => items.iter().all(exception_is_valid),
        Some(_) => false,
    }
}
