//! An approved Guard Cloud exception lifts the signed bundle's own rules for the
//! target it covers (`lift_cloud_excepted_policy_bundle_identities`,
//! `cloud_exceptions.py`).
//!
//! The lookup honors a saved `policy-bundle` row only while its identity is
//! listed, so leaving the bundle's non-allow identities out of one lookup lifts
//! its Cloud blocks and reviews there, and the lookup ranks the remaining local
//! rows as it would without them.

use std::collections::HashMap;

use guard_contracts::utc_timestamp_micros;
use serde_json::{Map, Value};

use crate::policy_bundle_store_identities::Identity;

#[cfg(test)]
#[path = "cloud_exception_lift_tests.rs"]
mod tests;

/// `_CLOUD_EXCEPTION_SCOPES` (`cloud_exceptions.py`).
const SCOPES: [&str; 5] = ["artifact", "publisher", "harness", "workspace", "global"];
/// Position of the action in a decision identity.
const ACTION_INDEX: usize = 6;

/// The evaluated target of one lookup.
pub(crate) struct LiftTarget<'a> {
    pub(crate) harness: &'a str,
    pub(crate) artifact_id: Option<&'a str>,
    pub(crate) publisher: Option<&'a str>,
    pub(crate) workspace: Option<&'a str>,
    pub(crate) now: &'a str,
}

/// The identities to ship for this lookup: all of them, or only the bundle's
/// allow identities when an active exception in `bundle` covers `target`.
pub(crate) fn lift_cloud_excepted_identities(
    identities: &[Identity],
    bundle: Option<&Map<String, Value>>,
    target: &LiftTarget<'_>,
) -> Vec<Identity> {
    if identities.is_empty() || !bundle.is_some_and(|bundle| covered(bundle, target)) {
        return identities.to_vec();
    }
    identities
        .iter()
        .filter(|identity| identity.get(ACTION_INDEX).and_then(Value::as_str) == Some("allow"))
        .cloned()
        .collect()
}

/// Whether an active exception in `bundle` covers `target`, which lifts the
/// bundle's canonical (v2) non-allow rules for that lookup
/// (`policy_bundle_rules_lifted`).
pub(crate) fn cloud_exception_covers(
    bundle: Option<&Map<String, Value>>,
    target: &LiftTarget<'_>,
) -> bool {
    bundle.is_some_and(|bundle| covered(bundle, target))
}

struct Exception<'a> {
    id: &'a str,
    scope: &'a str,
    harness: Option<&'a str>,
    expiry: i64,
    raw: &'a Map<String, Value>,
}

/// `cloud_exception_lifting_policy_bundle`: whether an active exception covers
/// the target. When an id repeats, the last entry wins.
fn covered(bundle: &Map<String, Value>, target: &LiftTarget<'_>) -> bool {
    let Some(Value::Array(items)) = bundle.get("cloudExceptions") else {
        return false;
    };
    let Some(now) = utc_timestamp_micros(target.now) else {
        return false;
    };
    let mut latest: HashMap<&str, Exception<'_>> = HashMap::new();
    for item in items {
        if let Some(exception) = item.as_object().and_then(parse) {
            latest.insert(exception.id, exception);
        }
    }
    let bundle_workspace_id = non_empty(bundle.get("workspaceId"));
    latest
        .values()
        .any(|exception| exception.expiry > now && matches(exception, target, bundle_workspace_id))
}

/// `cloud_exception_from_mapping`, reduced to the fields matching reads.
fn parse(raw: &Map<String, Value>) -> Option<Exception<'_>> {
    let id = non_empty(either(raw, "exceptionId", "id"))?;
    let scope = raw
        .get("scope")
        .and_then(Value::as_str)
        .filter(|scope| SCOPES.contains(scope))?;
    match raw.get("effect").filter(|effect| truthy(effect)) {
        None => {}
        Some(effect) if effect.as_str() == Some("allow") => {}
        Some(_) => return None,
    }
    non_empty(raw.get("owner"))?;
    let expiry = non_empty(either(raw, "expiresAt", "expiry")).and_then(utc_timestamp_micros)?;
    let harness = non_empty(raw.get("harness"));
    if scope == "harness" && harness.is_none() {
        return None;
    }
    Some(Exception {
        id,
        scope,
        harness,
        expiry,
        raw,
    })
}

/// `_cloud_exception_matches`.
fn matches(
    exception: &Exception<'_>,
    target: &LiftTarget<'_>,
    bundle_workspace_id: Option<&str>,
) -> bool {
    if exception
        .harness
        .is_some_and(|harness| harness != "*" && harness != target.harness)
    {
        return false;
    }
    let raw = exception.raw;
    let mut artifact_id = non_empty(raw.get("artifactId"));
    let mut publisher = non_empty(raw.get("publisher"));
    let working_directory = non_empty(raw.get("workingDirectory"));
    let workspace_id = non_empty(raw.get("workspaceId"));
    // `_cloud_exception_legacy_scope_field`: an id of `artifact:<id>` or
    // `publisher:<name>` names its target.
    if let Some(value) = exception
        .id
        .strip_prefix(exception.scope)
        .and_then(|rest| rest.strip_prefix(':'))
        .filter(|value| !value.trim().is_empty())
    {
        match exception.scope {
            "artifact" => artifact_id = artifact_id.or(Some(value)),
            "publisher" => publisher = publisher.or(Some(value)),
            _ => {}
        }
    }
    // The scope's own target must be named; an exception that names no
    // artifact cannot stand in for an artifact exception.
    let unnamed = match exception.scope {
        "artifact" => artifact_id.is_none(),
        "publisher" => publisher.is_none(),
        "workspace" => working_directory.is_none() && workspace_id.is_none(),
        _ => false,
    };
    if unnamed {
        return false;
    }
    // A Cloud workspace id must be the workspace that signed the bundle.
    if workspace_id.is_some() && workspace_id != bundle_workspace_id {
        return false;
    }
    // Every device-side target the exception names narrows it.
    [
        (artifact_id, target.artifact_id),
        (publisher, target.publisher),
        (working_directory, target.workspace),
    ]
    .into_iter()
    .all(|(named, observed)| named.is_none() || named == observed)
}

/// `_non_empty_string`.
fn non_empty(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
}

/// `item.get(first) or item.get(second)`.
fn either<'a>(raw: &'a Map<String, Value>, first: &str, second: &str) -> Option<&'a Value> {
    raw.get(first)
        .filter(|value| truthy(value))
        .or_else(|| raw.get(second))
}

/// Python truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}
