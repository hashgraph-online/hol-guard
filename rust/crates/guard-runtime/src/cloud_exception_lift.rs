//! An approved Guard Cloud exception lifts the signed bundle's own rules for the
//! target it covers (`cloud_exception_lifting_policy_bundle`,
//! `cloud_exceptions.py`).
//!
//! The policy lookup asks once per probe, against the bundle stored in the
//! same connection it reads rows from, and leaves the bundle's blocks and
//! reviews out of that probe when an exception covers it. Its allows and every
//! other source still apply, and the remaining rows rank as they would without
//! them.

use std::collections::HashMap;

use guard_contracts::utc_timestamp_micros;
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::policy_bundle_store_identities::cached_bundle_authority;
#[cfg(test)]
use crate::policy_bundle_store_identities::BundleAuthority;

#[cfg(test)]
#[path = "cloud_exception_lift_tests.rs"]
mod tests;

#[cfg(test)]
thread_local! {
    /// The validated bundle authority a test reads in place of the cached
    /// bundle, whose RSA signature tests have no key to make.
    pub(crate) static VALIDATED_BUNDLE: std::cell::RefCell<Option<BundleAuthority>> =
        const { std::cell::RefCell::new(None) };
}

/// `_CLOUD_EXCEPTION_SCOPES` (`cloud_exceptions.py`).
const SCOPES: [&str; 5] = ["artifact", "publisher", "harness", "workspace", "global"];

/// The evaluated target of one lookup.
pub(crate) struct LiftTarget<'a> {
    pub(crate) harness: &'a str,
    pub(crate) artifact_id: Option<&'a str>,
    pub(crate) publisher: Option<&'a str>,
    pub(crate) workspace: Option<&'a str>,
    pub(crate) now: &'a str,
}

/// The bundle stored in `connection`, validated at `now`, that Cloud
/// exceptions are matched against. A bundle that is missing, or that the
/// resident cannot validate the way the Python store would, is `None` and
/// lifts nothing.
pub(crate) fn stored_exception_bundle(
    connection: &Connection,
    now: &str,
) -> Option<Map<String, Value>> {
    #[cfg(test)]
    if let Some((_, bundle)) = VALIDATED_BUNDLE.with(|cell| cell.borrow().clone()) {
        return bundle;
    }
    cached_bundle_authority(connection, now).and_then(|(_, bundle)| bundle)
}

/// Whether an active exception in `bundle` covers `target`.
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
