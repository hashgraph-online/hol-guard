//! Admission kinds of the `PolicyBundleAuthority` op: whether an already
//! signature-checked candidate may replace the accepted bundle.
//!
//! `downgrade_verdict` decides replay and rollback against a reference bundle
//! (the v2 transition rules for a v2 candidate, the v1 ordering rules
//! otherwise). `candidate_admission` runs the full gate a synced candidate
//! passes before activation: daemon version, rollout state, then downgrade.

use serde_json::{json, Map, Value};

use crate::policy_bundle_op::{document, object_document, text_field, Fail, Handled};
use crate::policy_bundle_py::{is_int, Obj};
use crate::policy_bundle_v1 as v1;
use crate::policy_bundle_v2 as v2;

const ORDERING_KEYS: [&str; 5] = [
    "bundleVersion",
    "bundleHash",
    "payloadHash",
    "issuedAt",
    "workspaceId",
];

fn optional_document(input: &Obj, name: &str) -> Result<Value, Fail> {
    match input.get(name) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(_) => document(input, name),
    }
}

/// The fields the v1 ordering rules compare; anything else in the reference
/// must not make an otherwise empty reference look accepted.
fn ordering_view(bundle: &Value) -> Value {
    match bundle {
        Value::Object(map) => Value::Object(
            ORDERING_KEYS
                .iter()
                .filter_map(|key| {
                    map.get(*key)
                        .map(|value| ((*key).to_owned(), value.clone()))
                })
                .collect::<Map<String, Value>>(),
        ),
        other => other.clone(),
    }
}

fn int_at<'a>(bundle: Option<&'a Obj>, key: &str) -> Option<&'a Value> {
    bundle
        .and_then(|item| item.get(key))
        .filter(|value| is_int(Some(value)))
}

fn text_at<'a>(bundle: Option<&'a Obj>, key: &str) -> Option<&'a Value> {
    bundle
        .and_then(|item| item.get(key))
        .filter(|value| value.is_string())
}

/// The accepted Cloud exception set's identity: the hash a checkpoint stored,
/// else the hash of the set the reference bundle carries.
fn exceptions_hash(reference: Option<&Obj>) -> Option<Value> {
    let reference = reference?;
    match reference.get("cloudExceptionsHash") {
        Some(Value::String(hash)) => Some(Value::String(hash.clone())),
        _ => v2::cloud_exceptions_hash(reference).map(Value::String),
    }
}

pub(crate) fn is_downgrade(candidate: &Obj, reference: &Value, expected: &Value) -> bool {
    if candidate.get("contractVersion").and_then(Value::as_str) != Some(v2::CONTRACT) {
        return v1::is_downgrade(&ordering_view(reference), candidate);
    }
    let (reference, expected) = (reference.as_object(), expected.as_object());
    let current_hash = exceptions_hash(reference);
    let state = v2::Transition {
        current_version: int_at(reference, "bundleVersion"),
        current_hash: text_at(reference, "bundleHash"),
        expected_last_good_version: int_at(expected, "bundleVersion"),
        expected_last_good_hash: text_at(expected, "bundleHash"),
        current_cloud_exceptions_issued_at: text_at(reference, "cloudExceptionsIssuedAt"),
        current_cloud_exceptions_hash: current_hash.as_ref(),
    };
    v2::transition_error(candidate, &state).is_some()
}

fn downgrade_verdict(input: &Obj) -> Handled {
    let candidate = object_document(input, "bundle_chunks")?;
    let reference = optional_document(input, "reference_chunks")?;
    let expected = optional_document(input, "expected_chunks")?;
    Ok(json!({ "value": is_downgrade(&candidate, &reference, &expected) }))
}

/// The first reason a validated candidate may not become live authority.
pub(crate) fn rejection(
    candidate: &Obj,
    reference: &Value,
    daemon_version: &str,
) -> Option<&'static str> {
    if !v1::daemon_version_supported(candidate, daemon_version) {
        return Some("unsupported_daemon_version");
    }
    if !v1::is_enforceable(candidate) {
        return Some("inactive_rollout_state");
    }
    is_downgrade(candidate, reference, &Value::Null).then_some("bundle_version_downgrade")
}

fn candidate_admission(input: &Obj) -> Handled {
    let candidate = object_document(input, "bundle_chunks")?;
    let reference = optional_document(input, "reference_chunks")?;
    let daemon_version = text_field(input, "daemon_version")?;
    Ok(json!({ "rejection": rejection(&candidate, &reference, daemon_version) }))
}

pub(crate) fn handle(kind: &str, input: &Obj) -> Option<Handled> {
    Some(match kind {
        "downgrade_verdict" => downgrade_verdict(input),
        "candidate_admission" => candidate_admission(input),
        _ => return None,
    })
}
