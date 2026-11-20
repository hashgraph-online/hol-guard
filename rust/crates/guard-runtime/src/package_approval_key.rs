//! The package key a hook-route package review carries.
//!
//! The hook route reviews an install by its exact command, so an Always allow
//! saved only under that command never answers the identical install run from
//! another checkout of the repository. The review carries the install's package
//! key, which is bound to the repository, dependency graph and launch instead,
//! and an Always allow on it is saved under that key as well. Queuing and
//! resolution accept the same keys: only the harness's own package request key.

use guard_contracts::{ApprovalResolutionPlanApprovalV1, PackageApprovalKeyV1};
use serde_json::{json, Value};

use crate::context_digest::parse_context_token;

/// Whether `key` names this harness's own package request.
pub(crate) fn fits(key: &PackageApprovalKeyV1, harness: &str) -> bool {
    key.harness == harness
        && key
            .artifact_id
            .strip_prefix(harness)
            .and_then(|rest| rest.strip_prefix(":project:package-request:"))
            .is_some_and(|fingerprint| !fingerprint.is_empty())
        && parse_context_token(&Value::String(key.artifact_hash.clone())).is_some()
}

/// The package Always allow an Always allow on this review also saves, or
/// null when the answer saves nothing (`saved` is false: Allow once, a block,
/// or a wider scope) or the review carries no key that fits its harness.
pub(crate) fn decision(approval: &ApprovalResolutionPlanApprovalV1, saved: bool) -> Value {
    if !saved {
        return Value::Null;
    }
    let key = approval
        .envelope
        .as_ref()
        .and_then(|envelope| envelope.package_approval.as_ref());
    let (Some(key), Some(harness)) = (key, approval.harness.as_deref()) else {
        return Value::Null;
    };
    if !fits(key, harness) {
        return Value::Null;
    }
    json!({
        "harness": key.harness,
        "scope": "artifact",
        "action": "allow",
        "artifact_id": key.artifact_id,
        "artifact_hash": key.artifact_hash,
        "workspace": Value::Null,
        "publisher": Value::Null,
    })
}
