//! v2 device acknowledgement validation and monotonic transitions.

use serde_json::Value;

use crate::policy_bundle_py::{
    canonical_uuid, in_set, int_cmp, int_token, is_hex64, is_non_negative_int, is_positive_int,
    is_sha256_digest, py_eq, py_eq_opt, strict_non_empty, Obj,
};
use crate::policy_bundle_time::strict_utc_micros;
use crate::policy_bundle_v2::CONTRACT;

pub(crate) const STATUSES: [&str; 5] = ["received", "validated", "applied", "failed", "offline"];
const ALLOWED: [&str; 21] = [
    "contractVersion",
    "workspaceId",
    "deviceId",
    "deliveryId",
    "runtimeSessionId",
    "bundleId",
    "bundleVersion",
    "bundleHash",
    "policyRevision",
    "extensionAuthorityRevision",
    "catalogDigest",
    "effectiveProjectionDigest",
    "payloadHash",
    "extensionProjectionDigest",
    "appliedExtensionAuthorityRevision",
    "appliedEffectiveProjectionDigest",
    "lastKnownGoodBundleHash",
    "sequence",
    "status",
    "observedAt",
    "errorCode",
];
const STRING_FIELDS: [&str; 6] = [
    "workspaceId",
    "deviceId",
    "deliveryId",
    "runtimeSessionId",
    "bundleId",
    "bundleHash",
];
const DIGEST_FIELDS: [&str; 5] = [
    "bundleHash",
    "effectiveProjectionDigest",
    "payloadHash",
    "extensionProjectionDigest",
    "appliedEffectiveProjectionDigest",
];
const INTEGER_FIELDS: [&str; 4] = [
    "bundleVersion",
    "sequence",
    "policyRevision",
    "appliedExtensionAuthorityRevision",
];
const BAD: &str = "invalid_acknowledgement";

fn required() -> impl Iterator<Item = &'static str> {
    ALLOWED.iter().copied().filter(|key| *key != "errorCode")
}

fn transitions(previous: &str) -> &'static [&'static str] {
    match previous {
        "received" => &["received", "validated", "failed", "offline"],
        "validated" => &["validated", "applied", "failed", "offline"],
        "applied" => &["applied", "offline"],
        "failed" => &["failed", "received", "offline"],
        _ => &["offline", "received"],
    }
}

fn field_error(ack: &Obj) -> Option<&'static str> {
    if ack.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Some("unknown_field");
    }
    if required().any(|key| !ack.contains_key(key)) {
        return Some("missing_required_field");
    }
    if ack.get("contractVersion").and_then(Value::as_str) != Some(CONTRACT) {
        return Some("unsupported_contract_version");
    }
    if STRING_FIELDS
        .iter()
        .any(|key| strict_non_empty(ack.get(*key), 256).is_none())
        || !canonical_uuid(ack.get("deliveryId"), 128)
        || DIGEST_FIELDS
            .iter()
            .any(|key| !is_sha256_digest(ack.get(*key)))
        || !matches!(ack.get("catalogDigest"), Some(Value::String(text)) if is_hex64(text))
    {
        return Some(BAD);
    }
    let last_good = ack.get("lastKnownGoodBundleHash");
    if last_good.is_some_and(|value| !value.is_null()) && !is_sha256_digest(last_good) {
        return Some(BAD);
    }
    if INTEGER_FIELDS
        .iter()
        .any(|key| !is_positive_int(ack.get(*key)))
        || !is_non_negative_int(ack.get("extensionAuthorityRevision"))
    {
        return Some(BAD);
    }
    if !in_set(ack.get("status"), &STATUSES) {
        return Some("invalid_acknowledgement_status");
    }
    if ack
        .get("observedAt")
        .and_then(Value::as_str)
        .and_then(strict_utc_micros)
        .is_none()
    {
        return Some(BAD);
    }
    match ack.get("errorCode") {
        None | Some(Value::Null) => None,
        other if strict_non_empty(other, 128).is_some() => None,
        Some(_) => Some(BAD),
    }
}

/// Python `isinstance(value, int)`: a bool is an int (`True` is 1).
pub(crate) fn python_int(value: &Value) -> Option<&str> {
    match value {
        Value::Bool(flag) => Some(if *flag { "1" } else { "0" }),
        other => int_token(other),
    }
}

/// `validated_policy_bundle_v2_acknowledgement`; `Ok` means accept as given.
pub(crate) fn validate(ack: &Obj, previous: Option<&Obj>) -> Result<(), &'static str> {
    if let Some(code) = field_error(ack) {
        return Err(code);
    }
    let Some(previous) = previous else {
        return Ok(());
    };
    let identity = required().filter(|key| {
        !matches!(
            *key,
            "contractVersion" | "sequence" | "status" | "observedAt"
        )
    });
    if identity
        .into_iter()
        .any(|key| !py_eq_opt(previous.get(key), ack.get(key)))
    {
        return Err("acknowledgement_identity_mismatch");
    }
    let previous_status = previous.get("status");
    let (Some(old), true) = (
        previous.get("sequence").and_then(python_int),
        in_set(previous_status, &STATUSES),
    ) else {
        return Err("invalid_previous_acknowledgement");
    };
    let new = ack.get("sequence").and_then(int_token).ok_or(BAD)?;
    match int_cmp(new, old) {
        std::cmp::Ordering::Less => Err("acknowledgement_replay"),
        std::cmp::Ordering::Equal => {
            if py_eq(
                &Value::Object(ack.clone()),
                &Value::Object(previous.clone()),
            ) {
                Ok(())
            } else {
                Err("acknowledgement_sequence_conflict")
            }
        }
        std::cmp::Ordering::Greater => {
            let allowed = transitions(previous_status.and_then(Value::as_str).unwrap_or(""));
            if in_set(ack.get("status"), allowed) {
                Ok(())
            } else {
                Err("acknowledgement_transition_rejected")
            }
        }
    }
}
