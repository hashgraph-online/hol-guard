//! Failed acknowledgements for a bundle that Cloud delivered, or that Guard
//! cached, and that no longer passes local validation, or that Guard dropped.
//!
//! Without one, Cloud keeps the device's last applied acknowledgement and
//! shows the bundle as applied while Guard enforces nothing from it. The
//! acknowledgement only reports the rejection: building it never changes what
//! Guard enforces, and an empty map means Cloud has no shape that can carry
//! this failure.
//!
//! When the stored acknowledgement already told Cloud a bundle was delivered,
//! that acknowledgement is retracted in the legacy shape, which Cloud accepts
//! as `failed` for both contracts and which replaces a stored v2
//! acknowledgement (Cloud never lets a v2 `applied` become `failed`).
//! Otherwise the rejected bundle itself is reported.

use serde_json::{Map, Value};

use crate::policy_bundle_delivery::{has_extension_semantics, increment, GENERIC_IDENTITY_KEYS};
use crate::policy_bundle_py::{int_token, py_eq_opt, strict_non_empty, Obj};
use crate::policy_bundle_time::normalized_observed_at;
use crate::policy_bundle_v2::CONTRACT;
use crate::policy_bundle_v2_ack::{python_int, validate as validate_ack};

/// Cloud bounds every acknowledgement string, `errorCode` included, at 128.
const MAX_TEXT: usize = 128;
const FAILED: &str = "failed";

pub(crate) struct FailedRequest<'a> {
    pub(crate) device_id: &'a str,
    pub(crate) device_name: &'a str,
    pub(crate) bundle: &'a Obj,
    pub(crate) synced_at: &'a str,
    pub(crate) error_code: &'a str,
    pub(crate) previous: Option<&'a Obj>,
}

fn bounded(text: &str) -> bool {
    strict_non_empty(Some(&Value::String(text.to_owned())), MAX_TEXT).is_some()
}

/// The failed acknowledgement for this device, or an empty map.
pub(crate) fn failed_ack(request: &FailedRequest) -> Obj {
    if !bounded(request.error_code) || !bounded(request.device_id) {
        return Obj::new();
    }
    if let Some(ack) = request
        .previous
        .and_then(|previous| previous_failure(request, previous))
    {
        return ack;
    }
    if is_v2(request.bundle) {
        generic_failed_ack(request)
    } else {
        match legacy_identity(request.bundle, text_version) {
            Some((hash, version)) => legacy_failed_ack(request, hash, version),
            None => Obj::new(),
        }
    }
}

fn is_v2(document: &Obj) -> bool {
    document.get("contractVersion").and_then(Value::as_str) == Some(CONTRACT)
}

fn is_legacy_failure(previous: &Obj) -> bool {
    !previous.contains_key("contractVersion")
        && previous.get("status").and_then(Value::as_str) == Some(FAILED)
}

/// `Some` when the stored acknowledgement decides what to report.
fn previous_failure(request: &FailedRequest, previous: &Obj) -> Option<Obj> {
    if is_legacy_failure(previous) {
        // Re-sending the stored failure keeps its first `appliedAt`, so Cloud
        // sees one report instead of a new one every cycle.
        let ours = previous.get("deviceId").and_then(Value::as_str) == Some(request.device_id)
            && strict_non_empty(previous.get("appliedAt"), MAX_TEXT).is_some()
            && legacy_identity(previous, text_version).is_some();
        return ours.then(|| previous.clone());
    }
    if previous.get("status").and_then(Value::as_str) == Some(FAILED)
        || continues_generic(request, previous)
    {
        return None;
    }
    let (hash, version) = legacy_identity(previous, previous_version)?;
    Some(legacy_failed_ack(request, hash, version))
}

fn text_version(value: Option<&Value>) -> Option<String> {
    strict_non_empty(value, MAX_TEXT).map(str::to_owned)
}

/// A stored version may be a v1 string or a positive v2 integer; both report
/// as text.
fn previous_version(value: Option<&Value>) -> Option<String> {
    if let Some(text) = text_version(value) {
        return Some(text);
    }
    match value? {
        Value::Bool(_) => None,
        number => int_token(number)
            .filter(|token| *token != "0" && !token.starts_with('-'))
            .map(str::to_owned),
    }
}

fn legacy_identity(
    document: &Obj,
    version: impl Fn(Option<&Value>) -> Option<String>,
) -> Option<(String, String)> {
    let hash = strict_non_empty(document.get("bundleHash"), MAX_TEXT)?;
    Some((hash.to_owned(), version(document.get("bundleVersion"))?))
}

/// `guard-policy-bundle.v1` acknowledgements carry no sequence or error code.
fn legacy_failed_ack(request: &FailedRequest, bundle_hash: String, bundle_version: String) -> Obj {
    let mut ack = Map::new();
    ack.insert(
        "appliedAt".to_owned(),
        Value::String(request.synced_at.to_owned()),
    );
    ack.insert("bundleHash".to_owned(), Value::String(bundle_hash));
    ack.insert("bundleVersion".to_owned(), Value::String(bundle_version));
    ack.insert(
        "deviceId".to_owned(),
        Value::String(request.device_id.to_owned()),
    );
    if bounded(request.device_name) {
        ack.insert(
            "deviceName".to_owned(),
            Value::String(request.device_name.to_owned()),
        );
    }
    ack.insert("status".to_owned(), Value::String(FAILED.to_owned()));
    ack
}

/// The generic identity a failure of this v2 bundle carries.
fn generic_candidate(request: &FailedRequest) -> Option<Obj> {
    if !is_v2(request.bundle) || has_extension_semantics(request.bundle) {
        return None;
    }
    let mut candidate = Obj::new();
    for field in GENERIC_IDENTITY_KEYS {
        let value = if field == "deviceId" {
            Value::String(request.device_id.to_owned())
        } else {
            request.bundle.get(field).cloned()?
        };
        candidate.insert(field.to_owned(), value);
    }
    Some(candidate)
}

fn same_generic_bundle(candidate: &Obj, previous: &Obj) -> bool {
    !previous.contains_key("deliveryId")
        && GENERIC_IDENTITY_KEYS
            .iter()
            .all(|field| py_eq_opt(previous.get(*field), candidate.get(*field)))
}

/// A v2 acknowledgement of this bundle that has not reached applied yet, which
/// the generic failure continues instead of retracting.
fn continues_generic(request: &FailedRequest, previous: &Obj) -> bool {
    matches!(
        previous.get("status").and_then(Value::as_str),
        Some("received" | "validated")
    ) && generic_candidate(request)
        .is_some_and(|candidate| same_generic_bundle(&candidate, previous))
}

/// A v2 bundle reports its failure in the generic shape, bound to the signed
/// bundle and the device. A bundle with Extension semantics is acknowledged
/// only against its managed delivery, which a rejected bundle does not have,
/// so it gets nothing.
fn generic_failed_ack(request: &FailedRequest) -> Obj {
    let Some(candidate) = generic_candidate(request) else {
        return Obj::new();
    };
    let matching = request
        .previous
        .filter(|previous| same_generic_bundle(&candidate, previous));
    let error_code = Value::String(request.error_code.to_owned());
    if let Some(previous) = matching {
        match previous.get("status").and_then(Value::as_str) {
            Some(FAILED) if py_eq_opt(previous.get("errorCode"), Some(&error_code)) => {
                return previous.clone();
            }
            Some("received" | "validated" | FAILED) => {}
            _ => return Obj::new(),
        }
    }
    let sequence = match matching
        .and_then(|previous| previous.get("sequence"))
        .and_then(python_int)
    {
        Some(token) => match increment(token) {
            Some(next) => next,
            None => return Obj::new(),
        },
        None => Value::from(1),
    };
    let Some(observed) = normalized_observed_at(request.synced_at) else {
        return Obj::new();
    };
    let mut ack = candidate;
    ack.insert(
        "contractVersion".to_owned(),
        Value::String(CONTRACT.to_owned()),
    );
    ack.insert("sequence".to_owned(), sequence);
    ack.insert("status".to_owned(), Value::String(FAILED.to_owned()));
    ack.insert("observedAt".to_owned(), Value::String(observed));
    ack.insert("errorCode".to_owned(), error_code);
    if validate_ack(&ack, matching).is_err() {
        return Obj::new();
    }
    ack
}
