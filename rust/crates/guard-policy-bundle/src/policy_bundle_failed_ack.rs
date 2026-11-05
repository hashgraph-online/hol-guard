//! Failed acknowledgements for a bundle that Cloud delivered, or that Guard
//! cached, and that no longer passes local validation.
//!
//! Without one, Cloud keeps the device's last applied acknowledgement and
//! shows the bundle as applied while Guard enforces nothing from it. The
//! acknowledgement only reports the rejection: building it never changes what
//! Guard enforces, and an empty map means Cloud has no shape that can carry
//! this failure.

use serde_json::{Map, Value};

use crate::policy_bundle_delivery::{has_extension_semantics, increment, GENERIC_IDENTITY_KEYS};
use crate::policy_bundle_py::{py_eq_opt, strict_non_empty, Obj};
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

/// The failed acknowledgement for `request.bundle`, or an empty map.
pub(crate) fn failed_ack(request: &FailedRequest) -> Obj {
    if !bounded(request.error_code) || !bounded(request.device_id) {
        return Obj::new();
    }
    if request
        .bundle
        .get("contractVersion")
        .and_then(Value::as_str)
        == Some(CONTRACT)
    {
        generic_failed_ack(request)
    } else {
        legacy_failed_ack(request)
    }
}

/// `guard-policy-bundle.v1` acknowledgements carry no sequence. Re-sending the
/// stored failure for the same bundle keeps its first `appliedAt`.
fn legacy_failed_ack(request: &FailedRequest) -> Obj {
    let (Some(bundle_hash), Some(bundle_version)) = (
        strict_non_empty(request.bundle.get("bundleHash"), MAX_TEXT),
        strict_non_empty(request.bundle.get("bundleVersion"), MAX_TEXT),
    ) else {
        return Obj::new();
    };
    let is_stored_failure = |previous: &&Obj| {
        !previous.contains_key("contractVersion")
            && previous.get("status").and_then(Value::as_str) == Some(FAILED)
            && previous.get("bundleHash").and_then(Value::as_str) == Some(bundle_hash)
            && previous.get("bundleVersion").and_then(Value::as_str) == Some(bundle_version)
            && previous.get("deviceId").and_then(Value::as_str) == Some(request.device_id)
    };
    if let Some(previous) = request.previous.filter(is_stored_failure) {
        return previous.clone();
    }
    let mut ack = Map::new();
    ack.insert(
        "appliedAt".to_owned(),
        Value::String(request.synced_at.to_owned()),
    );
    ack.insert(
        "bundleHash".to_owned(),
        Value::String(bundle_hash.to_owned()),
    );
    ack.insert(
        "bundleVersion".to_owned(),
        Value::String(bundle_version.to_owned()),
    );
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

/// A v2 bundle reports its failure in the generic shape, bound to the signed
/// bundle and the device. A bundle with Extension semantics is acknowledged
/// only against its managed delivery, which a rejected bundle does not have,
/// and Cloud never lets an applied acknowledgement become failed, so both get
/// nothing.
fn generic_failed_ack(request: &FailedRequest) -> Obj {
    if has_extension_semantics(request.bundle) {
        return Obj::new();
    }
    let mut candidate = Obj::new();
    for field in GENERIC_IDENTITY_KEYS {
        let value = if field == "deviceId" {
            Some(Value::String(request.device_id.to_owned()))
        } else {
            request.bundle.get(field).cloned()
        };
        let Some(value) = value else {
            return Obj::new();
        };
        candidate.insert(field.to_owned(), value);
    }
    let matching = request.previous.filter(|previous| {
        !previous.contains_key("deliveryId")
            && GENERIC_IDENTITY_KEYS
                .iter()
                .all(|field| py_eq_opt(previous.get(*field), candidate.get(*field)))
    });
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
