//! `sync_acknowledgement`: the stored policy bundle acknowledgement the
//! cloud sync may report in its request context.
//!
//! A v2 acknowledgement is reported when it is a valid transition from no
//! previous acknowledgement. A legacy acknowledgement is reported only while
//! it names the bundle Guard still enforces, this device, a `synced` status
//! and a parseable `appliedAt`.
//!
//! The caller validates the cached bundle only when a legacy acknowledgement
//! needs it: without a `bundle` field the answer is `{"needs_bundle": true}`,
//! and the caller asks again with the validated bundle, or `null` when none
//! validates.

use serde_json::{json, Value};

use crate::policy_bundle_op::{text_field, Fail, Handled};
use crate::policy_bundle_py::{obj, Obj};
use crate::policy_bundle_time::from_isoformat;
use crate::policy_bundle_v2::CONTRACT as V2_CONTRACT;
use crate::policy_bundle_v2_ack as ack;

/// Python `isinstance(value, str) and value.strip()`.
fn non_empty(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
}

/// The runner's `_normalized_timestamp_string(value) is not None`.
fn parses_as_timestamp(value: Option<&Value>) -> bool {
    non_empty(value).is_some_and(|text| from_isoformat(&text.replace('Z', "+00:00")).is_some())
}

/// A legacy acknowledgement still describes `bundle` on this device.
fn matches_bundle(acknowledgement: &Obj, bundle: &Obj, device: (&str, &str)) -> bool {
    let (Some(hash), Some(version)) = (
        non_empty(bundle.get("bundleHash")),
        non_empty(bundle.get("bundleVersion")),
    ) else {
        return false;
    };
    let text = |name: &str| acknowledgement.get(name).and_then(Value::as_str);
    text("bundleHash") == Some(hash)
        && text("bundleVersion") == Some(version)
        && text("deviceId") == Some(device.0)
        && text("deviceName") == Some(device.1)
        && text("status") == Some("synced")
        && parses_as_timestamp(acknowledgement.get("appliedAt"))
}

pub(crate) fn sync_acknowledgement(input: &Obj) -> Handled {
    let acknowledgement = obj(input.get("ack")).ok_or(Fail::Invalid)?;
    let device = (
        text_field(input, "device_id")?,
        text_field(input, "device_name")?,
    );
    let reported = |keep: bool| {
        Ok(
            json!({ "ack": if keep { Value::Object(acknowledgement.clone()) } else { Value::Null } }),
        )
    };
    if acknowledgement
        .get("contractVersion")
        .and_then(Value::as_str)
        == Some(V2_CONTRACT)
    {
        return reported(ack::validate(acknowledgement, None).is_ok());
    }
    match input.get("bundle") {
        None => Ok(json!({ "needs_bundle": true })),
        Some(Value::Null) => reported(false),
        Some(Value::Object(bundle)) => reported(matches_bundle(acknowledgement, bundle, device)),
        Some(_) => Err(Fail::Invalid),
    }
}

#[cfg(test)]
#[path = "policy_bundle_op_sync_ack_tests.rs"]
mod tests;
