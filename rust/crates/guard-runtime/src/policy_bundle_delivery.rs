//! Strict correlation of managed policy deliveries to signed bundle authority
//! and the v2 acknowledgements built from them.

use serde_json::{Map, Value};

use crate::policy_bundle_py::{
    canonical_uuid, is_hex64, is_non_negative_int, is_positive_int, is_sha256_digest, obj, py_eq,
    py_eq_opt, strict_non_empty, Obj,
};
use crate::policy_bundle_time::normalized_observed_at;
use crate::policy_bundle_v2::CONTRACT;
use crate::policy_bundle_v2_ack::{python_int, validate as validate_ack};

const DELIVERY_KEYS: [&str; 14] = [
    "bundleId",
    "bundleHash",
    "bundleVersion",
    "workspaceId",
    "deviceId",
    "runtimeSessionId",
    "deliveryId",
    "policyRevision",
    "extensionAuthorityRevision",
    "catalogDigest",
    "effectiveProjectionDigest",
    "payloadHash",
    "extensionProjectionDigest",
    "lastKnownGoodBundleHash",
];
const BAD: &str = "invalid_policy_bundle_delivery";
const MISMATCH: &str = "policy_bundle_delivery_mismatch";

/// `policy_bundle_has_extension_semantics`.
pub(crate) fn has_extension_semantics(bundle: &Obj) -> bool {
    let Some(payload) = obj(bundle.get("payload")) else {
        return false;
    };
    if payload.contains_key("x-hol-extension-controls") {
        return true;
    }
    let Some(spec) = obj(payload.get("spec")) else {
        return false;
    };
    matches!(spec.get("rules"), Some(Value::Array(rules)) if rules.iter().any(|rule| {
        obj(Some(rule)).is_some_and(|rule| rule.contains_key("x-hol-extension-targets"))
    }))
}

fn scalars_are_valid(value: &Obj) -> bool {
    ["bundleId", "workspaceId", "deviceId", "runtimeSessionId"]
        .iter()
        .all(|field| strict_non_empty(value.get(*field), 128).is_some())
        && canonical_uuid(value.get("deliveryId"), 128)
        && is_sha256_digest(value.get("bundleHash"))
        && [
            "effectiveProjectionDigest",
            "payloadHash",
            "extensionProjectionDigest",
        ]
        .iter()
        .all(|field| is_sha256_digest(value.get(*field)))
        && matches!(value.get("catalogDigest"), Some(Value::String(text)) if is_hex64(text))
        && is_positive_int(value.get("bundleVersion"))
        && is_positive_int(value.get("policyRevision"))
        && is_non_negative_int(value.get("extensionAuthorityRevision"))
}

fn runtime_matches(value: &Obj, summary: &Obj, device_id: &str) -> bool {
    let device = summary.get("runtime_device_id");
    let device_ok = matches!(device, None | Some(Value::Null))
        || device.and_then(Value::as_str) == Some(device_id);
    device_ok
        && py_eq_opt(
            value.get("runtimeSessionId"),
            summary.get("runtime_session_id"),
        )
        && runtime_rest_matches(value, summary)
}

fn runtime_rest_matches(value: &Obj, summary: &Obj) -> bool {
    py_eq_opt(
        summary.get("extensionCatalogDigest"),
        value.get("catalogDigest"),
    ) && py_eq_opt(
        summary.get("extensionAuthorityRevision"),
        value.get("extensionAuthorityRevision"),
    ) && py_eq_opt(
        summary.get("effectiveProjectionDigest"),
        value.get("effectiveProjectionDigest"),
    )
}

/// `validate_policy_bundle_delivery`; `Ok` means the delivery is accepted as is.
pub(crate) fn validate_delivery(
    value: &Value,
    bundle: &Obj,
    workspace_id: Option<&str>,
    device_id: &str,
    summary: Option<&Value>,
) -> Result<(), &'static str> {
    let Value::Object(value) = value else {
        return Err("missing_policy_bundle_delivery");
    };
    if value.len() != DELIVERY_KEYS.len()
        || DELIVERY_KEYS.iter().any(|key| !value.contains_key(*key))
    {
        return Err("invalid_policy_bundle_delivery_fields");
    }
    let last_good = value.get("lastKnownGoodBundleHash");
    if !scalars_are_valid(value)
        || (last_good.is_some_and(|v| !v.is_null()) && !is_sha256_digest(last_good))
    {
        return Err(BAD);
    }
    let revision = obj(bundle.get("payload"))
        .and_then(|payload| obj(payload.get("metadata")))
        .and_then(|m| m.get("revision"));
    let signed_last_good =
        obj(bundle.get("rollback")).and_then(|rollback| rollback.get("lastGoodBundleHash"));
    let device = Value::String(device_id.to_owned());
    let expected: [(&str, Option<&Value>); 7] = [
        ("bundleHash", bundle.get("bundleHash")),
        ("bundleVersion", bundle.get("bundleVersion")),
        ("workspaceId", bundle.get("workspaceId")),
        ("deviceId", Some(&device)),
        ("policyRevision", revision),
        ("payloadHash", bundle.get("payloadHash")),
        ("lastKnownGoodBundleHash", signed_last_good),
    ];
    let workspace = workspace_id.map(|text| Value::String(text.to_owned()));
    if workspace.is_none() || !py_eq_opt(bundle.get("workspaceId"), workspace.as_ref()) {
        return Err(MISMATCH);
    }
    if expected
        .iter()
        .any(|(field, wanted)| !py_eq_opt(value.get(*field), *wanted))
    {
        return Err(MISMATCH);
    }
    let Some(Value::Object(summary)) = summary else {
        return Err("policy_bundle_delivery_runtime_unavailable");
    };
    if runtime_matches(value, summary, device_id) {
        Ok(())
    } else {
        Err(MISMATCH)
    }
}

/// Outcome of `validated_managed_policy_delivery`.
pub(crate) enum Managed {
    NotApplicable,
    Rejected(&'static str),
    Accepted,
}

pub(crate) fn validate_managed(
    bundle: &Obj,
    provided: bool,
    delivery: &Value,
    workspace_id: Option<&str>,
    device_id: &str,
    summary: Option<&Value>,
    expected_projection: Option<&str>,
) -> Managed {
    if bundle.get("contractVersion").and_then(Value::as_str) != Some(CONTRACT)
        || !has_extension_semantics(bundle)
    {
        return Managed::NotApplicable;
    }
    if !provided {
        return Managed::Rejected("missing_policy_bundle_delivery");
    }
    if let Err(code) = validate_delivery(delivery, bundle, workspace_id, device_id, summary) {
        return Managed::Rejected(code);
    }
    let digest = obj(Some(delivery)).and_then(|d| d.get("extensionProjectionDigest"));
    match expected_projection {
        Some(expected) if py_eq_opt(digest, Some(&Value::String(expected.to_owned()))) => {
            Managed::Accepted
        }
        _ => Managed::Rejected(MISMATCH),
    }
}

fn increment(token: &str) -> Option<Value> {
    let next = match token.parse::<i128>() {
        Ok(number) => (number + 1).to_string(),
        Err(_) if token.bytes().all(|b| b.is_ascii_digit()) => {
            let mut digits: Vec<u8> = token.bytes().collect();
            let mut index = digits.len();
            loop {
                if index == 0 {
                    digits.insert(0, b'1');
                    break;
                }
                index -= 1;
                if digits[index] == b'9' {
                    digits[index] = b'0';
                } else {
                    digits[index] += 1;
                    break;
                }
            }
            String::from_utf8(digits).ok()?
        }
        Err(_) => return None,
    };
    serde_json::from_str(&next).ok()
}

pub(crate) struct AckRequest<'a> {
    pub(crate) device_id: &'a str,
    pub(crate) device_name: &'a str,
    pub(crate) bundle: &'a Obj,
    pub(crate) synced_at: &'a str,
    pub(crate) status: &'a str,
    pub(crate) previous: Option<&'a Obj>,
    pub(crate) delivery: Option<&'a Obj>,
    pub(crate) applied_revision: Option<&'a Value>,
    pub(crate) applied_digest: Option<&'a Value>,
}

fn legacy_ack(request: &AckRequest) -> Result<Obj, String> {
    let take = |key: &str| {
        request
            .bundle
            .get(key)
            .cloned()
            .ok_or_else(|| format!("missing_policy_bundle_key:{key}"))
    };
    let mut ack = Map::new();
    ack.insert(
        "appliedAt".to_owned(),
        Value::String(request.synced_at.to_owned()),
    );
    ack.insert("bundleHash".to_owned(), take("bundleHash")?);
    ack.insert("bundleVersion".to_owned(), take("bundleVersion")?);
    ack.insert(
        "deviceId".to_owned(),
        Value::String(request.device_id.to_owned()),
    );
    ack.insert(
        "deviceName".to_owned(),
        Value::String(request.device_name.to_owned()),
    );
    ack.insert("status".to_owned(), Value::String("synced".to_owned()));
    Ok(ack)
}

/// `policy_bundle_acknowledgement_payload`; an empty map is Python's `{}`.
pub(crate) fn ack_payload(request: &AckRequest) -> Result<Obj, String> {
    if request
        .bundle
        .get("contractVersion")
        .and_then(Value::as_str)
        != Some(CONTRACT)
    {
        return legacy_ack(request);
    }
    let (Some(delivery), Some(revision), Some(digest)) = (
        request.delivery,
        request.applied_revision.filter(|v| !v.is_null()),
        request.applied_digest.filter(|v| !v.is_null()),
    ) else {
        return Ok(Obj::new());
    };
    let mut candidate = Obj::new();
    for field in DELIVERY_KEYS {
        let value = delivery
            .get(field)
            .ok_or("invalid_policy_bundle_acknowledgement")?;
        candidate.insert(field.to_owned(), value.clone());
    }
    let matching = request.previous.filter(|previous| {
        DELIVERY_KEYS
            .iter()
            .all(|field| py_eq_opt(previous.get(*field), candidate.get(*field)))
    });
    let previous_sequence = matching
        .and_then(|previous| previous.get("sequence"))
        .and_then(python_int);
    let sequence = match previous_sequence {
        Some(token) => increment(token).ok_or("invalid_policy_bundle_acknowledgement")?,
        None => Value::from(1),
    };
    let applied = request.status == "applied"
        || matching.is_some_and(|previous| {
            previous.get("status").and_then(Value::as_str) == Some("applied")
        });
    let observed =
        normalized_observed_at(request.synced_at).ok_or("invalid_policy_bundle_acknowledgement")?;
    let mut ack = candidate;
    ack.insert(
        "appliedExtensionAuthorityRevision".to_owned(),
        revision.clone(),
    );
    ack.insert(
        "appliedEffectiveProjectionDigest".to_owned(),
        digest.clone(),
    );
    ack.insert(
        "contractVersion".to_owned(),
        Value::String(CONTRACT.to_owned()),
    );
    ack.insert("sequence".to_owned(), sequence);
    ack.insert(
        "status".to_owned(),
        Value::String(if applied { "applied" } else { "validated" }.to_owned()),
    );
    ack.insert("observedAt".to_owned(), Value::String(observed));
    ack.insert("errorCode".to_owned(), Value::Null);
    validate_ack(&ack, matching).map_err(str::to_owned)?;
    Ok(ack)
}

pub(crate) struct EffectiveRequest<'a> {
    pub(crate) device_id: &'a str,
    pub(crate) device_name: &'a str,
    pub(crate) effective: &'a Obj,
    pub(crate) validated: Option<&'a Obj>,
    pub(crate) delivery: Option<&'a Obj>,
    pub(crate) stored: Option<&'a Obj>,
    pub(crate) synced_at: &'a str,
}

fn base<'a>(
    request: &EffectiveRequest<'a>,
    device_id: &'a str,
    previous: Option<&'a Obj>,
    delivery: Option<&'a Obj>,
) -> AckRequest<'a> {
    AckRequest {
        device_id,
        device_name: request.device_name,
        bundle: request.effective,
        synced_at: request.synced_at,
        status: "applied",
        previous,
        delivery,
        applied_revision: None,
        applied_digest: None,
    }
}

/// `effective_policy_bundle_acknowledgement`.
pub(crate) fn effective_ack(request: &EffectiveRequest) -> Result<Obj, String> {
    if request
        .effective
        .get("contractVersion")
        .and_then(Value::as_str)
        != Some(CONTRACT)
    {
        return ack_payload(&base(request, request.device_id, None, None));
    }
    let activating = request.validated.is_some_and(|validated| {
        py_eq(
            request.effective.get("bundleHash").unwrap_or(&Value::Null),
            validated.get("bundleHash").unwrap_or(&Value::Null),
        )
    });
    if !activating {
        return Ok(request.stored.cloned().unwrap_or_default());
    }
    let delivered = request
        .delivery
        .and_then(|delivery| delivery.get("deviceId"))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty());
    ack_payload(&base(
        request,
        delivered.unwrap_or(request.device_id),
        request.stored,
        request.delivery,
    ))
}
