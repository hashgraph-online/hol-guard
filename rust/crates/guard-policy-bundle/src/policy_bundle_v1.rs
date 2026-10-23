//! v1 policy bundle authority: integrity hashes, signature verification and the
//! ordered acceptance checks (`validated_policy_bundle_payload`).

use std::cmp::Ordering;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::policy_bundle_crypto::{parse_public_key, strict_base64_decode, verify_pss, SaltMode};
use crate::policy_bundle_json::{stable_serialize, v1_resource_limit_error};
use crate::policy_bundle_keys::{key_fingerprint, resolve_authorized, Key};
use crate::policy_bundle_py::{
    in_set, int_cmp, is_int, non_empty, py_eq_opt, version_cmp, version_tuple, Obj,
};
use crate::policy_bundle_time::v1_timestamp;
use crate::policy_bundle_v1_rules::{
    acknowledgement_is_valid, cloud_exceptions_are_valid, defaults_are_valid,
    redaction_level_is_valid, rule_is_valid, ENFORCEABLE_ROLLOUT_STATES, ROLLOUT_STATES,
};

pub(crate) const CONTRACT: &str = "guard-policy-bundle.v1";
const CORE_KEYS: [&str; 8] = [
    "contractVersion",
    "bundleVersion",
    "issuedAt",
    "expiresAt",
    "verifier",
    "rolloutState",
    "policyDefaults",
    "rules",
];
const CLOCK_SKEW_SECONDS: f64 = 300.0;

/// What the Python shim needs to rebuild the accepted payload dict.
pub(crate) struct Accepted {
    pub(crate) keys: Vec<&'static str>,
    pub(crate) payload_hash: String,
}

pub(crate) struct Authority<'a> {
    pub(crate) trusted: &'a [Key],
    pub(crate) anchored: &'a [Key],
    pub(crate) expected_workspace: Option<&'a str>,
    pub(crate) now: f64,
    pub(crate) daemon_version: &'a str,
}

/// `_policy_bundle_core`; the error is the Python `ValueError` message.
pub(crate) fn core(bundle: &Obj, drop_pem_when_unsupported: bool) -> Result<Obj, String> {
    let mut core = Obj::new();
    for key in CORE_KEYS {
        let Some(value) = bundle.get(key) else {
            return Err(format!("missing_policy_bundle_key:{key}"));
        };
        core.insert(key.to_owned(), value.clone());
    }
    if let Some(level) = bundle.get("receiptRedactionLevel") {
        core.insert("receiptRedactionLevel".to_owned(), level.clone());
    }
    if let Some(Value::Object(verifier)) = core.get("verifier") {
        let mut normalized = verifier.clone();
        if verifier.get("algorithm").and_then(Value::as_str) == Some("rsa-pss-sha256") {
            normalized.insert("publicKeyPem".to_owned(), Value::Null);
        } else if drop_pem_when_unsupported {
            normalized.remove("publicKeyPem");
        }
        normalized.insert("signature".to_owned(), Value::Null);
        core.insert("verifier".to_owned(), Value::Object(normalized));
    }
    if let Some(workspace) = bundle.get("workspaceId").filter(|value| !value.is_null()) {
        core.insert("workspaceId".to_owned(), workspace.clone());
    }
    if let Some(version) = non_empty(bundle.get("minDaemonVersion")) {
        core.insert(
            "minDaemonVersion".to_owned(),
            Value::String(version.to_owned()),
        );
    }
    Ok(core)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn serialize(value: Obj) -> Result<String, String> {
    stable_serialize(&Value::Object(value)).map_err(str::to_owned)
}

/// `computed_policy_bundle_hash`.
pub(crate) fn bundle_hash(bundle: &Obj) -> Result<String, String> {
    let text = serialize(core(bundle, true)?)?;
    Ok(format!("sha256:{}", sha256_hex(text.as_bytes())))
}

/// `canonical_policy_bundle_payload`.
pub(crate) fn canonical_payload(bundle: &Obj) -> Result<Vec<u8>, String> {
    let mut core = core(bundle, false)?;
    match bundle.get("acknowledgements") {
        None | Some(Value::Null) => {
            return Err("missing_policy_bundle_key:acknowledgements".to_owned())
        }
        Some(value) => core.insert("acknowledgements".to_owned(), value.clone()),
    };
    if let Some(exceptions) = bundle
        .get("cloudExceptions")
        .filter(|value| !value.is_null())
    {
        core.insert("cloudExceptions".to_owned(), exceptions.clone());
    }
    Ok(serialize(core)?.into_bytes())
}

/// `payload_hash_for_policy_bundle`.
pub(crate) fn payload_hash(bundle: &Obj) -> Result<String, String> {
    Ok(sha256_hex(&canonical_payload(bundle)?))
}

/// `policy_bundle_daemon_version_supported`.
pub(crate) fn daemon_version_supported(bundle: &Obj, current: &str) -> bool {
    let Some(minimum) = non_empty(bundle.get("minDaemonVersion")) else {
        return true;
    };
    match (version_tuple(current), version_tuple(minimum)) {
        (Some(current), Some(minimum)) => version_cmp(&current, &minimum) != Ordering::Less,
        _ => false,
    }
}

/// `policy_bundle_is_enforceable`.
pub(crate) fn is_enforceable(bundle: &Obj) -> bool {
    bundle.get("contractVersion").and_then(Value::as_str) == Some("guard-policy-bundle.v2")
        || in_set(bundle.get("rolloutState"), &ENFORCEABLE_ROLLOUT_STATES)
}

fn verify_signature(bundle: &Obj, payload: &[u8], authority: &Authority) -> Option<&'static str> {
    let Some(Value::Object(verifier)) = bundle.get("verifier") else {
        return Some("invalid_verifier");
    };
    if verifier.get("algorithm").and_then(Value::as_str) != Some("rsa-pss-sha256") {
        return Some("unsupported_signature_algorithm");
    }
    let key_id = non_empty(verifier.get("keyId"));
    let signature = non_empty(verifier.get("signature"));
    let Some(key_id) = key_id else {
        return Some("missing_signing_key_id");
    };
    let Some(signature) = signature else {
        return Some("missing_signature");
    };
    let key = match resolve_authorized(
        key_id,
        authority.trusted,
        authority.anchored,
        authority.expected_workspace,
        authority.now,
    ) {
        Ok(key) => key,
        Err(code) => return Some(code),
    };
    if let Some(bundled) = verifier
        .get("publicKeyPem")
        .filter(|value| !value.is_null())
    {
        let Some(pem) = non_empty(Some(bundled)) else {
            return Some("invalid_verifier");
        };
        if key_fingerprint(pem) != key.fingerprint {
            return Some("signing_key_fingerprint_mismatch");
        }
    }
    if let Some(embedded) = verifier
        .get("fingerprintSha256")
        .filter(|value| !value.is_null())
    {
        match non_empty(Some(embedded)) {
            None => return Some("invalid_verifier"),
            Some(fingerprint) if fingerprint != key.fingerprint => {
                return Some("signing_key_fingerprint_mismatch");
            }
            Some(_) => {}
        }
    }
    let Ok(parsed) = parse_public_key(&key.public_key_pem) else {
        return Some("invalid_verifier");
    };
    let Some(signature_bytes) = strict_base64_decode(signature) else {
        return Some("invalid_signature_encoding");
    };
    if verify_pss(&parsed, &signature_bytes, payload, SaltMode::Auto) {
        None
    } else {
        Some("bundle_signature_invalid")
    }
}

fn check_freshness(bundle: &Obj, now: f64) -> Result<(), &'static str> {
    let issued = non_empty(bundle.get("issuedAt")).ok_or("invalid_issued_at")?;
    let issued = v1_timestamp(issued).ok_or("invalid_issued_at")?;
    let expires = match bundle.get("expiresAt") {
        None | Some(Value::Null) => None,
        other => {
            let text = non_empty(other).ok_or("invalid_expires_at")?;
            let parsed = v1_timestamp(text).ok_or("invalid_expires_at")?;
            if parsed <= issued {
                return Err("invalid_expires_at");
            }
            Some(parsed)
        }
    };
    if issued > now + CLOCK_SKEW_SECONDS {
        return Err("bundle_not_yet_valid");
    }
    if expires.is_some_and(|expires| now > expires) {
        return Err("bundle_expired");
    }
    Ok(())
}

fn check_verifier_shape(verifier: Option<&Value>) -> Result<(), &'static str> {
    let Some(Value::Object(verifier)) = verifier else {
        return Err("invalid_verifier");
    };
    if verifier.get("algorithm").and_then(Value::as_str) != Some("rsa-pss-sha256") {
        return Err("unsupported_signature_algorithm");
    }
    if non_empty(verifier.get("keyId")).is_none() {
        return Err("missing_signing_key_id");
    }
    if non_empty(verifier.get("signature")).is_none() {
        return Err("missing_signature");
    }
    Ok(())
}

fn check_schema(bundle: &Obj, authority: &Authority) -> Result<(), &'static str> {
    if let Some(version) = bundle.get("minDaemonVersion") {
        let minimum = non_empty(Some(version)).and_then(version_tuple);
        if minimum.is_none() {
            return Err("invalid_min_daemon_version");
        }
        if !daemon_version_supported(bundle, authority.daemon_version) {
            return Err("unsupported_daemon_version");
        }
    }
    if bundle.contains_key("receiptRedactionLevel")
        && !redaction_level_is_valid(bundle.get("receiptRedactionLevel"))
    {
        return Err("invalid_receipt_redaction_level");
    }
    if !in_set(bundle.get("rolloutState"), &ROLLOUT_STATES) {
        return Err("invalid_rollout_state");
    }
    if !defaults_are_valid(bundle.get("policyDefaults")) {
        return Err("invalid_policy_defaults");
    }
    match bundle.get("rules") {
        Some(Value::Array(rules)) if rules.iter().all(rule_is_valid) => {}
        _ => return Err("invalid_rules"),
    }
    if !cloud_exceptions_are_valid(bundle) {
        return Err("invalid_cloud_exceptions");
    }
    match bundle.get("acknowledgements") {
        Some(Value::Array(items)) if items.iter().all(acknowledgement_is_valid) => Ok(()),
        _ => Err("invalid_acknowledgements"),
    }
}

fn accepted_keys(bundle: &Obj) -> Vec<&'static str> {
    let mut keys = vec![
        "contractVersion",
        "bundleVersion",
        "bundleHash",
        "issuedAt",
        "expiresAt",
    ];
    if non_empty(bundle.get("minDaemonVersion")).is_some() {
        keys.push("minDaemonVersion");
    }
    keys.extend([
        "verifier",
        "rolloutState",
        "policyDefaults",
        "rules",
        "acknowledgements",
    ]);
    if bundle.contains_key("receiptRedactionLevel") {
        keys.push("receiptRedactionLevel");
    }
    if matches!(bundle.get("cloudExceptions"), Some(Value::Array(_))) {
        keys.push("cloudExceptions");
    }
    keys.push("payloadHash");
    if bundle
        .get("workspaceId")
        .is_some_and(|value| !value.is_null())
    {
        keys.push("workspaceId");
    }
    keys
}

/// `validated_policy_bundle_payload`.
pub(crate) fn validate(value: &Value, authority: &Authority) -> Result<Accepted, String> {
    if let Some(code) = v1_resource_limit_error(value) {
        return Err(code.to_owned());
    }
    let Value::Object(bundle) = value else {
        return Err("missing_required_field".to_owned());
    };
    if CORE_KEYS
        .iter()
        .chain(["bundleHash", "acknowledgements"].iter())
        .any(|key| !bundle.contains_key(*key))
    {
        return Err("missing_required_field".to_owned());
    }
    if bundle.get("contractVersion").and_then(Value::as_str) != Some(CONTRACT) {
        return Err("unsupported_contract_version".to_owned());
    }
    if non_empty(bundle.get("bundleVersion")).is_none() {
        return Err("invalid_bundle_version".to_owned());
    }
    check_freshness(bundle, authority.now)?;
    let workspace = bundle.get("workspaceId").filter(|value| !value.is_null());
    let normalized = non_empty(workspace);
    if workspace.is_some() && normalized.is_none() {
        return Err("invalid_workspace_id".to_owned());
    }
    check_verifier_shape(bundle.get("verifier"))?;
    match (normalized, authority.expected_workspace) {
        (Some(actual), Some(expected)) if actual == expected => {}
        _ => return Err("wrong_workspace".to_owned()),
    }
    check_schema(bundle, authority)?;
    let canonical = canonical_payload(bundle)?;
    let computed = sha256_hex(&canonical);
    let stated = non_empty(bundle.get("payloadHash"));
    let Some(stated) = stated.filter(|text| crate::policy_bundle_py::py_strip(text) == *text)
    else {
        return Err("invalid_payload_hash".to_owned());
    };
    let lowered = stated.to_lowercase();
    if lowered != computed && lowered != format!("sha256:{computed}") {
        return Err("payload_hash_mismatch".to_owned());
    }
    let Some(stated_hash) = non_empty(bundle.get("bundleHash")) else {
        return Err("invalid_bundle_hash".to_owned());
    };
    if stated_hash != bundle_hash(bundle)? {
        return Err("bundle_hash_mismatch".to_owned());
    }
    if let Some(code) = verify_signature(bundle, &canonical, authority) {
        return Err(code.to_owned());
    }
    Ok(Accepted {
        keys: accepted_keys(bundle),
        payload_hash: computed,
    })
}

/// `policy_bundle_is_version_downgrade`.
pub(crate) fn is_downgrade(accepted: &Value, candidate: &Obj) -> bool {
    let Value::Object(accepted) = accepted else {
        return false;
    };
    if accepted.is_empty() {
        return false;
    }
    let (accepted_version, candidate_version) = (
        accepted.get("bundleVersion"),
        candidate.get("bundleVersion"),
    );
    if is_int(accepted_version) && is_int(candidate_version) {
        let (old, new) = (token(accepted_version), token(candidate_version));
        return match int_cmp(new, old) {
            Ordering::Equal => !py_eq_opt(accepted.get("bundleHash"), candidate.get("bundleHash")),
            order => order == Ordering::Less,
        };
    }
    is_downgrade_legacy(accepted, candidate)
}

fn token(value: Option<&Value>) -> &str {
    match value {
        Some(Value::Number(number)) => number.as_str(),
        _ => "0",
    }
}

fn field<'a>(bundle: &'a Obj, key: &str) -> Option<&'a str> {
    non_empty(bundle.get(key))
}

fn is_downgrade_legacy(accepted: &Obj, candidate: &Obj) -> bool {
    let (old_workspace, new_workspace) = (
        non_empty(accepted.get("workspaceId")),
        non_empty(candidate.get("workspaceId")),
    );
    if matches!((old_workspace, new_workspace), (Some(old), Some(new)) if old != new) {
        return false;
    }
    let (old_bundle, new_bundle) = (
        field(accepted, "bundleHash"),
        field(candidate, "bundleHash"),
    );
    let (old_payload, new_payload) = (
        field(accepted, "payloadHash"),
        field(candidate, "payloadHash"),
    );
    if old_bundle.is_some()
        && old_bundle == new_bundle
        && (old_payload.is_some() && old_payload == new_payload
            || old_payload.is_none() && new_payload.is_none())
    {
        return false;
    }
    let (Some(old_issued), Some(new_issued)) =
        (field(accepted, "issuedAt"), field(candidate, "issuedAt"))
    else {
        return true;
    };
    let (Some(old_time), Some(new_time)) = (v1_timestamp(old_issued), v1_timestamp(new_issued))
    else {
        return true;
    };
    if new_time != old_time {
        return new_time < old_time;
    }
    let (Some(old_version), Some(new_version)) = (
        field(accepted, "bundleVersion"),
        field(candidate, "bundleVersion"),
    ) else {
        return true;
    };
    match (version_tuple(old_version), version_tuple(new_version)) {
        (Some(old), Some(new)) => version_cmp(&new, &old) != Ordering::Greater,
        _ => old_version != new_version || old_bundle != new_bundle || old_payload != new_payload,
    }
}
