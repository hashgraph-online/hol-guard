//! v2 policy bundle authority: canonical hashes, signature verification and the
//! ordered envelope checks (`validated_policy_bundle_v2_payload`).

use std::cmp::Ordering;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::policy_bundle_crypto::{parse_public_key, strict_base64_decode, verify_pss, SaltMode};
use crate::policy_bundle_json::{v2_canonical_bytes, v2_check, MAX_BYTES};
use crate::policy_bundle_keys::{key_is_current, key_is_trusted, resolve_key, Key};
use crate::policy_bundle_py::{
    int_cmp, int_token, is_int, is_sha256_digest, obj, py_eq, py_eq_opt, strict_non_empty, Obj,
};
use crate::policy_bundle_time::strict_utc_micros;

pub(crate) const CONTRACT: &str = "guard-policy-bundle.v2";
const DEFAULT_STRING_MAX: usize = 1_048_576;
const TOP_LEVEL: [&str; 12] = [
    "envelopeVersion",
    "contractVersion",
    "bundleVersion",
    "bundleHash",
    "payloadHash",
    "issuedAt",
    "expiresAt",
    "workspaceId",
    "canonicalization",
    "verifier",
    "payload",
    "rollback",
];
const ROLLBACK_KEYS: [&str; 8] = [
    "rollbackOfBundleHash",
    "rollbackOfBundleVersion",
    "lastGoodBundleHash",
    "lastGoodBundleVersion",
    "reason",
    "actor",
    "createdAt",
    "authorization",
];
const VERIFIER_KEYS: [&str; 5] = [
    "algorithm",
    "keyId",
    "keyFingerprint",
    "publicKeyPem",
    "signature",
];

/// Policy-document hash computed by Python (`parse_policy_document_yaml` stays
/// there); `Failed` mirrors a `PolicyDocumentError`/`ValueError`.
pub(crate) enum Evidence {
    Hash(String),
    Failed,
}

pub(crate) enum Outcome {
    Accepted,
    NeedsEvidence,
    Rejected(String),
}

pub(crate) struct Authority<'a> {
    pub(crate) trusted: &'a [Key],
    pub(crate) anchored: &'a [Key],
    pub(crate) now_micros: i64,
    pub(crate) key_now: f64,
}

fn reject(code: &str) -> Outcome {
    Outcome::Rejected(code.to_owned())
}

fn known_keys(value: &Obj, allowed: &[&str]) -> bool {
    value
        .keys()
        .all(|key| allowed.contains(&key.as_str()) || key.starts_with("x-"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `_unsigned_bundle_core`.
fn unsigned_core(bundle: &Obj) -> Result<Value, String> {
    let whole = Value::Object(bundle.clone());
    v2_check(&whole, 0).map_err(str::to_owned)?;
    let mut core = bundle.clone();
    core.remove("bundleHash");
    let Some(Value::Object(verifier)) = core.get("verifier") else {
        return Err("invalid_verifier".to_owned());
    };
    let mut normalized = verifier.clone();
    normalized.remove("signature");
    normalized.remove("publicKeyPem");
    core.insert("verifier".to_owned(), Value::Object(normalized));
    Ok(Value::Object(core))
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    v2_canonical_bytes(value).map_err(str::to_owned)
}

/// `computed_policy_bundle_v2_hash`.
pub(crate) fn bundle_hash(bundle: &Obj) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        sha256_hex(&canonical(&unsigned_core(bundle)?)?)
    ))
}

/// `canonical_policy_bundle_v2_payload`.
pub(crate) fn canonical_payload(bundle: &Obj) -> Result<Vec<u8>, String> {
    let Value::Object(mut core) = unsigned_core(bundle)? else {
        return Err("invalid_bundle".to_owned());
    };
    let Some(hash) = strict_non_empty(bundle.get("bundleHash"), 128) else {
        return Err("missing_bundle_hash".to_owned());
    };
    core.insert("bundleHash".to_owned(), Value::String(hash.to_owned()));
    canonical(&Value::Object(core))
}

fn int_at_least_one(value: Option<&Value>) -> bool {
    value
        .and_then(int_token)
        .is_some_and(|token| int_cmp(token, "1") != Ordering::Less)
}

fn rollback_error(value: Option<&Value>) -> bool {
    let rollback = match value {
        None | Some(Value::Null) => return false,
        Some(Value::Object(rollback)) if known_keys(rollback, &ROLLBACK_KEYS) => rollback,
        Some(_) => return true,
    };
    let required = [
        "rollbackOfBundleHash",
        "lastGoodBundleHash",
        "reason",
        "actor",
        "createdAt",
        "authorization",
    ];
    required
        .iter()
        .any(|key| strict_non_empty(rollback.get(*key), DEFAULT_STRING_MAX).is_none())
        || !is_sha256_digest(rollback.get("rollbackOfBundleHash"))
        || !is_sha256_digest(rollback.get("lastGoodBundleHash"))
        || !int_at_least_one(rollback.get("rollbackOfBundleVersion"))
        || !int_at_least_one(rollback.get("lastGoodBundleVersion"))
        || rollback
            .get("createdAt")
            .and_then(Value::as_str)
            .and_then(strict_utc_micros)
            .is_none()
}

fn verify_signature(bundle: &Obj, authority: &Authority) -> Result<(), &'static str> {
    let Some(verifier) =
        obj(bundle.get("verifier")).filter(|item| known_keys(item, &VERIFIER_KEYS))
    else {
        return Err("invalid_verifier");
    };
    if verifier.get("algorithm").and_then(Value::as_str) != Some("rsa-pss-sha256") {
        return Err("invalid_verifier");
    }
    let key_id = strict_non_empty(verifier.get("keyId"), 128);
    let signature = strict_non_empty(verifier.get("signature"), DEFAULT_STRING_MAX);
    let (Some(key_id), Some(signature)) = (key_id, signature) else {
        return Err("invalid_verifier");
    };
    let key = resolve_key(key_id, authority.trusted).ok_or("untrusted_signing_key")?;
    if !key_is_trusted(key, authority.anchored) || !key_is_current(key, authority.key_now, false) {
        return Err("untrusted_signing_key");
    }
    if verifier
        .get("keyFingerprint")
        .filter(|value| !value.is_null())
        .is_some_and(|fingerprint| !py_eq(fingerprint, &Value::String(key.fingerprint.clone())))
    {
        return Err("untrusted_signing_key");
    }
    if verifier
        .get("publicKeyPem")
        .filter(|value| !value.is_null())
        .is_some_and(|pem| !py_eq(pem, &Value::String(key.public_key_pem.clone())))
    {
        return Err("untrusted_signing_key");
    }
    let parsed = parse_public_key(&key.public_key_pem).map_err(|_| "invalid_verifier")?;
    let bytes = strict_base64_decode(signature).ok_or("invalid_verifier")?;
    let message = canonical_payload(bundle).map_err(|_| "bundle_signature_invalid")?;
    if verify_pss(&parsed, &bytes, &message, SaltMode::Maximum) {
        Ok(())
    } else {
        Err("bundle_signature_invalid")
    }
}

fn check_envelope(bundle: &Obj, authority: &Authority) -> Result<(), &'static str> {
    if !known_keys(bundle, &TOP_LEVEL) {
        return Err("unknown_field");
    }
    let required = TOP_LEVEL
        .iter()
        .filter(|key| !matches!(**key, "expiresAt" | "rollback"));
    if required.into_iter().any(|key| !bundle.contains_key(*key)) {
        return Err("missing_required_field");
    }
    let envelope = bundle.get("envelopeVersion");
    if !envelope.is_some_and(|value| py_eq(value, &Value::from(2))) {
        return Err("unsupported_envelope_version");
    }
    if bundle.get("contractVersion").and_then(Value::as_str) != Some(CONTRACT) {
        return Err("unsupported_contract_version");
    }
    if !int_at_least_one(bundle.get("bundleVersion")) {
        return Err("invalid_bundle_version");
    }
    if strict_non_empty(bundle.get("workspaceId"), 128).is_none() {
        return Err("invalid_workspace_id");
    }
    let expected = serde_json::json!({"algorithm": "rfc8785", "version": "1"});
    if !bundle
        .get("canonicalization")
        .is_some_and(|value| py_eq(value, &expected))
    {
        return Err("unsupported_canonicalization");
    }
    let issued = bundle
        .get("issuedAt")
        .and_then(Value::as_str)
        .and_then(strict_utc_micros)
        .ok_or("invalid_issued_at")?;
    let expires = match bundle.get("expiresAt") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let parsed = value
                .as_str()
                .and_then(strict_utc_micros)
                .ok_or("invalid_expires_at")?;
            if parsed <= issued {
                return Err("invalid_expires_at");
            }
            Some(parsed)
        }
    };
    if expires.is_some_and(|expires| expires <= authority.now_micros) {
        return Err("bundle_expired");
    }
    if rollback_error(bundle.get("rollback")) {
        return Err("invalid_rollback");
    }
    Ok(())
}

/// `validated_policy_bundle_v2_payload`. `NeedsEvidence` asks the caller for the
/// canonical policy-document hash and to call again with it.
pub(crate) fn validate(
    value: &Value,
    authority: &Authority,
    evidence: Option<&Evidence>,
) -> Outcome {
    let Value::Object(bundle) = value else {
        return reject("invalid_json_value");
    };
    if let Err(code) = v2_check(value, 0) {
        return reject(code);
    }
    match v2_canonical_bytes(value) {
        Ok(encoded) if encoded.len() > MAX_BYTES => return reject("limit_bytes"),
        Ok(_) => {}
        Err(code) => return reject(code),
    }
    if let Err(code) = check_envelope(bundle, authority) {
        return reject(code);
    }
    if !matches!(bundle.get("payload"), Some(Value::Object(_))) {
        return reject("invalid_policy_document");
    }
    let expected = match evidence {
        None => return Outcome::NeedsEvidence,
        Some(Evidence::Failed) => return reject("invalid_policy_document"),
        Some(Evidence::Hash(hash)) => hash,
    };
    if !py_eq_opt(
        bundle.get("payloadHash"),
        Some(&Value::String(expected.clone())),
    ) {
        return reject("payload_hash_mismatch");
    }
    let Ok(expected_bundle) = bundle_hash(bundle) else {
        return reject("invalid_bundle");
    };
    if !py_eq_opt(
        bundle.get("bundleHash"),
        Some(&Value::String(expected_bundle)),
    ) {
        return reject("bundle_hash_mismatch");
    }
    match verify_signature(bundle, authority) {
        Ok(()) => Outcome::Accepted,
        Err(code) => reject(code),
    }
}

/// `validate_policy_bundle_v2_transition`.
pub(crate) struct Transition<'a> {
    pub(crate) current_version: Option<&'a Value>,
    pub(crate) current_hash: Option<&'a Value>,
    pub(crate) expected_last_good_version: Option<&'a Value>,
    pub(crate) expected_last_good_hash: Option<&'a Value>,
}

pub(crate) fn transition_error(bundle: &Obj, state: &Transition) -> Option<&'static str> {
    let version = bundle.get("bundleVersion");
    if !is_int(version) {
        return Some("invalid_bundle_version");
    }
    let Some(Value::String(hash)) = bundle.get("bundleHash") else {
        return Some("invalid_bundle_hash");
    };
    let current = state.current_version?;
    let Some(current_hash) = state.current_hash else {
        return Some("missing_current_bundle_hash");
    };
    let (incoming, current_token) = (version.and_then(int_token)?, int_token(current)?);
    match int_cmp(incoming, current_token) {
        Ordering::Less => return Some("bundle_downgrade_rejected"),
        Ordering::Equal => {
            return (!py_eq(&Value::String(hash.clone()), current_hash))
                .then_some("bundle_version_conflict");
        }
        Ordering::Greater => {}
    }
    let rollback = match bundle.get("rollback") {
        None | Some(Value::Null) => return None,
        Some(Value::Object(rollback)) => rollback,
        Some(_) => return Some("invalid_rollback"),
    };
    if !py_eq_opt(rollback.get("rollbackOfBundleHash"), Some(current_hash))
        || !py_eq_opt(rollback.get("rollbackOfBundleVersion"), Some(current))
    {
        return Some("rollback_target_mismatch");
    }
    let last_good = rollback.get("lastGoodBundleVersion");
    let Some(last_good_token) = last_good.and_then(int_token) else {
        return Some("rollback_target_mismatch");
    };
    if int_cmp(last_good_token, current_token) != Ordering::Less
        || strict_non_empty(rollback.get("lastGoodBundleHash"), 128).is_none()
    {
        return Some("rollback_target_mismatch");
    }
    if state
        .expected_last_good_version
        .filter(|value| !value.is_null())
        .is_some_and(|expected| !py_eq_opt(last_good, Some(expected)))
    {
        return Some("rollback_last_good_mismatch");
    }
    if state
        .expected_last_good_hash
        .filter(|value| !value.is_null())
        .is_some_and(|expected| !py_eq_opt(rollback.get("lastGoodBundleHash"), Some(expected)))
    {
        return Some("rollback_last_good_mismatch");
    }
    if strict_non_empty(rollback.get("authorization"), DEFAULT_STRING_MAX).is_none() {
        return Some("rollback_authorization_missing");
    }
    None
}
