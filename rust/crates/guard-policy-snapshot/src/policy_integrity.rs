//! `policy_integrity.py` — canonical signing + verification for persisted
//! policy `policy_decisions` rows. Ported byte-identically: the signed payload
//! is `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
//! of a 11/15-field envelope, hashed with SHA-256, MAC'd with a *raw* 2-arg
//! `hmac.new(key, payload, sha256)` (no purpose derivation — unlike
//! `local_authority_integrity`).

use serde_json::Value;

use crate::crypto::{constant_time_eq, digest_bytes, hmac_sha256_raw};

pub const POLICY_INTEGRITY_VERSION: i64 = 2;
pub const LEGACY_POLICY_INTEGRITY_VERSION: i64 = 1;
pub const POLICY_INTEGRITY_MAC_ALGORITHM: &str = "hmac-sha256";

/// `REMOTE_POLICY_SOURCES` (:16-22) — rows signed remotely are trusted without
/// local HMAC verification.
pub const REMOTE_POLICY_SOURCES: [&str; 5] = [
    "cloud-signed-memory",
    "cloud-sync",
    "policy-bundle",
    "policy-bundle-canonical",
    "team-policy",
];

/// `is_remote_policy_source` (:38-39).
pub fn is_remote_policy_source(source: Option<&str>) -> bool {
    match source {
        Some(s) => REMOTE_POLICY_SOURCES.contains(&s),
        None => false,
    }
}

/// `PolicyIntegrityVerificationResult` (:24-35).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIntegrityVerification {
    pub status: &'static str,
    pub payload_hash: Option<String>,
    pub key_id: Option<String>,
    pub message: Option<&'static str>,
    /// `rollback_detected` rows expose the stored generation for diagnostics.
    pub generation: Option<i64>,
}

/// `_string_or_none` (:196-197) — non-empty strings only.
fn string_or_none(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// `_int_or_none` (:199-209) — bools coerce, numeric strings parse, floats and
/// other types do not.
fn int_or_none(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(b) => Some(i64::from(*b)),
        Value::Number(n) => n.as_i64().filter(|_| !n.is_f64()),
        Value::String(s) => {
            let stripped = s.trim();
            if !stripped.is_empty() && stripped.bytes().all(|b| b.is_ascii_digit()) {
                stripped.parse::<i64>().ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `_mapping_value` / `row[key] -> None` on missing.
fn mapping_value(row: &Value, key: &str) -> Value {
    row.get(key).cloned().unwrap_or(Value::Null)
}

/// `canonical_policy_payload` (:42-74) — the signed bytes.
///
/// `None` when the row is not serializable into the canonical envelope
/// (non-finite floats, etc.), matching the Python `json.dumps` failure mode
/// the call sites treat as unverifiable.
pub fn canonical_policy_payload(row: &Value, integrity_version: Option<i64>) -> Option<Vec<u8>> {
    let resolved_version = integrity_version.or_else(|| {
        int_or_none(&mapping_value(row, "integrity_version")).or(Some(POLICY_INTEGRITY_VERSION))
    })?;
    let mut payload = serde_json::json!({
        "action": string_or_none(&mapping_value(row, "action")),
        "artifact_hash": string_or_none(&mapping_value(row, "artifact_hash")),
        "artifact_id": string_or_none(&mapping_value(row, "artifact_id")),
        "expires_at": string_or_none(&mapping_value(row, "expires_at")),
        "harness": string_or_none(&mapping_value(row, "harness")),
        "integrity_version": resolved_version,
        "publisher": string_or_none(&mapping_value(row, "publisher")),
        "scope": string_or_none(&mapping_value(row, "scope")),
        "source": string_or_none(&mapping_value(row, "source")),
        "updated_at": string_or_none(&mapping_value(row, "updated_at")),
        "workspace": string_or_none(&mapping_value(row, "workspace")),
    });
    if resolved_version == POLICY_INTEGRITY_VERSION {
        payload["decision_id"] =
            int_or_none(&mapping_value(row, "decision_id")).map_or(Value::Null, Value::from);
        payload["integrity_generation"] = int_or_none(&mapping_value(row, "integrity_generation"))
            .map_or(Value::Null, Value::from);
        payload["owner"] =
            string_or_none(&mapping_value(row, "owner")).map_or(Value::Null, Value::from);
        payload["reason"] =
            string_or_none(&mapping_value(row, "reason")).map_or(Value::Null, Value::from);
    }
    let mut out = Vec::new();
    guard_contracts::write_canonical_json_with_limit(
        &payload,
        &mut out,
        256 * 1024,
        "policy_integrity_payload_too_large",
    )
    .ok()?;
    Some(out)
}

/// `sign_local_policy_row` (:76-94) — the six integrity columns.
pub fn sign_local_policy_row(
    row: &Value,
    key: &[u8],
    key_id: &str,
    signed_at: &str,
    generation: i64,
) -> Result<Value, &'static str> {
    let mut signing_row = row.clone();
    signing_row["integrity_generation"] = Value::from(generation);
    let payload = canonical_policy_payload(&signing_row, Some(POLICY_INTEGRITY_VERSION))
        .ok_or("policy_row_unserializable")?;
    let payload_hash = digest_bytes(&payload);
    let payload_mac = hex::encode(hmac_sha256_raw(key, &payload));
    Ok(serde_json::json!({
        "integrity_version": POLICY_INTEGRITY_VERSION,
        "integrity_generation": generation,
        "payload_hash": payload_hash,
        "payload_mac": payload_mac,
        "integrity_key_id": key_id,
        "signed_at": signed_at,
    }))
}

/// `verify_local_policy_row` (:96-176).
pub fn verify_local_policy_row(
    row: &Value,
    key: Option<&[u8]>,
    key_id: Option<&str>,
    degraded_mode: bool,
    trusted_generation: Option<i64>,
) -> PolicyIntegrityVerification {
    let stored_key_id = string_or_none(&mapping_value(row, "integrity_key_id"));
    let stored_payload_hash = string_or_none(&mapping_value(row, "payload_hash"));
    let stored_payload_mac = string_or_none(&mapping_value(row, "payload_mac"));
    let stored_signed_at = string_or_none(&mapping_value(row, "signed_at"));
    let version = int_or_none(&mapping_value(row, "integrity_version"));

    if degraded_mode {
        return PolicyIntegrityVerification {
            status: "degraded_mode",
            payload_hash: stored_payload_hash,
            key_id: stored_key_id,
            message: Some("policy_integrity_backend_unavailable"),
            generation: int_or_none(&mapping_value(row, "integrity_generation")),
        };
    }
    if version.is_none()
        || stored_key_id.is_none()
        || stored_payload_hash.is_none()
        || stored_payload_mac.is_none()
        || stored_signed_at.is_none()
    {
        return PolicyIntegrityVerification {
            status: "missing_integrity",
            payload_hash: stored_payload_hash,
            key_id: stored_key_id,
            message: Some("policy_integrity_metadata_missing"),
            generation: int_or_none(&mapping_value(row, "integrity_generation")),
        };
    }
    let version = version.unwrap();
    if !(version == LEGACY_POLICY_INTEGRITY_VERSION || version == POLICY_INTEGRITY_VERSION) {
        return PolicyIntegrityVerification {
            status: "tampered",
            payload_hash: stored_payload_hash,
            key_id: stored_key_id,
            message: Some("policy_integrity_version_unsupported"),
            generation: int_or_none(&mapping_value(row, "integrity_generation")),
        };
    }
    let (key, _key_id) = match (key, key_id) {
        (Some(k), Some(kid)) if stored_key_id.as_deref() == Some(kid) => (k, kid),
        _ => {
            return PolicyIntegrityVerification {
                status: "unknown_key",
                payload_hash: stored_payload_hash,
                key_id: stored_key_id,
                message: Some("policy_integrity_key_unavailable"),
                generation: int_or_none(&mapping_value(row, "integrity_generation")),
            };
        }
    };

    let payload = match canonical_policy_payload(row, Some(version)) {
        Some(p) => p,
        None => {
            return PolicyIntegrityVerification {
                status: "tampered",
                payload_hash: None,
                key_id: stored_key_id,
                message: Some("policy_integrity_payload_invalid"),
                generation: int_or_none(&mapping_value(row, "integrity_generation")),
            };
        }
    };
    let computed_payload_hash = digest_bytes(&payload);
    if !constant_time_eq(
        stored_payload_hash.as_deref().unwrap_or("").as_bytes(),
        computed_payload_hash.as_bytes(),
    ) {
        return PolicyIntegrityVerification {
            status: "tampered",
            payload_hash: Some(computed_payload_hash),
            key_id: stored_key_id,
            message: Some("policy_integrity_payload_hash_mismatch"),
            generation: int_or_none(&mapping_value(row, "integrity_generation")),
        };
    }
    let computed_payload_mac = hex::encode(hmac_sha256_raw(key, &payload));
    if !constant_time_eq(
        stored_payload_mac.as_deref().unwrap_or("").as_bytes(),
        computed_payload_mac.as_bytes(),
    ) {
        return PolicyIntegrityVerification {
            status: "tampered",
            payload_hash: Some(computed_payload_hash),
            key_id: stored_key_id,
            message: Some("policy_integrity_mac_mismatch"),
            generation: int_or_none(&mapping_value(row, "integrity_generation")),
        };
    }
    if version == POLICY_INTEGRITY_VERSION {
        if let Some(trusted) = trusted_generation {
            let stored_generation = int_or_none(&mapping_value(row, "integrity_generation"));
            if stored_generation != Some(trusted) {
                return PolicyIntegrityVerification {
                    status: "rollback_detected",
                    payload_hash: Some(computed_payload_hash),
                    key_id: stored_key_id,
                    message: Some("policy_integrity_generation_rollback"),
                    generation: stored_generation,
                };
            }
        }
    }
    PolicyIntegrityVerification {
        status: "valid",
        payload_hash: Some(computed_payload_hash),
        key_id: stored_key_id,
        message: Some(POLICY_INTEGRITY_MAC_ALGORITHM),
        generation: int_or_none(&mapping_value(row, "integrity_generation")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ORACLE: &str = include_str!("../testdata/policy_integrity_oracle.json");

    /// Byte-parity with `policy_integrity.py` `canonical_policy_payload`,
    /// `sign_local_policy_row`, and `verify_local_policy_row` across rows
    /// covering non-ASCII (`\uXXXX` ensure_ascii), nulls, and each verify
    /// branch.
    #[test]
    fn policy_integrity_python_oracle() {
        let oracle: Value = serde_json::from_str(ORACLE).expect("oracle json");
        let key = hex::decode(oracle["key_hex"].as_str().unwrap()).unwrap();
        let key_id = oracle["key_id"].as_str().unwrap();

        for case in oracle["cases"].as_array().unwrap() {
            let row = &case["row"];
            let generation = case["signature"]["integrity_generation"].as_i64().unwrap();
            let signed_at = case["signature"]["signed_at"].as_str().unwrap();

            // sign parity
            let sig =
                sign_local_policy_row(row, &key, key_id, signed_at, generation).expect("sign");
            let want = &case["signature"];
            assert_eq!(
                sig["integrity_version"].as_i64().unwrap(),
                POLICY_INTEGRITY_VERSION
            );
            assert_eq!(
                sig["integrity_generation"].as_i64().unwrap(),
                want["integrity_generation"].as_i64().unwrap()
            );
            assert_eq!(
                sig["payload_hash"].as_str().unwrap(),
                want["payload_hash"].as_str().unwrap()
            );
            assert_eq!(
                sig["payload_mac"].as_str().unwrap(),
                want["payload_mac"].as_str().unwrap()
            );
            assert_eq!(
                sig["integrity_key_id"].as_str().unwrap(),
                want["integrity_key_id"].as_str().unwrap()
            );
            assert_eq!(
                sig["signed_at"].as_str().unwrap(),
                want["signed_at"].as_str().unwrap()
            );

            // canonical byte parity
            let signed = &case["signed"];
            let canonical = canonical_policy_payload(signed, Some(POLICY_INTEGRITY_VERSION))
                .expect("canonical");
            assert_eq!(
                hex::encode(&canonical),
                case["canonical_b64"].as_str().unwrap()
            );

            // verify branches
            let branches = &case["branches"];
            assert_eq!(
                verify_local_policy_row(signed, Some(&key), Some(key_id), false, Some(generation))
                    .status,
                branches["valid"].as_str().unwrap()
            );
            assert_eq!(
                verify_local_policy_row(signed, Some(&key), Some(key_id), true, Some(generation))
                    .status,
                branches["degraded"].as_str().unwrap()
            );
            assert_eq!(
                verify_local_policy_row(
                    signed,
                    Some(&key),
                    Some(key_id),
                    false,
                    Some(generation + 1)
                )
                .status,
                branches["wrong_gen"].as_str().unwrap()
            );
            assert_eq!(
                verify_local_policy_row(signed, Some(&key), Some("other"), false, Some(generation))
                    .status,
                branches["wrong_key_id"].as_str().unwrap()
            );
            let mut tampered = signed.clone();
            tampered["payload_mac"] = json!("0".repeat(64));
            assert_eq!(
                verify_local_policy_row(
                    &tampered,
                    Some(&key),
                    Some(key_id),
                    false,
                    Some(generation)
                )
                .status,
                branches["tampered"].as_str().unwrap()
            );
        }
    }
}
