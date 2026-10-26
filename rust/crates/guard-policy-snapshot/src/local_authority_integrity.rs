//! `local_authority_integrity.py` — domain-separated integrity for local
//! approval authority that lives outside policy rows (e.g. the
//! `guard_local_once_approvals` table).
//!
//! Sign/verify are byte-identical to Python: the canonical payload is a
//! `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
//! of a domain envelope, and the MAC key is purpose-derived via
//! `HMAC(key, DOMAIN + b"\\0" + purpose)`.

use serde_json::Value;

use crate::crypto::{constant_time_eq, digest_bytes, hmac_sha256_raw};

pub const LOCAL_AUTHORITY_INTEGRITY_VERSION: u32 = 1;
pub const LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM: &str = "hmac-sha256";
pub const LOCAL_AUTHORITY_INTEGRITY_DOMAIN: &[u8] = b"hol-guard.local-authority-integrity.v1";
const LOCAL_AUTHORITY_CANONICAL_MAX_BYTES: usize = 256 * 1024;

/// `PolicyIntegrityVerificationResult` (:31-35) projected to the local
/// authority surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAuthorityVerification {
    pub status: &'static str,
    pub payload_hash: Option<String>,
    pub key_id: Option<String>,
    pub message: Option<&'static str>,
}

/// `sign_local_authority_payload` (:17-43).
///
/// `payload` is a JSON object of the signed fields (the caller includes
/// `claimed_at`/`signed_at`-style fields in it). Returns the five integrity
/// columns stored alongside the row.
pub fn sign_local_authority_payload(
    payload: &Value,
    key: &[u8],
    key_id: &str,
    purpose: &str,
    signed_at: &str,
) -> Result<SignedAuthorityFields, &'static str> {
    let canonical_payload = canonical_local_authority_payload(
        payload,
        purpose,
        signed_at,
        LOCAL_AUTHORITY_INTEGRITY_VERSION,
    )
    .ok_or("local_authority_payload_invalid")?;
    let purpose_key = purpose_key(key, purpose);
    let payload_mac = hmac_sha256_raw(&purpose_key, &canonical_payload);
    Ok(SignedAuthorityFields {
        integrity_version: LOCAL_AUTHORITY_INTEGRITY_VERSION,
        payload_hash: digest_bytes(&canonical_payload),
        payload_mac: hex::encode(payload_mac),
        integrity_key_id: key_id.to_owned(),
        signed_at: signed_at.to_owned(),
    })
}

/// The five columns `sign_local_authority_payload` returns (:31-40).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAuthorityFields {
    pub integrity_version: u32,
    pub payload_hash: String,
    pub payload_mac: String,
    pub integrity_key_id: String,
    pub signed_at: String,
}

/// `verify_local_authority_payload` (:46-128).
///
/// `integrity` is the stored integrity column set; `key`/`key_id` are the
/// current resolver outputs. Verification status is one of
/// `valid | missing_integrity | tampered | unknown_key`.
pub fn verify_local_authority_payload(
    payload: &Value,
    integrity: &Value,
    key: Option<&[u8]>,
    key_id: Option<&str>,
    purpose: &str,
) -> LocalAuthorityVerification {
    let stored_key_id = string_or_none(integrity.get("integrity_key_id"));
    let stored_payload_hash = integrity.get("payload_hash").and_then(Value::as_str);
    let stored_payload_mac = integrity.get("payload_mac").and_then(Value::as_str);
    let stored_signed_at = string_or_none(integrity.get("signed_at"));
    let version = int_or_none(integrity.get("integrity_version"));

    if stored_payload_hash.is_none()
        || stored_payload_mac.is_none()
        || stored_signed_at.is_none()
        || version.is_none()
    {
        return LocalAuthorityVerification {
            status: "missing_integrity",
            payload_hash: stored_payload_hash.map(str::to_owned),
            key_id: stored_key_id.clone(),
            message: Some("local_authority_integrity_metadata_missing"),
        };
    }
    let version = version.unwrap();
    if version != LOCAL_AUTHORITY_INTEGRITY_VERSION as i64 {
        return LocalAuthorityVerification {
            status: "tampered",
            payload_hash: stored_payload_hash.map(str::to_owned),
            key_id: stored_key_id.clone(),
            message: Some("local_authority_integrity_version_unsupported"),
        };
    }
    let (key, key_id) = match (key, key_id) {
        (Some(k), Some(kid))
            if constant_time_text_equal(stored_key_id.as_deref().unwrap_or(""), kid) =>
        {
            (k, kid)
        }
        _ => {
            return LocalAuthorityVerification {
                status: "unknown_key",
                payload_hash: stored_payload_hash.map(str::to_owned),
                key_id: stored_key_id.clone(),
                message: Some("local_authority_integrity_key_unavailable"),
            };
        }
    };
    let _ = key_id;

    let canonical_payload = match canonical_local_authority_payload(
        payload,
        purpose,
        stored_signed_at.as_deref().unwrap_or(""),
        version as u32,
    ) {
        Some(bytes) => bytes,
        None => {
            return LocalAuthorityVerification {
                status: "tampered",
                payload_hash: stored_payload_hash.map(str::to_owned),
                key_id: stored_key_id.clone(),
                message: Some("local_authority_integrity_payload_invalid"),
            };
        }
    };
    let computed_payload_hash = digest_bytes(&canonical_payload);
    if !constant_time_text_equal(stored_payload_hash.unwrap_or(""), &computed_payload_hash) {
        return LocalAuthorityVerification {
            status: "tampered",
            payload_hash: Some(computed_payload_hash),
            key_id: stored_key_id.clone(),
            message: Some("local_authority_integrity_payload_hash_mismatch"),
        };
    }
    let purpose_key = purpose_key(key, purpose);
    let computed_payload_mac = hex::encode(hmac_sha256_raw(&purpose_key, &canonical_payload));
    if !constant_time_text_equal(stored_payload_mac.unwrap_or(""), &computed_payload_mac) {
        return LocalAuthorityVerification {
            status: "tampered",
            payload_hash: Some(computed_payload_hash),
            key_id: stored_key_id.clone(),
            message: Some("local_authority_integrity_mac_mismatch"),
        };
    }
    LocalAuthorityVerification {
        status: "valid",
        payload_hash: Some(computed_payload_hash),
        key_id: stored_key_id.clone(),
        message: Some(LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM),
    }
}

/// `_canonical_local_authority_payload` (:131-145). `None` when the payload is
/// not JSON-serializable in the canonical envelope form.
fn canonical_local_authority_payload(
    payload: &Value,
    purpose: &str,
    signed_at: &str,
    integrity_version: u32,
) -> Option<Vec<u8>> {
    let envelope = serde_json::json!({
        "domain": std::str::from_utf8(LOCAL_AUTHORITY_INTEGRITY_DOMAIN).ok()?,
        "integrity_version": integrity_version,
        "payload": payload,
        "purpose": purpose,
        "signed_at": signed_at,
    });
    // CPython `json.dumps(sort_keys=True, separators=(",", ":"),
    // ensure_ascii=True, allow_nan=False)` — the shared guard-contracts
    // encoder escapes non-ASCII to `\uXXXX` exactly like CPython, which
    // `serde_json::to_string` would not.
    let mut out = Vec::new();
    guard_contracts::write_canonical_json_with_limit(
        &envelope,
        &mut out,
        LOCAL_AUTHORITY_CANONICAL_MAX_BYTES,
        "local_authority_canonical_too_large",
    )
    .ok()?;
    Some(out)
}

/// `_purpose_key` (:148-153): `HMAC(key, DOMAIN + b"\\0" + purpose)`.
fn purpose_key(key: &[u8], purpose: &str) -> [u8; 32] {
    let mut message = LOCAL_AUTHORITY_INTEGRITY_DOMAIN.to_vec();
    message.push(0);
    message.extend_from_slice(purpose.as_bytes());
    hmac_sha256_raw(key, &message)
}

fn string_or_none(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// `_int_or_none` (local version :160-161): only real ints, no bools, no
/// numeric strings (unlike the policy_integrity variant).
fn int_or_none(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(n)) => n.as_i64().filter(|_| !n.is_f64()),
        _ => None,
    }
}

/// `hmac.compare_digest` for UTF-8 strings (:171-172).
fn constant_time_text_equal(left: &str, right: &str) -> bool {
    constant_time_eq(left.as_bytes(), right.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ORACLE: &str = include_str!("../testdata/local_authority_integrity_oracle.json");

    /// Byte-parity with `local_authority_integrity.py` sign + verify across a
    /// payload grid (incl. non-ASCII → `\uXXXX` ensure_ascii path, nulls,
    /// floats, nested maps).
    #[test]
    fn local_authority_integrity_python_oracle() {
        let oracle: Value = serde_json::from_str(ORACLE).expect("oracle json");
        let key = hex::decode(oracle["key"].as_str().unwrap()).unwrap();
        let key_id = oracle["key_id"].as_str().unwrap();
        let purpose = oracle["purpose"].as_str().unwrap();
        let signed_at = oracle["signed_at"].as_str().unwrap();
        let wrong_key = [b'X'; 32];

        for row in oracle["rows"].as_array().unwrap() {
            let payload = &row["payload"];
            let signed = sign_local_authority_payload(payload, &key, key_id, purpose, signed_at)
                .expect("sign");
            let want = &row["signed"];
            assert_eq!(signed.integrity_version, 1);
            assert_eq!(signed.payload_hash, want["payload_hash"].as_str().unwrap());
            assert_eq!(signed.payload_mac, want["payload_mac"].as_str().unwrap());
            assert_eq!(
                signed.integrity_key_id,
                want["integrity_key_id"].as_str().unwrap()
            );
            assert_eq!(signed.signed_at, want["signed_at"].as_str().unwrap());

            let integrity = json!({
                "integrity_version": signed.integrity_version,
                "payload_hash": signed.payload_hash,
                "payload_mac": signed.payload_mac,
                "integrity_key_id": signed.integrity_key_id,
                "signed_at": signed.signed_at,
            });

            let v_ok = verify_local_authority_payload(
                payload,
                &integrity,
                Some(&key),
                Some(key_id),
                purpose,
            );
            assert_eq!(v_ok.status, row["v_ok"].as_str().unwrap());
            assert_eq!(
                v_ok.payload_hash.as_deref(),
                Some(signed.payload_hash.as_str())
            );
            assert_eq!(v_ok.key_id.as_deref(), Some(key_id));

            // Tampered payload → tampered + hash-mismatch message.
            let mut tampered = payload.clone();
            tampered["action"] = json!("block");
            let v_tamper = verify_local_authority_payload(
                &tampered,
                &integrity,
                Some(&key),
                Some(key_id),
                purpose,
            );
            assert_eq!(v_tamper.status, row["v_tamper"].as_str().unwrap());
            assert_eq!(
                v_tamper.message,
                Some(row["v_tamper_msg"].as_str().unwrap())
            );

            // Wrong key bytes, same key_id → MAC mismatch → tampered.
            let v_wrongkey = verify_local_authority_payload(
                payload,
                &integrity,
                Some(&wrong_key),
                Some(key_id),
                purpose,
            );
            assert_eq!(v_wrongkey.status, row["v_wrongkey"].as_str().unwrap());

            // Wrong key_id → unknown_key before any crypto.
            let v_wrongkeyid = verify_local_authority_payload(
                payload,
                &integrity,
                Some(&key),
                Some("other"),
                purpose,
            );
            assert_eq!(v_wrongkeyid.status, row["v_wrongkeyid"].as_str().unwrap());

            // No resolver output → unknown_key.
            let v_nokey = verify_local_authority_payload(payload, &integrity, None, None, purpose);
            assert_eq!(v_nokey.status, row["v_nokey"].as_str().unwrap());
        }
    }

    #[test]
    fn verify_missing_and_bad_integrity_metadata() {
        let key = [b'K'; 32];
        let payload = json!({"approval_id": "x"});
        // Empty integrity object → missing_integrity.
        let v = verify_local_authority_payload(&payload, &json!({}), Some(&key), Some("k"), "p");
        assert_eq!(v.status, "missing_integrity");
        // Unsupported version → tampered.
        let bad = json!({
            "integrity_version": 99,
            "payload_hash": "ab",
            "payload_mac": "cd",
            "integrity_key_id": "k",
            "signed_at": "2026-10-02T00:00:00Z",
        });
        let v = verify_local_authority_payload(&payload, &bad, Some(&key), Some("k"), "p");
        assert_eq!(v.status, "tampered");
        assert_eq!(
            v.message,
            Some("local_authority_integrity_version_unsupported")
        );
    }
}
