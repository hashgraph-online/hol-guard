//! Python-parity OAuth credential authority for the resident.
//!
//! `store_base.py:_secret_fingerprint` fingerprints the canonical secret JSON
//! with scrypt and prefixes the hex digest with `scrypt$`; `store_oauth.py`
//! stores that string as `credentials_sha256` in the `oauth_local_credentials`
//! state payload while the secret itself lives in the scoped secret store
//! under `credentials_ref`. The resident must reproduce the fingerprint
//! exactly: a rotated token written with a divergent fingerprint makes the
//! credential read as unhealthy to Python, which is worse than not writing it
//! at all.
//!
//! `resolve_credentials` is the read half — it turns the state payload plus the
//! secret it points at into the flat credential dict the rest of the guard-sync
//! seam consumes, so a normally-provisioned store (which never inlines secret
//! material) can start native sync.
//!
//! The write half (rotation persistence) still owes Python's canonical dump —
//! `json.dumps(..., sort_keys=True, separators=(",", ":"))` — plus a
//! re-fingerprint of the rotated secret. `serde_json::to_string` over a
//! BTreeMap-backed `Map` produces that exact form for the ASCII payloads these
//! records hold, and `secret_fingerprint` supplies the matching record hash.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// `store_base.py:333` — current fingerprint prefix.
pub const FINGERPRINT_PREFIX: &str = "scrypt$";
/// `store_base.py:334` — legacy prefix, produced by pbkdf2-hmac-sha256.
pub const LEGACY_FINGERPRINT_PREFIX: &str = "pbkdf2-sha256$";
/// `store_base.py:335` — scrypt salt.
const FINGERPRINT_SALT: &[u8] = b"hol-guard-secret-fingerprint:v1";
/// `store_base.py:336` — `n = 2**14`, expressed as scrypt's log2 parameter.
const FINGERPRINT_LOG_N: u8 = 14;
/// `store_base.py:337` — block size.
const FINGERPRINT_R: u32 = 8;
/// `store_base.py:338` — parallelism.
const FINGERPRINT_P: u32 = 1;
/// `store_base.py:339` — digest length.
const FINGERPRINT_DKLEN: usize = 32;
/// `store_base.py:368` — iteration count of the legacy pbkdf2 fingerprint.
const LEGACY_FINGERPRINT_ITERATIONS: u32 = 200_000;

/// `store_base.py:233` — the payload key holding the scoped secret ref.
pub const CREDENTIALS_REF_KEY: &str = "credentials_ref";
/// `store_base.py:232` — the payload key holding the secret fingerprint.
pub const CREDENTIALS_HASH_KEY: &str = "credentials_sha256";

/// Fields that only ever come from the secret store; every other field is record
/// metadata and the record stays authoritative for it.
const SECRET_MATERIAL_KEYS: &[&str] = &[
    "refresh_token",
    "dpop_private_key_pem",
    "dpop_public_jwk",
    "dpop_public_jwk_thumbprint",
    "access_token",
    "access_token_expires_at",
];

/// Verdict memo for `secret_matches_fingerprint`.
///
/// Verification is memory-hard (scrypt, ~16 MiB) and the resident re-checks the
/// same credential on every health read and every sync attempt. Results are
/// memoised by the digest of the exact bytes involved — identical inputs can only
/// produce the identical verdict, and a rotated secret yields a different key and
/// is verified again. Memory is bounded by clearing at capacity.
fn verification_memo() -> &'static Mutex<HashMap<(String, String), bool>> {
    static CACHE: OnceLock<Mutex<HashMap<(String, String), bool>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

const VERIFICATION_MEMO_CAPACITY: usize = 16;

/// `secret_matches_fingerprint` behind the resident's memo.
pub fn verified_secret_matches(value: &str, expected: &str) -> Result<bool, String> {
    let key = (
        hex::encode(Sha256::digest(value.as_bytes())),
        expected.to_owned(),
    );
    if let Some(verdict) = verification_memo()
        .lock()
        .ok()
        .and_then(|memo| memo.get(&key).copied())
    {
        return Ok(verdict);
    }
    let verdict = secret_matches_fingerprint(value, expected)?;
    if let Ok(mut memo) = verification_memo().lock() {
        if memo.len() >= VERIFICATION_MEMO_CAPACITY {
            memo.clear();
        }
        memo.insert(key, verdict);
    }
    Ok(verdict)
}

#[cfg(test)]
fn verification_memo_len() -> usize {
    verification_memo()
        .lock()
        .map(|memo| memo.len())
        .unwrap_or_default()
}

/// `store_base.py:371 _secret_fingerprint` — `scrypt$` + scrypt hex digest of
/// the value's UTF-8 bytes.
pub fn secret_fingerprint(value: &str) -> Result<String, String> {
    let params = scrypt::Params::new(
        FINGERPRINT_LOG_N,
        FINGERPRINT_R,
        FINGERPRINT_P,
        FINGERPRINT_DKLEN,
    )
    .map_err(|error| format!("scrypt_params_invalid: {error}"))?;
    let mut digest = [0u8; FINGERPRINT_DKLEN];
    scrypt::scrypt(value.as_bytes(), FINGERPRINT_SALT, &params, &mut digest)
        .map_err(|error| format!("scrypt_failed: {error}"))?;
    Ok(format!("{FINGERPRINT_PREFIX}{}", hex::encode(digest)))
}

/// `store_base.py:383 _legacy_secret_fingerprint` — pbkdf2-hmac-sha256 over the
/// same salt, at the pre-scrypt iteration count.
pub fn legacy_secret_fingerprint(value: &str) -> String {
    let mut digest = [0u8; FINGERPRINT_DKLEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        value.as_bytes(),
        FINGERPRINT_SALT,
        LEGACY_FINGERPRINT_ITERATIONS,
        &mut digest,
    );
    format!("{LEGACY_FINGERPRINT_PREFIX}{}", hex::encode(digest))
}

/// `store_base.py:393 _legacy_secret_sha256` — the oldest records carry a bare
/// sha256 hex digest, weak by design and kept only to read them back.
fn legacy_secret_sha256(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// `store_base.py:397 _secret_matches_hash` — verification dispatches on the
/// stored prefix: `scrypt$`, then `pbkdf2-sha256$`, then a bare sha256 digest.
/// A stored value still hashes to exactly one of them.
pub fn secret_matches_fingerprint(value: &str, expected: &str) -> Result<bool, String> {
    if expected.starts_with(FINGERPRINT_PREFIX) {
        return Ok(secret_fingerprint(value)? == expected);
    }
    if expected.starts_with(LEGACY_FINGERPRINT_PREFIX) {
        return Ok(legacy_secret_fingerprint(value) == expected);
    }
    Ok(legacy_secret_sha256(value) == expected)
}

fn non_empty_str(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

/// Merge the `oauth_local_credentials` payload with the scoped secret it points
/// at, yielding the flat credential dict the guard-sync seam reads: metadata
/// (`issuer`, `client_id`, workspace fields) from the payload, secret material
/// (`refresh_token`, DPoP key, cached access token) from the secret store.
///
/// `read_secret` is the scoped secret-store read, injected so the resolution
/// can be exercised without a guard home. It receives the payload's ref, or
/// `None` when the record predates it, in which case the caller applies the
/// home-scoped default ref (`_load_oauth_secret_payload`).
pub fn resolve_credentials(
    payload: &Value,
    read_secret: &dyn Fn(Option<&str>) -> Option<String>,
) -> Result<Value, String> {
    let object = payload
        .as_object()
        .ok_or_else(|| "credentials_payload_not_object".to_owned())?;
    let secret_ref = non_empty_str(object.get(CREDENTIALS_REF_KEY));
    let expected = non_empty_str(object.get(CREDENTIALS_HASH_KEY));
    if secret_ref.is_none() && expected.is_none() && object.contains_key("refresh_token") {
        return Ok(payload.clone());
    }
    let expected = expected.ok_or_else(|| "credentials_hash_missing".to_owned())?;
    let raw = read_secret(secret_ref).ok_or_else(|| "credentials_secret_unavailable".to_owned())?;
    if !verified_secret_matches(&raw, expected)? {
        return Err("credentials_secret_fingerprint_mismatch".to_owned());
    }
    let secret: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("credentials_secret_invalid_json: {error}"))?;
    let secret_object = secret
        .as_object()
        .ok_or_else(|| "credentials_secret_not_object".to_owned())?;
    let mut merged: Map<String, Value> = object.clone();
    for (key, value) in secret_object {
        // Secret material always comes from the verified secret; any other field
        // only fills a gap, so a secret can never override record metadata such
        // as `issuer` or `client_id`.
        if SECRET_MATERIAL_KEYS.contains(&key.as_str()) {
            merged.insert(key.clone(), value.clone());
        } else {
            merged.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
    Ok(Value::Object(merged))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector produced by the Python implementation this mirrors:
    /// `_secret_fingerprint(json.dumps(payload, sort_keys=True, separators=(",", ":")))`
    /// over the payload below. If this test fails, the resident and Python
    /// disagree about whether a stored credential is intact.
    const VECTOR_CANONICAL: &str = r#"{"access_token":"at-1","access_token_expires_at":"2026-01-01T00:00:00+00:00","dpop_private_key_pem":"pem-vector-1\n","dpop_public_jwk":{"crv":"P-256","kty":"EC","x":"x1","y":"y1"},"dpop_public_jwk_thumbprint":"tp-1","refresh_token":"rt-vector"}"#;
    const VECTOR_FINGERPRINT: &str =
        "scrypt$ffae7bdd9f8ab3b429acd733879eeacc7f1813d9d7cf6bf86a7e6fe87d31bb08";

    #[test]
    fn fingerprint_matches_the_python_implementation() {
        assert_eq!(
            secret_fingerprint(VECTOR_CANONICAL).expect("fingerprint"),
            VECTOR_FINGERPRINT
        );
    }

    /// Same canonical value as `VECTOR_CANONICAL`, fingerprinted by each
    /// implementation the Python side accepts (`store_base.py:397`).
    const VECTOR_LEGACY_PBKDF2: &str =
        "pbkdf2-sha256$35e9da2d08fa4c82f83931925f9c3a4cb0432cd2c006428fa0da72fa17e6900b";
    const VECTOR_LEGACY_SHA256: &str =
        "c328fcbd6364aab3d830e527c722f4354e469bb5f95529afd4cf83922a8b8509";

    #[test]
    fn fingerprint_verification_dispatches_on_the_stored_prefix() {
        assert!(secret_matches_fingerprint(VECTOR_CANONICAL, VECTOR_FINGERPRINT).expect("verify"));
        assert!(
            secret_matches_fingerprint(VECTOR_CANONICAL, VECTOR_LEGACY_PBKDF2).expect("verify")
        );
        assert!(
            secret_matches_fingerprint(VECTOR_CANONICAL, VECTOR_LEGACY_SHA256).expect("verify")
        );
        assert!(!secret_matches_fingerprint("other", VECTOR_FINGERPRINT).expect("verify"));
        assert!(!secret_matches_fingerprint("other", VECTOR_LEGACY_PBKDF2).expect("verify"));
        assert!(!secret_matches_fingerprint("other", VECTOR_LEGACY_SHA256).expect("verify"));
    }

    #[test]
    fn legacy_fingerprints_match_the_python_implementation() {
        assert_eq!(
            legacy_secret_fingerprint(VECTOR_CANONICAL),
            VECTOR_LEGACY_PBKDF2
        );
        assert_eq!(legacy_secret_sha256(VECTOR_CANONICAL), VECTOR_LEGACY_SHA256);
    }

    fn secret_payload() -> String {
        // Compact, key-sorted dump — the form Python writes and fingerprints
        // (`json.dumps(..., sort_keys=True, separators=(",", ":"))`); serde_json's
        // `Map` is BTreeMap-backed, so the two agree for these ASCII payloads.
        serde_json::to_string(&serde_json::json!({
            "refresh_token": "rt-1",
            "dpop_private_key_pem": "pem-1",
            "dpop_public_jwk": {"crv": "P-256", "kty": "EC", "x": "x1", "y": "y1"},
            "dpop_public_jwk_thumbprint": "tp-1",
        }))
        .expect("json")
    }

    #[test]
    fn resolution_reads_the_scoped_secret_and_keeps_payload_metadata() {
        let secret = secret_payload();
        let payload = serde_json::json!({
            "issuer": "https://cloud.example",
            "client_id": "client-1",
            CREDENTIALS_REF_KEY: "hol-guard:oauth-local-credentials",
            CREDENTIALS_HASH_KEY: secret_fingerprint(&secret).expect("fingerprint"),
            "workspace_id": "ws-1",
        });
        let resolved = resolve_credentials(&payload, &|secret_ref: Option<&str>| {
            (secret_ref == Some("hol-guard:oauth-local-credentials")).then(|| secret.clone())
        })
        .expect("resolved");
        assert_eq!(
            resolved.get("refresh_token").and_then(Value::as_str),
            Some("rt-1")
        );
        assert_eq!(
            resolved
                .get("dpop_public_jwk_thumbprint")
                .and_then(Value::as_str),
            Some("tp-1")
        );
        assert_eq!(
            resolved.get("issuer").and_then(Value::as_str),
            Some("https://cloud.example")
        );
        assert_eq!(
            resolved.get("client_id").and_then(Value::as_str),
            Some("client-1")
        );
        assert_eq!(
            resolved.get("workspace_id").and_then(Value::as_str),
            Some("ws-1")
        );
    }

    #[test]
    fn resolution_fails_closed_on_a_tampered_secret() {
        let payload = serde_json::json!({
            "issuer": "https://cloud.example",
            "client_id": "client-1",
            CREDENTIALS_REF_KEY: "ref-1",
            CREDENTIALS_HASH_KEY: secret_fingerprint(&secret_payload()).expect("fingerprint"),
        });
        let tampered =
            serde_json::to_string(&serde_json::json!({"refresh_token": "rt-evil"})).expect("json");
        assert_eq!(
            resolve_credentials(&payload, &|_: Option<&str>| Some(tampered.clone()))
                .expect_err("mismatch"),
            "credentials_secret_fingerprint_mismatch"
        );
    }

    #[test]
    fn resolution_reports_each_unavailable_input() {
        let read_none = |_: Option<&str>| None;
        assert_eq!(
            resolve_credentials(&serde_json::json!({"issuer": "i"}), &read_none).expect_err("hash"),
            "credentials_hash_missing"
        );
        assert_eq!(
            resolve_credentials(
                &serde_json::json!({
                    "issuer": "i",
                    CREDENTIALS_HASH_KEY: "scrypt$00",
                }),
                &read_none
            )
            .expect_err("secret-without-ref"),
            "credentials_secret_unavailable"
        );
        assert_eq!(
            resolve_credentials(
                &serde_json::json!({
                    CREDENTIALS_REF_KEY: "ref-1",
                    CREDENTIALS_HASH_KEY: "scrypt$00",
                }),
                &read_none
            )
            .expect_err("secret"),
            "credentials_secret_unavailable"
        );
    }

    #[test]
    fn resolution_accepts_the_legacy_inline_form_unchanged() {
        let inline = serde_json::json!({
            "issuer": "https://cloud.example",
            "client_id": "client-1",
            "refresh_token": "rt-inline",
        });
        let resolved = resolve_credentials(&inline, &|_: Option<&str>| None).expect("inline");
        assert_eq!(resolved, inline);
    }

    #[test]
    fn a_record_carrying_a_ref_is_verified_even_when_it_also_inlines_a_token() {
        let secret = secret_payload();
        let payload = serde_json::json!({
            "issuer": "https://cloud.example",
            "client_id": "client-1",
            "refresh_token": "rt-stale-inline",
            CREDENTIALS_REF_KEY: "ref-1",
            CREDENTIALS_HASH_KEY: secret_fingerprint(&secret).expect("fingerprint"),
        });
        // The stored secret wins: an inline token must not bypass verification.
        let resolved = resolve_credentials(&payload, &|_: Option<&str>| Some(secret.clone()))
            .expect("resolved");
        assert_eq!(
            resolved.get("refresh_token").and_then(Value::as_str),
            Some("rt-1")
        );
    }

    #[test]
    fn a_secret_cannot_override_record_metadata() {
        let secret = serde_json::to_string(&serde_json::json!({
            "refresh_token": "rt-1",
            "issuer": "https://evil.example",
            "client_id": "other-client",
            "workspace_id": "ws-from-secret",
        }))
        .expect("json");
        let payload = serde_json::json!({
            "issuer": "https://cloud.example",
            "client_id": "client-1",
            CREDENTIALS_REF_KEY: "ref-1",
            CREDENTIALS_HASH_KEY: secret_fingerprint(&secret).expect("fingerprint"),
        });
        let resolved = resolve_credentials(&payload, &|_: Option<&str>| Some(secret.clone()))
            .expect("resolved");
        // Material from the verified secret, identity from the record.
        assert_eq!(
            resolved.get("refresh_token").and_then(Value::as_str),
            Some("rt-1")
        );
        assert_eq!(
            resolved.get("issuer").and_then(Value::as_str),
            Some("https://cloud.example")
        );
        assert_eq!(
            resolved.get("client_id").and_then(Value::as_str),
            Some("client-1")
        );
        // A secret-only field still fills the gap.
        assert_eq!(
            resolved.get("workspace_id").and_then(Value::as_str),
            Some("ws-from-secret")
        );
    }

    #[test]
    fn repeated_verification_keeps_its_verdict_and_the_memo_stays_bounded() {
        let secret = secret_payload();
        let expected = secret_fingerprint(&secret).expect("fingerprint");
        for _ in 0..3 {
            assert!(verified_secret_matches(&secret, &expected).expect("verdict"));
        }
        for index in 0..(VERIFICATION_MEMO_CAPACITY + 2) {
            let value = format!("value-{index}");
            assert!(!verified_secret_matches(&value, &expected).expect("verdict"));
        }
        // Holds under any interleaving with tests sharing this process's memo.
        assert!(
            verification_memo_len() <= VERIFICATION_MEMO_CAPACITY,
            "the memo must stay bounded"
        );
    }
}
