//! `store_secret_policy_integrity.py` — the *read-path* resolution the claim
//! transaction needs: scoped secret refs, the policy-integrity signing
//! material (`key`,`key_id`), and the trusted control state →
//! `integrity_state` payload.
//!
//! This intentionally resolves only `create=False` (no key minting, no cutover
//! resign). The full `_refresh_policy_integrity_state` startup state machine —
//! path-warning probes, generation reconcile, pending-cutover, notification
//! side-effects — stays in Python until the resident owns schema startup; the
//! claim path consumes its *result* (mode/enforcement/generation/key_id), which
//! this module reproduces for the steady-state protected/degraded cases.

use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::encrypted_secret_store::EncryptedFileSecretStore;

/// `_POLICY_INTEGRITY_KEY_REF` (`store_base.py:227`).
pub const POLICY_INTEGRITY_KEY_REF: &str = "guard-policy-integrity-key";
/// `_POLICY_INTEGRITY_CONTROL_REF` (`store_base.py:228`).
pub const POLICY_INTEGRITY_CONTROL_REF: &str = "guard-policy-integrity-control";
/// `_POLICY_INTEGRITY_CONTROL_VERSION` (`store_base.py:272`).
pub const POLICY_INTEGRITY_CONTROL_VERSION: i64 = 1;
/// `_POLICY_INTEGRITY_STATE_KEY` (`store_base.py:271`) — `sync_state` row key.
#[allow(dead_code)]
pub const POLICY_INTEGRITY_STATE_KEY: &str = "policy_integrity";

/// `_build_scoped_secret_ref` (:192-195) — `{prefix}:{sha256(resolved_home)[:16]}`.
///
/// `guard_home` must already be the resolved absolute path (callers resolve
/// `expanduser()`/`resolve()`); hashing the canonical string matches Python's
/// `str(self.guard_home.expanduser().resolve())`.
pub fn build_scoped_secret_ref(prefix: &str, resolved_guard_home: &Path) -> String {
    let home_str = resolved_guard_home.to_string_lossy();
    let hash = hex::encode(Sha256::digest(home_str.as_bytes()));
    format!("{prefix}:{}", &hash[..16])
}

/// `_versioned_secret_ref` (:198-199) — `{base}:{hash[:16]}`.
pub fn versioned_secret_ref(base_ref: &str, value_hash: &str) -> String {
    format!("{base_ref}:{}", &value_hash[..16.min(value_hash.len())])
}

/// The resolved policy-integrity signing material.
pub struct PolicyIntegrityMaterial {
    pub raw_key: Vec<u8>,
    pub key_id: String,
}

/// `_policy_integrity_secret_material` (:426-467), `create=False` path only.
///
/// Reads `key_ref` via the secret store, b64-decodes to 32 bytes, and derives
/// `key_id` from `sha256(raw_key)`. `None` mirrors the Python `None, None`
/// fail-closed return — callers treat absent material as unverifiable.
pub fn policy_integrity_secret_material(
    store: &mut EncryptedFileSecretStore,
    resolved_guard_home: &Path,
) -> Option<PolicyIntegrityMaterial> {
    let key_ref = build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, resolved_guard_home);
    let encoded_key = store.get_secret(&key_ref)?;
    let raw_key = b64_urlsafe_decode(encoded_key.as_bytes())?;
    if raw_key.len() != 32 {
        return None;
    }
    let key_id = versioned_secret_ref(&key_ref, &hex::encode(Sha256::digest(&raw_key)));
    Some(PolicyIntegrityMaterial { raw_key, key_id })
}

/// `_normalize_policy_integrity_control_state` (:485-503) — strict field
/// validation; `None` on any malformed field.
pub fn normalize_policy_integrity_control_state(payload: &Value) -> Option<Value> {
    if !payload.is_object() {
        return None;
    }
    let version = payload.get("version")?.as_i64()?;
    if version != POLICY_INTEGRITY_CONTROL_VERSION {
        return None;
    }
    let generation = payload.get("generation")?.as_i64()?;
    if generation < 0 || payload.get("generation").is_some_and(Value::is_boolean) {
        return None;
    }
    let pending_generation = match payload.get("pending_generation") {
        Some(v) if !v.is_null() => {
            let p = v.as_i64()?;
            if v.is_boolean() || p <= generation {
                return None;
            }
            Value::from(p)
        }
        _ => Value::Null,
    };
    let cutover_complete = match payload.get("cutover_complete") {
        Some(Value::Bool(b)) => *b,
        _ => return None,
    };
    Some(serde_json::json!({
        "cutover_complete": cutover_complete,
        "generation": generation,
        "pending_generation": pending_generation,
        "version": version,
    }))
}

/// `_load_policy_integrity_control_state` (:506-531), `create=False` path.
/// Reads `control_ref` secret, parses + normalizes; `None` when absent or
/// malformed (Python returns `None`, never a default, when `create=False`).
pub fn load_policy_integrity_control_state(
    store: &mut EncryptedFileSecretStore,
    resolved_guard_home: &Path,
) -> Option<Value> {
    let control_ref = build_scoped_secret_ref(POLICY_INTEGRITY_CONTROL_REF, resolved_guard_home);
    let payload_json = store.get_secret(&control_ref)?;
    let payload: Value = serde_json::from_str(&payload_json).ok()?;
    normalize_policy_integrity_control_state(&payload)
}

/// The `integrity_state` dict `claim_approval_reuse_decisions` /
/// `policy_row_payload` consume: `mode`/`enforcement`/`generation`/`key_id`/
/// `cutover_complete`.
///
/// Steady-state mapping of the Python result (:1031-1040): `mode` is
/// `protected` iff key material + trusted control state both resolve with no
/// path warnings; otherwise `degraded`. `enforcement` is `enforce`. The
/// generation comes from the trusted control state (0 when absent/degraded).
pub fn resolve_integrity_state(
    store: &mut EncryptedFileSecretStore,
    resolved_guard_home: &Path,
) -> (Option<PolicyIntegrityMaterial>, Value) {
    let control = load_policy_integrity_control_state(store, resolved_guard_home);
    let material = policy_integrity_secret_material(store, resolved_guard_home);

    let (mode, generation, key_id, cutover_complete) = match (&material, &control) {
        (Some(m), Some(c)) => (
            "protected",
            c.get("generation").and_then(Value::as_i64).unwrap_or(0),
            Value::from(m.key_id.clone()),
            c.get("cutover_complete")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
        _ => ("degraded", 0, Value::Null, false),
    };

    let state = serde_json::json!({
        "backend": "encrypted_file",
        "cutover_complete": cutover_complete,
        "degraded_reasons": if mode == "degraded" { serde_json::json!(["policy_integrity_key_unavailable"]) } else { serde_json::json!([]) },
        "enforcement": "enforce",
        "generation": generation,
        "key_id": key_id,
        "mode": mode,
    });
    (material, state)
}

/// urlsafe-b64 decode for the stored key string (tolerates padding).
fn b64_urlsafe_decode(b: &[u8]) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let s = std::str::from_utf8(b).ok()?;
    let unpadded = s.trim().trim_end_matches('=');
    let mut buf = vec![0u8; (unpadded.len() * 3) / 4 + 4];
    let out = Base64UrlUnpadded::decode(unpadded, &mut buf).ok()?;
    Some(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORACLE: &str = include_str!("../testdata/policy_integrity_resolver_oracle.json");

    /// `build_scoped_secret_ref` + `versioned_secret_ref` byte-parity, and
    /// `normalize_policy_integrity_control_state` accept/reject cases.
    #[test]
    fn scoped_refs_and_normalize_oracle() {
        let oracle: Value = serde_json::from_str(ORACLE).unwrap();
        let home = Path::new(oracle["guard_home"].as_str().unwrap());
        assert_eq!(
            build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, home),
            oracle["key_ref"].as_str().unwrap()
        );
        assert_eq!(
            build_scoped_secret_ref(POLICY_INTEGRITY_CONTROL_REF, home),
            oracle["control_ref"].as_str().unwrap()
        );
        // versioned ref
        let key_ref = oracle["key_ref"].as_str().unwrap();
        let raw = b64_urlsafe_decode(oracle["raw_key_b64"].as_str().unwrap().as_bytes()).unwrap();
        let vref = versioned_secret_ref(key_ref, &hex::encode(Sha256::digest(&raw)));
        assert_eq!(vref, oracle["key_id"].as_str().unwrap());

        // normalize: valid
        let norm = normalize_policy_integrity_control_state(&oracle["control"]).unwrap();
        assert_eq!(norm["generation"].as_i64().unwrap(), 3);
        assert!(norm["cutover_complete"].as_bool().unwrap());
        assert!(norm["pending_generation"].is_null());
        // normalize: rejects
        assert!(normalize_policy_integrity_control_state(&oracle["bad_version"]).is_none());
        assert!(normalize_policy_integrity_control_state(&oracle["bad_pending"]).is_none());
        assert!(normalize_policy_integrity_control_state(&oracle["bad_gen"]).is_none());
        assert!(normalize_policy_integrity_control_state(&serde_json::json!("x")).is_none());
    }

    /// End-to-end: seed a real guard_home with the Python-written secrets, then
    /// `resolve_integrity_state` returns material + protected state.
    #[test]
    fn resolve_integrity_state_protected() {
        let oracle: Value = serde_json::from_str(ORACLE).unwrap();
        let home = std::env::temp_dir().join(format!("hg-res-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let resolved = home.canonicalize().unwrap_or_else(|_| {
            std::fs::create_dir_all(&home).unwrap();
            home.canonicalize().unwrap()
        });
        let mut store = EncryptedFileSecretStore::new(&home);
        // Scope under THIS test home's resolved path.
        let key_ref = build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, &resolved);
        let control_ref = build_scoped_secret_ref(POLICY_INTEGRITY_CONTROL_REF, &resolved);
        store
            .set_secret(&key_ref, oracle["raw_key_b64"].as_str().unwrap())
            .unwrap();
        let control_json = serde_json::to_string(&oracle["control"]).unwrap();
        store.set_secret(&control_ref, &control_json).unwrap();

        // resolve uses resolved path for scoping — must equal oracle's refs.
        let (material, state) = resolve_integrity_state(&mut store, &resolved);
        // scoped ref for home == oracle ref only if resolved==oracle home; here
        // home differs, so just assert material resolves + protected mode.
        let material = material.expect("material");
        assert_eq!(material.raw_key.len(), 32);
        assert_eq!(state["mode"].as_str().unwrap(), "protected");
        assert_eq!(state["generation"].as_i64().unwrap(), 3);
        assert_eq!(state["enforcement"].as_str().unwrap(), "enforce");
        assert_eq!(state["key_id"].as_str().unwrap(), material.key_id);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Missing secrets → degraded state, no material.
    #[test]
    fn resolve_integrity_state_degraded() {
        let home = std::env::temp_dir().join(format!("hg-deg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let resolved = home.canonicalize().unwrap();
        let mut store = EncryptedFileSecretStore::new(&home);
        let (material, state) = resolve_integrity_state(&mut store, &resolved);
        assert!(material.is_none());
        assert_eq!(state["mode"].as_str().unwrap(), "degraded");
        assert_eq!(state["generation"].as_i64().unwrap(), 0);
        assert!(state["key_id"].is_null());
        let _ = std::fs::remove_dir_all(&home);
    }
}
