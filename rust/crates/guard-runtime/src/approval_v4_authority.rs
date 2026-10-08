#![forbid(unsafe_code)]

//! Root-authenticated WebAuthn authority and resident-owned counter state.
//!
//! The public authority record is safe to transport, but it is never trusted
//! without the release-pinned approval enrollment root. The credential,
//! credential key, and sign counter are mirrored in a purpose-scoped secure
//! resident account; Python and cloud persistence have no write path.

use super::approval_v4_assertion_state::AssertionBinding;
use super::approval_v4_secure_state::{
    secure_state_matches_record, SecureState, SECURE_STATE_SCHEMA, SECURE_STATE_VERSION,
};
use guard_contracts::{ApprovalAuthorityV4, NATIVE_APPROVAL_V4_ENROLLMENT_DOMAIN};
use guard_policy_snapshot::canonical_json_bytes;
use serde_json::Value;
use std::collections::HashMap;
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[path = "approval_v4_lineage.rs"]
pub(super) mod lineage;
pub(crate) use lineage::{challenge_matches_authority, verify_renewal_authority};
#[path = "approval_v4_install.rs"]
mod install;
pub(crate) use install::install_record;

pub(super) const AUTHORITY_FILE_NAME: &str = "approval-authority-v4.json";
const AUTHORITY_MAX_BYTES: u64 = 32 * 1024;
#[derive(Debug, Clone)]
pub(crate) struct ApprovalV4Authority {
    pub(crate) credential_id: Vec<u8>,
    pub(crate) cose_public_key: Vec<u8>,
    pub(crate) algorithm: i32,
    pub(crate) rp_id: String,
    pub(crate) origin: String,
    pub(crate) key_id: String,
    pub(crate) device_binding: String,
    pub(crate) installation_binding: String,
    pub(crate) enrollment_generation: u64,
    previous_key_id: Option<String>,
    enrollment_lineage: Arc<Vec<lineage::EnrollmentAncestor>>,
    pub(crate) status: String,
    pub(crate) path: PathBuf,
    pub(crate) fingerprint: String,
    record_digest: String,
    state_base: PathBuf,
    sign_count: Arc<Mutex<u32>>,
    pub(crate) assertions: Arc<Mutex<HashMap<String, AssertionBinding>>>,
}
use super::approval_v4_enrollment::{origin_matches_rp_id, valid_origin, valid_rp_id};
/// Verify the V4 record with the release-pinned root and a domain distinct
/// from the V3 authority contract. Production has no private-root material.
fn verify_enrollment_root_signature(
    signing_bytes: &[u8],
    signature_hex: &str,
) -> Result<(), String> {
    if !valid_hex(signature_hex, 64) {
        return Err("native_approval_v4_enrollment_invalid".to_owned());
    }
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|_| "native_approval_v4_enrollment_invalid".to_owned())?;
    let mut message =
        Vec::with_capacity(NATIVE_APPROVAL_V4_ENROLLMENT_DOMAIN.len() + signing_bytes.len());
    message.extend_from_slice(NATIVE_APPROVAL_V4_ENROLLMENT_DOMAIN);
    message.extend_from_slice(signing_bytes);
    #[cfg(test)]
    let root = super::approval_authority::enrollment_root_public_key();
    #[cfg(not(test))]
    let root = super::approval_authority::enrollment_root_public_key()?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, root)
        .verify(&message, &signature_bytes)
        .map_err(|_| "native_approval_v4_enrollment_invalid".to_owned())
}

fn valid_hex_string(value: &str, maximum_bytes: usize) -> bool {
    value.len() >= 2
        && value.len() <= maximum_bytes.saturating_mul(2)
        && value.len() % 2 == 0
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_hex(value: &str, bytes: usize, code: &str) -> Result<Vec<u8>, String> {
    if !valid_hex(value, bytes) {
        return Err(code.to_owned());
    }
    hex::decode(value).map_err(|_| code.to_owned())
}

fn record_signing_value(record: &ApprovalAuthorityV4) -> Result<Value, String> {
    let mut value = serde_json::to_value(record)
        .map_err(|_| "native_approval_v4_authority_invalid".to_owned())?;
    value
        .as_object_mut()
        .ok_or_else(|| "native_approval_v4_authority_invalid".to_owned())?
        .remove("enrollment_signature");
    Ok(value)
}

fn record_signing_bytes(record: &ApprovalAuthorityV4) -> Result<Vec<u8>, String> {
    canonical_json_bytes(&record_signing_value(record)?)
        .map_err(|_| "native_approval_v4_authority_invalid".to_owned())
}

fn validate_record(record: &ApprovalAuthorityV4) -> Result<(Vec<u8>, Vec<u8>), String> {
    if record.schema != guard_contracts::NATIVE_APPROVAL_AUTHORITY_V4_SCHEMA
        || record.version != 4
        || !matches!(record.algorithm, -7 | -8)
        || record.enrollment_generation == 0
        || !matches!(record.status.as_str(), "active" | "revoked")
        || !valid_rp_id(&record.rp_id)
        || !valid_origin(&record.origin)
        || !origin_matches_rp_id(&record.origin, &record.rp_id)
        || !valid_hex(&record.key_id, 32)
        || !valid_hex(&record.device_binding, 32)
        || !valid_hex(&record.installation_binding, 32)
        || record.device_binding == record.installation_binding
        || !valid_hex(&record.enrollment_signature, 64)
        || (record.enrollment_generation == 1 && record.previous_key_id.is_some())
    {
        return Err("native_approval_v4_authority_invalid".to_owned());
    }
    if let Some(previous) = record.previous_key_id.as_ref() {
        if !valid_hex(previous, 32) || previous == &record.key_id {
            return Err("native_approval_v4_authority_invalid".to_owned());
        }
    }
    if record.credential_id.len() > 2 * 1024 || record.credential_id.len() % 2 != 0 {
        return Err("native_approval_v4_authority_invalid".to_owned());
    }
    let credential_id = decode_hex(
        &record.credential_id,
        record.credential_id.len() / 2,
        "native_approval_v4_authority_invalid",
    )?;
    if credential_id.is_empty() || credential_id.len() > 1024 {
        return Err("native_approval_v4_authority_invalid".to_owned());
    }
    if !valid_hex_string(
        &record.cose_public_key,
        guard_contracts::NATIVE_APPROVAL_V4_MAX_COSE_KEY_BYTES,
    ) {
        return Err("native_approval_v4_authority_invalid".to_owned());
    }
    let cose = hex::decode(&record.cose_public_key)
        .map_err(|_| "native_approval_v4_authority_invalid".to_owned())?;
    if cose.is_empty() || cose.len() > 2048 {
        return Err("native_approval_v4_authority_invalid".to_owned());
    }
    crate::approval::approval_v4_crypto::validate_cose_public_key(&cose, record.algorithm)
        .map_err(|_| "native_approval_v4_authority_invalid".to_owned())?;
    if record.key_id != guard_policy_snapshot::digest_bytes(&cose) {
        return Err("native_approval_v4_authority_key_id_mismatch".to_owned());
    }
    let signing_bytes = record_signing_bytes(record)?;
    verify_enrollment_root_signature(&signing_bytes, &record.enrollment_signature)?;
    Ok((credential_id, cose))
}

fn secure_state_value(authority: &ApprovalV4Authority, sign_count: u32) -> Result<String, String> {
    let state = serde_json::json!({
        "schema": SECURE_STATE_SCHEMA,
        "version": SECURE_STATE_VERSION,
        "record_digest": authority.record_digest,
        "enrollment_generation": authority.enrollment_generation,
        "key_id": authority.key_id,
        "rp_id": authority.rp_id,
        "origin": authority.origin,
        "credential_id": hex::encode(&authority.credential_id),
        "cose_public_key": hex::encode(&authority.cose_public_key),
        "algorithm": authority.algorithm,
        "status": authority.status,
        "enrollment_lineage": authority.enrollment_lineage.as_ref(),
        "sign_count": sign_count,
    });
    let bytes = canonical_json_bytes(&state)
        .map_err(|_| "native_approval_v4_secure_state_invalid".to_owned())?;
    Ok(String::from_utf8(bytes).expect("canonical JSON is UTF-8"))
}

fn read_secure_state_record(state_base: &Path) -> Result<Option<SecureState>, String> {
    let Some(encoded) = super::approval_v4_secure_state::load(state_base)? else {
        return Ok(None);
    };
    let value = crate::strict_json_value(encoded.as_bytes())
        .map_err(|_| "native_approval_v4_secure_state_invalid".to_owned())?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_approval_v4_secure_state_invalid".to_owned())?;
    if canonical != encoded.as_bytes() {
        return Err("native_approval_v4_secure_state_invalid".to_owned());
    }
    let state: SecureState = serde_json::from_value(value)
        .map_err(|_| "native_approval_v4_secure_state_invalid".to_owned())?;
    Ok(Some(state))
}

fn read_secure_state(
    state_base: &Path,
    authority: &ApprovalV4Authority,
) -> Result<SecureState, String> {
    let state = read_secure_state_record(state_base)?
        .ok_or_else(|| "native_approval_v4_secure_state_unavailable".to_owned())?;
    if state.schema != SECURE_STATE_SCHEMA
        || state.version != SECURE_STATE_VERSION
        || state.record_digest != authority.record_digest
        || state.enrollment_generation != authority.enrollment_generation
        || state.key_id != authority.key_id
        || state.rp_id != authority.rp_id
        || state.origin != authority.origin
        || state.credential_id != hex::encode(&authority.credential_id)
        || state.cose_public_key != hex::encode(&authority.cose_public_key)
        || state.status != authority.status
        || state.algorithm != authority.algorithm
    {
        return Err("native_approval_v4_authority_provenance_mismatch".to_owned());
    }
    Ok(state)
}

fn read_record(
    path: &Path,
    private_root: &Path,
) -> Result<Option<(ApprovalAuthorityV4, Vec<u8>)>, String> {
    let Some((value, bytes)) = super::policy_store_persistence::read_private_json(
        path,
        AUTHORITY_MAX_BYTES,
        "approval_authority_v4",
        private_root,
    )?
    else {
        return Ok(None);
    };
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_approval_v4_authority_invalid".to_owned())?;
    if canonical != bytes {
        return Err("native_approval_v4_authority_invalid".to_owned());
    }
    let record: ApprovalAuthorityV4 = serde_json::from_value(value)
        .map_err(|_| "native_approval_v4_authority_invalid".to_owned())?;
    let _ = validate_record(&record)?;
    Ok(Some((record, bytes)))
}

pub(crate) fn load(state_base: &Path) -> Result<Option<ApprovalV4Authority>, String> {
    super::approval_enrollment::with_transition_lock(state_base, || load_locked(state_base))
}

pub(super) fn load_locked(state_base: &Path) -> Result<Option<ApprovalV4Authority>, String> {
    let path = state_base.join(AUTHORITY_FILE_NAME);
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    let Some((record, bytes)) = read_record(&path, &private_root)? else {
        return Ok(None);
    };
    let (credential_id, cose_public_key) = validate_record(&record)?;
    let record_digest = guard_policy_snapshot::digest_bytes(&bytes);
    let mut authority = ApprovalV4Authority {
        credential_id,
        cose_public_key,
        algorithm: record.algorithm,
        rp_id: record.rp_id,
        origin: record.origin,
        key_id: record.key_id,
        device_binding: record.device_binding,
        installation_binding: record.installation_binding,
        enrollment_generation: record.enrollment_generation,
        previous_key_id: record.previous_key_id,
        enrollment_lineage: Arc::new(Vec::new()),
        status: record.status,
        path: path.clone(),
        fingerprint: super::policy_store_authority::authority_fingerprint(&path)
            .ok_or_else(|| "native_approval_v4_authority_invalid".to_owned())?,
        record_digest,
        state_base: state_base.to_owned(),
        sign_count: Arc::new(Mutex::new(0)),
        assertions: Arc::new(Mutex::new(HashMap::new())),
    };
    let state = read_secure_state(state_base, &authority)?;
    *authority
        .sign_count
        .lock()
        .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())? = state.sign_count;
    authority.enrollment_lineage = Arc::new(state.enrollment_lineage);
    if authority.status == "revoked" {
        return Err("native_approval_v4_authority_revoked".to_owned());
    }
    Ok(Some(authority))
}

pub(crate) use super::approval_v4_enrollment::prepare_enrollment;

pub(crate) fn sign_count(authority: &ApprovalV4Authority) -> Result<u32, String> {
    authority
        .sign_count
        .lock()
        .map(|counter| *counter)
        .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())
}

pub(crate) fn advance_sign_count(
    authority: &ApprovalV4Authority,
    candidate: u32,
) -> Result<(), String> {
    let mut counter = authority
        .sign_count
        .lock()
        .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())?;
    if *counter != 0 && candidate <= *counter {
        return Err("native_approval_v4_counter_replay".to_owned());
    }
    if candidate > *counter {
        let state = secure_state_value(authority, candidate)?;
        super::approval_v4_secure_state::store(&authority.state_base, &state)?;
        *counter = candidate;
    }
    Ok(())
}

pub(crate) fn with_verified_authority<T, F>(
    authority: &ApprovalV4Authority,
    operation: F,
) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    super::approval_enrollment::with_transition_lock(&authority.state_base, || {
        let current = load_locked(&authority.state_base)?
            .ok_or_else(|| "native_approval_v4_authority_missing".to_owned())?;
        if current.status != "active" || current.fingerprint != authority.fingerprint {
            return Err("native_approval_v4_authority_changed".to_owned());
        }
        operation()
    })
}

pub(crate) use super::approval_v4_assertion_state::{
    assertion_matches, forget_assertion, remember_assertion,
};

#[cfg(test)]
#[path = "approval_v4_authority_tests.rs"]
pub(crate) mod tests;
