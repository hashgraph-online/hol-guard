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
    let state = SecureState {
        schema: SECURE_STATE_SCHEMA.to_owned(),
        version: SECURE_STATE_VERSION,
        record_digest: authority.record_digest.clone(),
        enrollment_generation: authority.enrollment_generation,
        key_id: authority.key_id.clone(),
        rp_id: authority.rp_id.clone(),
        origin: authority.origin.clone(),
        credential_id: hex::encode(&authority.credential_id),
        cose_public_key: hex::encode(&authority.cose_public_key),
        algorithm: authority.algorithm,
        sign_count,
    };
    let value = serde_json::to_value(state)
        .map_err(|_| "native_approval_v4_secure_state_invalid".to_owned())?;
    let bytes = canonical_json_bytes(&value)
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

fn read_secure_state(state_base: &Path, authority: &ApprovalV4Authority) -> Result<u32, String> {
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
        || state.algorithm != authority.algorithm
    {
        return Err("native_approval_v4_authority_provenance_mismatch".to_owned());
    }
    Ok(state.sign_count)
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

fn load_locked(state_base: &Path) -> Result<Option<ApprovalV4Authority>, String> {
    let path = state_base.join(AUTHORITY_FILE_NAME);
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    let Some((record, bytes)) = read_record(&path, &private_root)? else {
        return Ok(None);
    };
    let (credential_id, cose_public_key) = validate_record(&record)?;
    let record_digest = guard_policy_snapshot::digest_bytes(&bytes);
    let authority = ApprovalV4Authority {
        credential_id,
        cose_public_key,
        algorithm: record.algorithm,
        rp_id: record.rp_id,
        origin: record.origin,
        key_id: record.key_id,
        device_binding: record.device_binding,
        installation_binding: record.installation_binding,
        enrollment_generation: record.enrollment_generation,
        status: record.status,
        path: path.clone(),
        fingerprint: super::policy_store_authority::authority_fingerprint(&path)
            .ok_or_else(|| "native_approval_v4_authority_invalid".to_owned())?,
        record_digest,
        state_base: state_base.to_owned(),
        sign_count: Arc::new(Mutex::new(0)),
        assertions: Arc::new(Mutex::new(HashMap::new())),
    };
    let counter = read_secure_state(state_base, &authority)?;
    *authority
        .sign_count
        .lock()
        .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())? = counter;
    if authority.status == "revoked" {
        return Err("native_approval_v4_authority_revoked".to_owned());
    }
    Ok(Some(authority))
}

pub(crate) fn install_record(state_base: &Path, record_path: &Path) -> Result<(), String> {
    super::approval_enrollment::with_transition_lock(state_base, || {
        super::validate_private_directory(state_base)?;
        let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
        let Some((candidate, bytes)) = read_record(record_path, &private_root)? else {
            return Err("native_approval_v4_authority_missing".to_owned());
        };
        let target = state_base.join(AUTHORITY_FILE_NAME);
        let current = read_record(&target, &private_root)?;
        let (candidate_credential_id, candidate_cose) = validate_record(&candidate)?;
        let candidate_digest = guard_policy_snapshot::digest_bytes(&bytes);
        if let Some((current, current_bytes)) = current.as_ref() {
            if *current_bytes == bytes {
                let (credential_id, cose_public_key) = validate_record(current)?;
                let state = read_secure_state_record(state_base)?
                    .ok_or_else(|| "native_approval_v4_secure_state_unavailable".to_owned())?;
                if !secure_state_matches_record(
                    &state,
                    current,
                    &guard_policy_snapshot::digest_bytes(current_bytes),
                    &credential_id,
                    &cose_public_key,
                ) {
                    return Err("native_approval_v4_authority_provenance_mismatch".to_owned());
                }
                return Ok(());
            }
            if current.status == "revoked" {
                return Err("native_approval_v4_authority_revoked".to_owned());
            }
            if candidate.enrollment_generation <= current.enrollment_generation
                || (candidate.status == "active"
                    && candidate.previous_key_id.as_deref() != Some(current.key_id.as_str()))
                || (candidate.status == "revoked"
                    && (candidate.key_id != current.key_id || candidate.previous_key_id.is_some()))
            {
                return Err("native_approval_v4_authority_generation_rollback".to_owned());
            }
            if candidate.device_binding != current.device_binding
                || candidate.installation_binding != current.installation_binding
                || candidate.rp_id != current.rp_id
                || candidate.origin != current.origin
            {
                return Err("native_approval_v4_authority_provenance_mismatch".to_owned());
            }
            if candidate.status == "revoked"
                && (candidate.credential_id != current.credential_id
                    || candidate.cose_public_key != current.cose_public_key
                    || candidate.algorithm != current.algorithm)
            {
                return Err("native_approval_v4_authority_provenance_mismatch".to_owned());
            }
        }
        if let Some(existing) = super::approval_enrollment::load_unlocked(state_base)? {
            if existing.device_binding != candidate.device_binding
                || existing.installation_binding != candidate.installation_binding
            {
                return Err("native_approval_v4_authority_provenance_mismatch".to_owned());
            }
            if existing.status == "revoked" {
                return Err("native_approval_v4_authority_revoked".to_owned());
            }
        }
        let existing_secure_state = read_secure_state_record(state_base)?;
        if current.is_none()
            && existing_secure_state.is_none()
            && (candidate.enrollment_generation != 1 || candidate.status != "active")
        {
            return Err("native_approval_v4_authority_generation_rollback".to_owned());
        }
        // Write the counter record before the public authority file so an
        // explicit enrollment attempt can recover an interrupted replacement.
        let initial_counter = match existing_secure_state.as_ref() {
            Some(state)
                if secure_state_matches_record(
                    state,
                    &candidate,
                    &candidate_digest,
                    &candidate_credential_id,
                    &candidate_cose,
                ) =>
            {
                state.sign_count
            }
            _ => match current.as_ref() {
                Some((current, current_bytes)) => {
                    let (current_credential_id, current_cose) = validate_record(current)?;
                    let state = existing_secure_state
                        .as_ref()
                        .ok_or_else(|| "native_approval_v4_secure_state_unavailable".to_owned())?;
                    if !secure_state_matches_record(
                        state,
                        current,
                        &guard_policy_snapshot::digest_bytes(current_bytes),
                        &current_credential_id,
                        &current_cose,
                    ) {
                        return Err("native_approval_v4_authority_provenance_mismatch".to_owned());
                    }
                    0
                }
                None => match existing_secure_state.as_ref() {
                    Some(state) => {
                        if !secure_state_matches_record(
                            state,
                            &candidate,
                            &candidate_digest,
                            &candidate_credential_id,
                            &candidate_cose,
                        ) {
                            return Err(
                                "native_approval_v4_authority_generation_rollback".to_owned()
                            );
                        }
                        state.sign_count
                    }
                    None => 0,
                },
            },
        };
        let authority = ApprovalV4Authority {
            credential_id: candidate_credential_id,
            cose_public_key: candidate_cose,
            algorithm: candidate.algorithm,
            rp_id: candidate.rp_id.clone(),
            origin: candidate.origin.clone(),
            key_id: candidate.key_id.clone(),
            device_binding: candidate.device_binding.clone(),
            installation_binding: candidate.installation_binding.clone(),
            enrollment_generation: candidate.enrollment_generation,
            status: candidate.status.clone(),
            path: target.clone(),
            fingerprint: String::new(),
            record_digest: candidate_digest,
            state_base: state_base.to_owned(),
            sign_count: Arc::new(Mutex::new(initial_counter)),
            assertions: Arc::new(Mutex::new(HashMap::new())),
        };
        let state = secure_state_value(&authority, initial_counter)?;
        super::approval_v4_secure_state::store(state_base, &state)?;
        super::policy_store_persistence::persist_private_bytes(
            &target,
            &bytes,
            AUTHORITY_MAX_BYTES,
            "approval_authority_v4",
            &private_root,
        )?;
        Ok(())
    })
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

pub(crate) use super::approval_v4_assertion_state::{
    assertion_matches, forget_assertion, remember_assertion,
};

#[cfg(test)]
#[path = "approval_v4_authority_tests.rs"]
pub(crate) mod tests;
