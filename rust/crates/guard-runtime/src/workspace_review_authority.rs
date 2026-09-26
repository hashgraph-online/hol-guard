#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Root-authenticated workspace-review authority metadata.
//!
//! This module verifies a purpose-separated record with the existing
//! release-pinned Ed25519 root. It does not ingest Portal metadata or verify
//! RSA-PSS decisions; the resident consumes only this installed record.

use guard_contracts::{WorkspaceReviewAuthorityV1, NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const SHA256_HEX_BYTES: usize = 32;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
pub(crate) const AUTHORITY_FILE_NAME: &str = "workspace-review-authority.v1.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedWorkspaceReviewAuthority {
    pub(crate) key_id: String,
    pub(crate) public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    pub(crate) workspace_binding: String,
    pub(crate) device_binding: String,
    pub(crate) installation_binding: String,
    pub(crate) enrollment_generation: u64,
    pub(crate) previous_key_id: Option<String>,
    pub(crate) scope_contract_version: String,
    pub(crate) scope_binding: String,
    pub(crate) issued_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) status: String,
    pub(crate) record_digest: String,
}

#[path = "workspace_review_authority_contract.rs"]
mod contract;
#[cfg(test)]
pub(crate) use contract::{signing_bytes, verify_record_bytes};
pub(crate) use contract::{verify_record, verify_record_for_transition};

fn now_ms() -> Result<u64, String> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_millis();
    u64::try_from(value).map_err(|_| "native_resident_clock_invalid".to_owned())
}

fn read_record(
    path: &Path,
    private_root: &Path,
    now_ms: Option<u64>,
) -> Result<
    Option<(
        WorkspaceReviewAuthorityV1,
        Vec<u8>,
        VerifiedWorkspaceReviewAuthority,
    )>,
    String,
> {
    let Some((value, bytes)) = super::policy_store_persistence::read_private_json(
        path,
        NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES as u64,
        "workspace_review_authority",
        private_root,
    )
    .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?
    else {
        return Ok(None);
    };
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    if canonical != bytes {
        return Err("native_workspace_review_authority_noncanonical".to_owned());
    }
    let record: WorkspaceReviewAuthorityV1 = serde_json::from_value(value)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    let verified = match now_ms {
        Some(now_ms) => verify_record(&record, now_ms)?,
        None => verify_record_for_transition(&record)?,
    };
    Ok(Some((record, bytes, verified)))
}

fn trusted_local_bindings(state_base: &Path) -> Result<(String, String), String> {
    let enrollment = super::approval_enrollment::load_unlocked(state_base)?
        .ok_or_else(|| "native_workspace_review_enrollment_required".to_owned())?;
    if enrollment.status == "revoked" {
        return Err("native_workspace_review_authority_revoked".to_owned());
    }
    Ok((enrollment.device_binding, enrollment.installation_binding))
}

fn ensure_local_bindings(
    state_base: &Path,
    authority: &VerifiedWorkspaceReviewAuthority,
) -> Result<(), String> {
    let (device_binding, installation_binding) = trusted_local_bindings(state_base)?;
    if authority.device_binding != device_binding
        || authority.installation_binding != installation_binding
    {
        return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
    }
    Ok(())
}

fn pending_record(
    state: &super::workspace_review_secure_state::WorkspaceReviewSecureStateV1,
) -> Result<
    Option<(
        Vec<u8>,
        WorkspaceReviewAuthorityV1,
        VerifiedWorkspaceReviewAuthority,
    )>,
    String,
> {
    let Some(encoded) = state.pending_authority_record.as_ref() else {
        return Ok(None);
    };
    let bytes = encoded.as_bytes().to_vec();
    if digest_bytes(&bytes) != state.authority_record_digest {
        return Err("native_workspace_review_secure_state_invalid".to_owned());
    }
    let value = crate::strict_json_value(&bytes)
        .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
    if canonical != bytes {
        return Err("native_workspace_review_secure_state_invalid".to_owned());
    }
    let record: WorkspaceReviewAuthorityV1 = serde_json::from_value(value)
        .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
    let verified = verify_record_for_transition(&record)?;
    if !state.matches_authority(&verified) {
        return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
    }
    Ok(Some((bytes, record, verified)))
}

fn state_for_authority(
    authority: &VerifiedWorkspaceReviewAuthority,
    previous: Option<&super::workspace_review_secure_state::WorkspaceReviewSecureStateV1>,
    pending_bytes: Option<&[u8]>,
) -> Result<super::workspace_review_secure_state::WorkspaceReviewSecureStateV1, String> {
    let mut state =
        super::workspace_review_secure_state::WorkspaceReviewSecureStateV1::for_authority(
            authority,
        );
    if let Some(previous) = previous {
        state.consumed_claims = previous.consumed_claims.clone();
        state.last_observed_time_ms = previous.last_observed_time_ms;
    }
    if let Some(pending_bytes) = pending_bytes {
        state = state.with_pending_authority_record(pending_bytes)?;
    }
    Ok(state)
}

pub(crate) fn read_installed_record(
    state_base: &Path,
    now_ms: u64,
) -> Result<Option<VerifiedWorkspaceReviewAuthority>, String> {
    load_at(state_base, now_ms)
}

pub(crate) fn load(state_base: &Path) -> Result<Option<VerifiedWorkspaceReviewAuthority>, String> {
    let now_ms = now_ms()?;
    super::approval_enrollment::with_transition_lock(state_base, || load_at(state_base, now_ms))
}

fn load_at(
    state_base: &Path,
    now_ms: u64,
) -> Result<Option<VerifiedWorkspaceReviewAuthority>, String> {
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    let path = state_base.join(AUTHORITY_FILE_NAME);
    let state = super::workspace_review_secure_state::load(state_base)?;
    let mut target = read_record(&path, &private_root, None)?;
    if let Some(state) = state.as_ref() {
        if let Some((pending_bytes, _, pending_verified)) = pending_record(state)? {
            let target_matches_pending = target.as_ref().is_some_and(|(_, _, verified)| {
                verified.record_digest == pending_verified.record_digest
            });
            if !target_matches_pending {
                ensure_local_bindings(state_base, &pending_verified)?;
                super::policy_store_persistence::persist_private_bytes(
                    &path,
                    &pending_bytes,
                    NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES as u64,
                    "workspace_review_authority",
                    &private_root,
                )
                .map_err(|_| "native_workspace_review_authority_persistence_failed".to_owned())?;
                target = read_record(&path, &private_root, None)?;
            }
        }
    }
    let Some((record, _, transition_verified)) = target else {
        if state.is_some() {
            return Err("native_workspace_review_secure_state_unavailable".to_owned());
        }
        return Ok(None);
    };
    let verified = verify_record(&record, now_ms)?;
    if verified.record_digest != transition_verified.record_digest {
        return Err("native_workspace_review_authority_invalid".to_owned());
    }
    ensure_local_bindings(state_base, &verified)?;
    let mut state =
        state.ok_or_else(|| "native_workspace_review_secure_state_unavailable".to_owned())?;
    if !state.matches_authority(&verified) {
        if !state.can_transition_to(&verified) {
            if state.status == "revoked" {
                return Err("native_workspace_review_authority_revoked".to_owned());
            }
            return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
        }
        state = state_for_authority(&verified, Some(&state), None)?;
        super::workspace_review_secure_state::store(state_base, &state)?;
    }
    if state.pending_authority_record.is_some() {
        state.clear_pending_authority_record();
        super::workspace_review_secure_state::store(state_base, &state)?;
    }
    if verified.status == "revoked" {
        return Err("native_workspace_review_authority_revoked".to_owned());
    }
    Ok(Some(verified))
}

pub(crate) fn install_record(state_base: &Path, record_path: &Path) -> Result<(), String> {
    let now_ms = now_ms()?;
    super::approval_enrollment::with_transition_lock(state_base, || {
        install_record_at(state_base, record_path, now_ms)
    })
}

fn install_record_at(state_base: &Path, record_path: &Path, now_ms: u64) -> Result<(), String> {
    super::validate_private_directory(state_base)?;
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    let Some((_candidate, candidate_bytes, candidate_verified)) =
        read_record(record_path, &private_root, Some(now_ms))?
    else {
        return Err("native_workspace_review_authority_missing".to_owned());
    };
    ensure_local_bindings(state_base, &candidate_verified)?;
    let target = state_base.join(AUTHORITY_FILE_NAME);
    let current = read_record(&target, &private_root, None)?;
    let existing_state = super::workspace_review_secure_state::load(state_base)?;
    let candidate_state_matches = existing_state
        .as_ref()
        .is_some_and(|state| state.matches_authority(&candidate_verified));
    let current_state_matches = current.as_ref().and_then(|(_, _, verified)| {
        existing_state
            .as_ref()
            .filter(|state| state.matches_authority(verified))
    });

    if let Some((_, current_bytes, current_verified)) = current.as_ref() {
        if *current_bytes == candidate_bytes {
            let state = existing_state
                .as_ref()
                .ok_or_else(|| "native_workspace_review_secure_state_unavailable".to_owned())?;
            if !state.matches_authority(current_verified) {
                return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
            }
            if state.pending_authority_record.is_some() {
                let mut state = state.clone();
                state.clear_pending_authority_record();
                super::workspace_review_secure_state::store(state_base, &state)?;
            }
            return Ok(());
        }
        validate_transition(Some(current_verified), &candidate_verified)?;
        if existing_state.is_none() && !candidate_state_matches {
            return Err("native_workspace_review_secure_state_unavailable".to_owned());
        }
        if current_state_matches.is_none() && !candidate_state_matches {
            return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
        }
    } else if !candidate_state_matches {
        validate_transition(None, &candidate_verified)?;
        if existing_state.is_some() {
            return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
        }
    }

    let next_state = state_for_authority(
        &candidate_verified,
        existing_state.as_ref(),
        Some(&candidate_bytes),
    )?;
    super::workspace_review_secure_state::store(state_base, &next_state)?;
    super::policy_store_persistence::persist_private_bytes(
        &target,
        &candidate_bytes,
        NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES as u64,
        "workspace_review_authority",
        &private_root,
    )
    .map_err(|_| "native_workspace_review_authority_persistence_failed".to_owned())?;
    let mut committed_state = next_state;
    committed_state.clear_pending_authority_record();
    super::workspace_review_secure_state::store(state_base, &committed_state)
}

#[cfg(test)]
pub(crate) fn install_record_at_for_test(
    state_base: &Path,
    record_path: &Path,
    now_ms: u64,
) -> Result<(), String> {
    install_record_at(state_base, record_path, now_ms)
}

#[cfg(test)]
pub(crate) fn load_at_for_test(
    state_base: &Path,
    now_ms: u64,
) -> Result<Option<VerifiedWorkspaceReviewAuthority>, String> {
    load_at(state_base, now_ms)
}

pub(crate) fn validate_transition(
    current: Option<&VerifiedWorkspaceReviewAuthority>,
    candidate: &VerifiedWorkspaceReviewAuthority,
) -> Result<(), String> {
    let Some(current) = current else {
        if candidate.enrollment_generation == 1 && candidate.status == "active" {
            return Ok(());
        }
        return Err("native_workspace_review_authority_generation_invalid".to_owned());
    };
    if current.status == "revoked" {
        return Err("native_workspace_review_authority_revoked".to_owned());
    }
    if candidate.enrollment_generation <= current.enrollment_generation {
        return Err("native_workspace_review_authority_generation_rollback".to_owned());
    }
    if candidate.workspace_binding != current.workspace_binding
        || candidate.device_binding != current.device_binding
        || candidate.installation_binding != current.installation_binding
        || candidate.scope_contract_version != current.scope_contract_version
        || candidate.scope_binding != current.scope_binding
    {
        return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
    }
    if candidate.status == "active" {
        if candidate.previous_key_id.as_deref() != Some(current.key_id.as_str())
            || candidate.key_id == current.key_id
        {
            return Err("native_workspace_review_authority_generation_rollback".to_owned());
        }
    } else if candidate.key_id != current.key_id || candidate.previous_key_id.is_some() {
        return Err("native_workspace_review_authority_generation_rollback".to_owned());
    }
    Ok(())
}

#[cfg(test)]
#[path = "workspace_review_authority_tests.rs"]
mod tests;
