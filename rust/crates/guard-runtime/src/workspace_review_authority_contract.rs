#![forbid(unsafe_code)]

use super::VerifiedWorkspaceReviewAuthority;
#[cfg(test)]
use guard_contracts::NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES;
use guard_contracts::{
    WorkspaceReviewAuthorityV1, NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE,
    NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_SCHEMA, NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_VERSION,
    NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN, NATIVE_WORKSPACE_REVIEW_KEY_ALGORITHM_ED25519,
    NATIVE_WORKSPACE_REVIEW_MAX_SCOPE_BINDING_BYTES,
    NATIVE_WORKSPACE_REVIEW_MAX_SCOPE_VERSION_BYTES, NATIVE_WORKSPACE_REVIEW_MAX_TTL_MS,
    NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use ring::signature;
use serde_json::Value;

const SHA256_HEX_BYTES: usize = 32;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;

fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn signing_value(record: &WorkspaceReviewAuthorityV1) -> Result<Value, String> {
    let mut value = serde_json::to_value(record)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    value
        .as_object_mut()
        .ok_or_else(|| "native_workspace_review_authority_invalid".to_owned())?
        .remove("enrollment_signature");
    Ok(value)
}

pub(crate) fn signing_bytes(record: &WorkspaceReviewAuthorityV1) -> Result<Vec<u8>, String> {
    canonical_json_bytes(&signing_value(record)?)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())
}

fn root_public_key() -> Result<[u8; 32], String> {
    #[cfg(test)]
    {
        Ok(super::super::approval_authority::enrollment_root_public_key())
    }
    #[cfg(not(test))]
    {
        super::super::approval_authority::enrollment_root_public_key()
    }
}

fn verify_root_signature(record: &WorkspaceReviewAuthorityV1) -> Result<(), String> {
    let signature_bytes = hex::decode(&record.enrollment_signature)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    let signing = signing_bytes(record)?;
    let mut message =
        Vec::with_capacity(NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN.len() + signing.len());
    message.extend_from_slice(NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN);
    message.extend_from_slice(&signing);
    signature::UnparsedPublicKey::new(&signature::ED25519, root_public_key()?)
        .verify(&message, &signature_bytes)
        .map_err(|_| "native_workspace_review_authority_enrollment_invalid".to_owned())
}

fn validate_record(
    record: &WorkspaceReviewAuthorityV1,
    now_ms: Option<u64>,
) -> Result<([u8; ED25519_PUBLIC_KEY_BYTES], Vec<u8>), String> {
    if record.schema != NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_SCHEMA
        || record.version != NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_VERSION
        || record.purpose != NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE
        || record.key_algorithm != NATIVE_WORKSPACE_REVIEW_KEY_ALGORITHM_ED25519
        || record.enrollment_generation == 0
        || !matches!(record.status.as_str(), "active" | "revoked")
        || !valid_lower_hex(&record.key_id, SHA256_HEX_BYTES)
        || !valid_lower_hex(&record.public_key, ED25519_PUBLIC_KEY_BYTES)
        || !valid_lower_hex(&record.workspace_binding, SHA256_HEX_BYTES)
        || !valid_lower_hex(&record.device_binding, SHA256_HEX_BYTES)
        || !valid_lower_hex(&record.installation_binding, SHA256_HEX_BYTES)
        || record.device_binding == record.installation_binding
        || record.scope_contract_version != NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1
        || record.scope_contract_version.len() > NATIVE_WORKSPACE_REVIEW_MAX_SCOPE_VERSION_BYTES
        || !valid_lower_hex(
            &record.scope_binding,
            NATIVE_WORKSPACE_REVIEW_MAX_SCOPE_BINDING_BYTES / 2,
        )
        || record.issued_at_ms == 0
        || record.expires_at_ms <= record.issued_at_ms
        || record.expires_at_ms - record.issued_at_ms > NATIVE_WORKSPACE_REVIEW_MAX_TTL_MS
        || now_ms.is_some_and(|now| now < record.issued_at_ms || now >= record.expires_at_ms)
        || !valid_lower_hex(&record.enrollment_signature, ED25519_SIGNATURE_BYTES)
        || (record.enrollment_generation == 1
            && (record.previous_key_id.is_some() || record.status != "active"))
    {
        if let Some(now_ms) = now_ms {
            if now_ms >= record.expires_at_ms && record.expires_at_ms > record.issued_at_ms {
                return Err("native_workspace_review_authority_expired".to_owned());
            }
            if now_ms < record.issued_at_ms && record.expires_at_ms > record.issued_at_ms {
                return Err("native_workspace_review_authority_not_yet_valid".to_owned());
            }
        }
        if record.key_algorithm != NATIVE_WORKSPACE_REVIEW_KEY_ALGORITHM_ED25519 {
            return Err("native_workspace_review_authority_key_algorithm_unsupported".to_owned());
        }
        return Err("native_workspace_review_authority_invalid".to_owned());
    }
    if let Some(previous_key_id) = record.previous_key_id.as_ref() {
        if !valid_lower_hex(previous_key_id, SHA256_HEX_BYTES) {
            return Err("native_workspace_review_authority_generation_invalid".to_owned());
        }
        if previous_key_id == &record.key_id {
            return Err("native_workspace_review_authority_generation_invalid".to_owned());
        }
        if record.status == "revoked" {
            return Err("native_workspace_review_authority_generation_invalid".to_owned());
        }
    }
    let public_key_bytes = hex::decode(&record.public_key)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    let public_key: [u8; ED25519_PUBLIC_KEY_BYTES] = public_key_bytes
        .try_into()
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    if record.key_id != digest_bytes(&public_key) {
        return Err("native_workspace_review_authority_key_id_mismatch".to_owned());
    }
    verify_root_signature(record)?;
    let canonical_record = canonical_json_bytes(
        &serde_json::to_value(record)
            .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?,
    )
    .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    Ok((public_key, canonical_record))
}

pub(crate) fn verify_record(
    record: &WorkspaceReviewAuthorityV1,
    now_ms: u64,
) -> Result<VerifiedWorkspaceReviewAuthority, String> {
    let (public_key, canonical_record) = validate_record(record, Some(now_ms))?;
    Ok(verified_record(record, public_key, canonical_record))
}

/// Revalidate an existing root-signed record for a generation transition.
/// Expiry blocks use of the authority but must not erase its monotonic state.
pub(crate) fn verify_record_for_transition(
    record: &WorkspaceReviewAuthorityV1,
) -> Result<VerifiedWorkspaceReviewAuthority, String> {
    let (public_key, canonical_record) = validate_record(record, None)?;
    Ok(verified_record(record, public_key, canonical_record))
}

fn verified_record(
    record: &WorkspaceReviewAuthorityV1,
    public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    canonical_record: Vec<u8>,
) -> VerifiedWorkspaceReviewAuthority {
    VerifiedWorkspaceReviewAuthority {
        key_id: record.key_id.clone(),
        public_key,
        workspace_binding: record.workspace_binding.clone(),
        device_binding: record.device_binding.clone(),
        installation_binding: record.installation_binding.clone(),
        enrollment_generation: record.enrollment_generation,
        previous_key_id: record.previous_key_id.clone(),
        scope_contract_version: record.scope_contract_version.clone(),
        scope_binding: record.scope_binding.clone(),
        issued_at_ms: record.issued_at_ms,
        expires_at_ms: record.expires_at_ms,
        status: record.status.clone(),
        record_digest: digest_bytes(&canonical_record),
    }
}

#[cfg(test)]
pub(crate) fn verify_record_bytes(
    bytes: &[u8],
    now_ms: u64,
) -> Result<VerifiedWorkspaceReviewAuthority, String> {
    if bytes.is_empty() || bytes.len() > NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES {
        return Err("native_workspace_review_authority_invalid".to_owned());
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    if canonical != bytes {
        return Err("native_workspace_review_authority_noncanonical".to_owned());
    }
    let record: WorkspaceReviewAuthorityV1 = serde_json::from_value(value)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    verify_record(&record, now_ms)
}
