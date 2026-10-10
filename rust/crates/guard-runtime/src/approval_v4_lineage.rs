use super::*;
use guard_contracts::ApprovalChallengeV4;
use serde::{Deserialize, Serialize};

const MAX_ANCESTORS: usize = 64;

/// Only an installed, Root-authenticated active record may become an ancestor.
/// Its exact installed fingerprint preserves the original hook's authority pin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::policy_store) struct EnrollmentAncestor {
    pub(super) fingerprint: String,
    pub(super) record: ApprovalAuthorityV4,
}

fn same_bindings(record: &ApprovalAuthorityV4, authority: &ApprovalV4Authority) -> bool {
    record.device_binding == authority.device_binding
        && record.installation_binding == authority.installation_binding
        && record.rp_id == authority.rp_id
        && record.origin == authority.origin
}

pub(super) fn validate(authority: &ApprovalV4Authority) -> Result<(), String> {
    let ancestors = &authority.enrollment_lineage;
    if ancestors.len() > MAX_ANCESTORS || (authority.status != "active" && !ancestors.is_empty()) {
        return Err("native_approval_v4_authority_provenance_mismatch".into());
    }
    for (index, ancestor) in ancestors.iter().enumerate() {
        let record = &ancestor.record;
        let _ = validate_record(record)?;
        if !valid_hex(&ancestor.fingerprint, 32)
            || record.status != "active"
            || !same_bindings(record, authority)
        {
            return Err("native_approval_v4_authority_provenance_mismatch".into());
        }
        let (next_generation, next_previous) = ancestors.get(index + 1).map_or(
            (
                authority.enrollment_generation,
                authority.previous_key_id.as_deref(),
            ),
            |next| {
                (
                    next.record.enrollment_generation,
                    next.record.previous_key_id.as_deref(),
                )
            },
        );
        if next_generation <= record.enrollment_generation
            || next_previous != Some(record.key_id.as_str())
        {
            return Err("native_approval_v4_authority_provenance_mismatch".into());
        }
    }
    Ok(())
}

pub(crate) fn challenge_matches_authority(
    challenge: &ApprovalChallengeV4,
    authority: &ApprovalV4Authority,
) -> bool {
    challenge.signing_key_id == authority.key_id
        && challenge.device_binding.as_deref() == Some(authority.device_binding.as_str())
        && challenge.installation_binding.as_deref()
            == Some(authority.installation_binding.as_str())
        && challenge.webauthn.rp_id == authority.rp_id
        && challenge.webauthn.origin == authority.origin
        && challenge.webauthn.algorithm == authority.algorithm
        && challenge.webauthn.credential_id
            == crate::approval::approval_v4_crypto::encode_base64url(&authority.credential_id)
        && challenge.webauthn.user_verification == "required"
}

/// The original fingerprint is never weakened to key equality. A different pin
/// is accepted only as a protected, Root-signed predecessor of the current key.
pub(crate) fn verify_renewal_authority(
    authority: &ApprovalV4Authority,
    original: &ApprovalChallengeV4,
    original_fingerprint: &str,
) -> Result<(), String> {
    if authority.status != "active" {
        return Err("native_approval_v4_authority_revoked".into());
    }
    if original_fingerprint == authority.fingerprint {
        return if challenge_matches_authority(original, authority) {
            Ok(())
        } else {
            Err("native_approval_v4_authority_provenance_mismatch".into())
        };
    }
    validate(authority)?;
    let ancestor = authority
        .enrollment_lineage
        .iter()
        .find(|ancestor| ancestor.fingerprint == original_fingerprint)
        .ok_or("native_approval_v4_authority_changed")?;
    let record = &ancestor.record;
    if original.signing_key_id != record.key_id
        || record.key_id == authority.key_id
        || record.credential_id == hex::encode(&authority.credential_id)
        || original.device_binding.as_deref() != Some(record.device_binding.as_str())
        || original.installation_binding.as_deref() != Some(record.installation_binding.as_str())
        || original.webauthn.rp_id != record.rp_id
        || original.webauthn.origin != record.origin
        || original.webauthn.algorithm != record.algorithm
        || original.webauthn.user_verification != "required"
    {
        return Err("native_approval_v4_authority_provenance_mismatch".into());
    }
    let credential_id = hex::decode(&record.credential_id)
        .map_err(|_| "native_approval_v4_authority_provenance_mismatch".to_owned())?;
    if original.webauthn.credential_id
        != crate::approval::approval_v4_crypto::encode_base64url(&credential_id)
    {
        return Err("native_approval_v4_authority_provenance_mismatch".into());
    }
    Ok(())
}
