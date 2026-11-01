//! Check one signed trust attestation for a caller that holds no verifier.
//!
//! [`guard_command::attestation_verify`] owns the decision. This operation
//! only reads the caller's attestation and verifier state onto that function's
//! types and reports what it answered, so the only verifier in the product is
//! the one here.

use std::collections::BTreeSet;

use guard_command::attestation_verification::{
    TrustAttestationVerificationKey, TrustAttestationVerificationPolicy,
};
use guard_command::attestation_verify::verify_trust_attestation;
use guard_contracts::{
    TrustAttestationVerifyKeyV1, TrustAttestationVerifyPolicyV1, TrustAttestationVerifyRequestV1,
    TrustAttestationVerifyResultV1, TRUST_ATTESTATION_VERIFY_RESULT_SCHEMA,
};
use serde_json::json;

use crate::package_authority_op::request_digest_with_limit;

/// An attestation and the state it is checked against are small documents; a
/// request past this size is not one.
const TRUST_ATTESTATION_VERIFY_MAX_BYTES: usize = 1024 * 1024;

fn verification_key(key: &TrustAttestationVerifyKeyV1) -> TrustAttestationVerificationKey {
    TrustAttestationVerificationKey {
        key_id: key.key_id.clone(),
        public_key_pem: key.public_key_pem.clone(),
        fingerprint_sha256: key.fingerprint_sha256.clone(),
        public_jwk_thumbprint: key.public_jwk_thumbprint.clone(),
    }
}

fn verification_policy(
    policy: &TrustAttestationVerifyPolicyV1,
) -> TrustAttestationVerificationPolicy {
    TrustAttestationVerificationPolicy {
        revoked_key_ids: policy
            .revoked_key_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        key_not_before: policy.key_not_before.clone(),
        minimum_sequence: policy.minimum_sequence.clone(),
        seen_replay_keys: policy
            .seen_replay_keys
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        now: policy.now.clone(),
        require_nonce: policy.require_nonce,
    }
}

pub(crate) fn evaluate_trust_attestation_verify_request(
    request: &TrustAttestationVerifyRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, TRUST_ATTESTATION_VERIFY_MAX_BYTES)
        .map_err(|_| "native_trust_attestation_verify_too_large".to_owned())?;

    let trusted_keys = request
        .trusted_keys
        .as_ref()
        .map(|keys| keys.iter().map(verification_key).collect::<Vec<_>>());
    let policy = verification_policy(&request.policy);

    let payload = match verify_trust_attestation(
        &request.payload,
        &request.envelope,
        request.claim.as_ref(),
        trusted_keys.as_deref(),
        &policy,
    ) {
        Ok(replay_key) => json!({ "outcome": "verified", "replay_key": replay_key }),
        Err(refusal) => json!({ "outcome": "refused", "message": refusal.message() }),
    };

    crate::encode_response(&TrustAttestationVerifyResultV1 {
        schema: TRUST_ATTESTATION_VERIFY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload,
    })
}

#[cfg(test)]
#[path = "trust_attestation_verify_op_tests.rs"]
mod tests;
