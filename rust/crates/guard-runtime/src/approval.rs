#![forbid(unsafe_code)]

//! Native, request-bound approval validation.
//!
//! The presentation layer may display a challenge and return a signed
//! artifact, but this module is the authority that reconstructs the action,
//! validates every binding, and atomically claims the one-use nonce.  Raw
//! command text, paths, URLs, prompts, and source content never enter a
//! challenge, result, receipt, or resident replay record.

use guard_contracts::{
    ApprovalArtifactV3, ApprovalChallengeRequestV3, ApprovalConsumeRequestV3, ApprovalReceiptV3,
    ApprovalResultV3, ApprovalValidateRequestV3, NATIVE_APPROVAL_ARTIFACT_V3_SCHEMA,
    NATIVE_APPROVAL_CHALLENGE_REQUEST_V3_SCHEMA, NATIVE_APPROVAL_CONSUME_REQUEST_V3_SCHEMA,
    NATIVE_APPROVAL_INTEGRITY_ALGORITHM, NATIVE_APPROVAL_INTEGRITY_DOMAIN,
    NATIVE_APPROVAL_MAX_BYTES, NATIVE_APPROVAL_MAX_CLOCK_SKEW_MS, NATIVE_APPROVAL_MAX_REASON_BYTES,
    NATIVE_APPROVAL_MAX_STRING_BYTES, NATIVE_APPROVAL_MAX_TTL_MS, NATIVE_APPROVAL_NONCE_BYTES,
    NATIVE_APPROVAL_RECEIPT_V3_SCHEMA, NATIVE_APPROVAL_RESPONSE_MAX_BYTES,
    NATIVE_APPROVAL_RESULT_V3_SCHEMA, NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA,
    NATIVE_PROTOCOL_VERSION,
};
use guard_policy_snapshot::{canonical_json_bytes, verifier_key_id};
use ring::signature;
#[cfg(test)]
use ring::signature::KeyPair;
use serde::Serialize;

#[path = "approval_replay_memory.rs"]
pub(crate) mod approval_replay_memory;
pub(crate) use approval_replay_memory::{ApprovalReplayBinding, ApprovalReplayMemory};
#[path = "approval_v4.rs"]
pub(crate) mod approval_v4;
#[path = "approval_v4_crypto.rs"]
pub(crate) mod approval_v4_crypto;

const ACTION_IDENTITY_MAX_BYTES: usize = 4 * 1024;
const APPROVAL_DEFAULT_TTL_MS: u64 = 5 * 60 * 1000;
const APPROVAL_SCOPE_SCHEMA: &str = "guard-native-scope.v1";
const APPROVAL_RUNTIME_PACKAGE: &str = env!("CARGO_PKG_NAME");
const APPROVAL_RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");
#[path = "approval_context.rs"]
mod approval_context;

use approval_context::{
    bounded_string, challenge_from_context, derive_context_with_snapshot, encode_digest,
    ensure_context_approvable, is_approvable_floor, is_lower_hex, now_ms, replay_binding,
    valid_binding, ApprovalContext,
};

fn encode_approval_response<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let encoded = crate::encode_response(value)?;
    if encoded.len() > NATIVE_APPROVAL_RESPONSE_MAX_BYTES {
        return Err("native_approval_response_too_large".to_owned());
    }
    Ok(encoded)
}

pub(crate) fn create_challenge(
    request: ApprovalChallengeRequestV3,
    store: &crate::policy_store::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    if request.schema != NATIVE_APPROVAL_CHALLENGE_REQUEST_V3_SCHEMA || request.version != 3 {
        return Err("native_approval_challenge_request_invalid".to_owned());
    }
    store.with_approval_fence(&request.envelope, |snapshot| {
        let context = derive_context_with_snapshot(&request.envelope, store, snapshot)?;
        ensure_context_approvable(&context)?;
        let issued_at_ms = now_ms()?;
        let expires_at_ms = issued_at_ms
            .checked_add(APPROVAL_DEFAULT_TTL_MS)
            .ok_or_else(|| "native_approval_clock_invalid".to_owned())?;
        let mut nonce = [0u8; NATIVE_APPROVAL_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| "native_approval_random_failed".to_owned())?;
        let signing_key_id = store.approval_signing_key_id()?;
        let challenge = challenge_from_context(
            &context,
            hex::encode(nonce),
            issued_at_ms,
            expires_at_ms,
            signing_key_id,
            store.approval_resident_epoch().to_owned(),
        );
        let encoded = encode_approval_response(&challenge)?;
        let binding = replay_binding(&context, expires_at_ms);
        store.register_approval_challenge(&encode_digest(&nonce), binding, issued_at_ms)?;
        Ok(encoded)
    })
}

fn artifact_signing_bytes(artifact: &ApprovalArtifactV3) -> Result<Vec<u8>, String> {
    let mut value = serde_json::to_value(artifact)
        .map_err(|_| "native_approval_artifact_serialization_failed".to_owned())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "native_approval_artifact_serialization_failed".to_owned())?;
    object.remove("integrity");
    let bytes = canonical_json_bytes(&value)
        .map_err(|_| "native_approval_artifact_serialization_failed".to_owned())?;
    if bytes.len() > NATIVE_APPROVAL_MAX_BYTES {
        return Err("native_approval_artifact_too_large".to_owned());
    }
    Ok(bytes)
}

fn approval_signature(artifact: &ApprovalArtifactV3, public_key: &[u8; 32]) -> Result<(), String> {
    let signature = hex::decode(&artifact.integrity.signature)
        .map_err(|_| "native_approval_integrity_invalid".to_owned())?;
    if signature.len() != 64 {
        return Err("native_approval_integrity_invalid".to_owned());
    }
    let mut message = Vec::with_capacity(NATIVE_APPROVAL_INTEGRITY_DOMAIN.len() + 4096);
    message.extend_from_slice(NATIVE_APPROVAL_INTEGRITY_DOMAIN);
    message.extend_from_slice(&artifact_signing_bytes(artifact)?);
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(&message, &signature)
        .map_err(|_| "native_approval_integrity_mismatch".to_owned())
}

#[cfg(test)]
fn approval_signature_for_tests(
    artifact: &ApprovalArtifactV3,
    signing_key: &[u8; 32],
) -> Result<String, String> {
    let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(signing_key)
        .map_err(|_| "native_approval_integrity_invalid".to_owned())?;
    let mut message = Vec::with_capacity(NATIVE_APPROVAL_INTEGRITY_DOMAIN.len() + 4096);
    message.extend_from_slice(NATIVE_APPROVAL_INTEGRITY_DOMAIN);
    message.extend_from_slice(&artifact_signing_bytes(artifact)?);
    Ok(hex::encode(key_pair.sign(&message).as_ref()))
}

#[cfg(test)]
fn approval_public_key_for_tests(signing_key: &[u8; 32]) -> [u8; 32] {
    let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(signing_key).unwrap();
    key_pair.public_key().as_ref().try_into().unwrap()
}

fn validate_times(issued_at_ms: u64, expires_at_ms: u64, now: u64) -> Result<(), String> {
    if expires_at_ms <= issued_at_ms
        || expires_at_ms - issued_at_ms > NATIVE_APPROVAL_MAX_TTL_MS
        || issued_at_ms > now.saturating_add(NATIVE_APPROVAL_MAX_CLOCK_SKEW_MS)
        || expires_at_ms <= now
        || expires_at_ms
            > now
                .saturating_add(NATIVE_APPROVAL_MAX_TTL_MS)
                .saturating_add(NATIVE_APPROVAL_MAX_CLOCK_SKEW_MS)
    {
        return Err("native_approval_time_invalid".to_owned());
    }
    Ok(())
}

fn validate_artifact(
    artifact: &ApprovalArtifactV3,
    context: &ApprovalContext,
    store: &crate::policy_store::PolicySnapshotStore,
    now: u64,
) -> Result<[u8; NATIVE_APPROVAL_NONCE_BYTES], String> {
    let encoded =
        serde_json::to_vec(artifact).map_err(|_| "native_approval_artifact_invalid".to_owned())?;
    if encoded.is_empty() || encoded.len() > NATIVE_APPROVAL_MAX_BYTES {
        return Err("native_approval_artifact_too_large".to_owned());
    }
    if artifact.schema != NATIVE_APPROVAL_ARTIFACT_V3_SCHEMA || artifact.version != 3 {
        return Err("native_approval_artifact_schema_mismatch".to_owned());
    }
    bounded_string(
        &artifact.request_id,
        false,
        NATIVE_APPROVAL_MAX_STRING_BYTES,
        "native_approval_artifact_invalid",
    )?;
    if artifact.request_id != context.request_id
        || artifact.request_digest != context.request_digest
        || artifact.action_digest != context.action_digest
        || artifact.action_type != context.action_type
        || artifact.operation != context.operation
        || artifact.intrinsic_action != context.intrinsic_action
        || artifact.minimum_action != context.minimum_action
        || artifact.floor_class != context.action_identity.floor_class
        || artifact.approval_eligible != context.action_identity.approval_eligible
        || artifact.policy_generation != context.policy_generation
        || artifact.policy_digest != context.policy_digest
        || artifact.rule_digest != context.rule_digest
        || artifact.runtime_identity != context.runtime_identity
        || artifact.runtime_binary_identity != context.runtime_identity
        || artifact.harness != context.harness
        || artifact.workspace_binding != context.workspace_binding
        || artifact.device_binding != context.device_binding
        || artifact.installation_binding != context.installation_binding
        || artifact.publisher_binding != context.publisher_binding
        || artifact.artifact_binding != context.artifact_binding
        || artifact.scope_contract_version != context.scope_contract_version
        || artifact.scope_contract_digest != context.scope_contract_digest
        || artifact.scope_binding != context.scope_binding
        || artifact.resident_epoch != store.approval_resident_epoch()
    {
        return Err("native_approval_binding_mismatch".to_owned());
    }
    if artifact.runtime_protocol_version != NATIVE_PROTOCOL_VERSION
        || artifact.runtime_package != APPROVAL_RUNTIME_PACKAGE
        || artifact.runtime_version != APPROVAL_RUNTIME_VERSION
        || artifact.scope_contract_version != APPROVAL_SCOPE_SCHEMA
    {
        return Err("native_approval_runtime_mismatch".to_owned());
    }
    if !is_lower_hex(&artifact.resident_epoch, 64) {
        return Err("native_approval_binding_mismatch".to_owned());
    }
    for digest in [
        artifact.request_digest.as_str(),
        artifact.action_digest.as_str(),
        artifact.policy_digest.as_str(),
        artifact.rule_digest.as_str(),
        artifact.runtime_identity.as_str(),
        artifact.runtime_binary_identity.as_str(),
        artifact.scope_contract_digest.as_str(),
    ] {
        if !is_lower_hex(digest, 64) {
            return Err("native_approval_digest_invalid".to_owned());
        }
    }
    valid_binding(artifact.workspace_binding.as_ref())?;
    valid_binding(artifact.device_binding.as_ref())?;
    valid_binding(artifact.installation_binding.as_ref())?;
    valid_binding(artifact.publisher_binding.as_ref())?;
    valid_binding(artifact.artifact_binding.as_ref())?;
    valid_binding(artifact.scope_binding.as_ref())?;
    if !is_approvable_floor(&artifact.requested_action)
        || artifact.requested_action != context.minimum_action
        || artifact.approved_action != "allow"
    {
        return Err("native_approval_action_not_approvable".to_owned());
    }
    if artifact.intrinsic_action != context.action_identity.intrinsic_action
        || artifact.minimum_action != context.action_identity.minimum_action
    {
        return Err("native_approval_floor_mismatch".to_owned());
    }
    validate_times(artifact.issued_at_ms, artifact.expires_at_ms, now)?;
    bounded_string(
        &artifact.nonce,
        false,
        NATIVE_APPROVAL_NONCE_BYTES * 2,
        "native_approval_nonce_invalid",
    )?;
    if !is_lower_hex(&artifact.nonce, NATIVE_APPROVAL_NONCE_BYTES * 2) {
        return Err("native_approval_nonce_invalid".to_owned());
    }
    let nonce_bytes =
        hex::decode(&artifact.nonce).map_err(|_| "native_approval_nonce_invalid".to_owned())?;
    let nonce: [u8; NATIVE_APPROVAL_NONCE_BYTES] = nonce_bytes
        .try_into()
        .map_err(|_| "native_approval_nonce_invalid".to_owned())?;
    if artifact.integrity.algorithm != NATIVE_APPROVAL_INTEGRITY_ALGORITHM
        || !is_lower_hex(&artifact.integrity.key_id, 64)
        || !is_lower_hex(&artifact.integrity.signature, 128)
    {
        return Err("native_approval_integrity_invalid".to_owned());
    }
    let key = store.read_approval_public_key()?;
    if artifact.integrity.key_id != verifier_key_id(&key) {
        return Err("native_approval_integrity_mismatch".to_owned());
    }
    approval_signature(artifact, &key)?;
    // The snapshot is revalidated after all artifact fields have been parsed;
    // a policy rollback or runtime/rule mismatch therefore cannot be hidden by
    // an otherwise valid artifact.
    let snapshot = store.current_snapshot()?;
    if snapshot.generation != context.policy_generation
        || snapshot.policy_digest != context.policy_digest
        || snapshot.rule_digest != context.rule_digest
        || snapshot.runtime_identity != context.runtime_identity
    {
        return Err("native_approval_policy_context_mismatch".to_owned());
    }
    Ok(nonce)
}

struct ReceiptStatus {
    phase: &'static str,
    decision: &'static str,
    approved_action: Option<String>,
    reason_code: &'static str,
    nonce_digest: String,
    replay_claimed: bool,
}

fn approval_receipt(
    context: &ApprovalContext,
    artifact: &ApprovalArtifactV3,
    status: ReceiptStatus,
) -> ApprovalResultV3 {
    let bounded_reason = if status.reason_code.len() <= NATIVE_APPROVAL_MAX_REASON_BYTES {
        status.reason_code.to_owned()
    } else {
        "native_approval_failed".to_owned()
    };
    ApprovalResultV3 {
        schema: NATIVE_APPROVAL_RESULT_V3_SCHEMA.to_owned(),
        version: 3,
        authority: "rust".to_owned(),
        receipt: ApprovalReceiptV3 {
            schema: NATIVE_APPROVAL_RECEIPT_V3_SCHEMA.to_owned(),
            version: 3,
            phase: status.phase.to_owned(),
            request_id: context.request_id.clone(),
            request_digest: context.request_digest.clone(),
            action_digest: context.action_digest.clone(),
            policy_generation: context.policy_generation,
            policy_digest: context.policy_digest.clone(),
            rule_digest: context.rule_digest.clone(),
            runtime_identity: context.runtime_identity.clone(),
            runtime_protocol_version: NATIVE_PROTOCOL_VERSION,
            runtime_package: APPROVAL_RUNTIME_PACKAGE.to_owned(),
            runtime_version: APPROVAL_RUNTIME_VERSION.to_owned(),
            runtime_binary_identity: context.runtime_identity.clone(),
            harness: context.harness.clone(),
            workspace_binding: context.workspace_binding.clone(),
            device_binding: context.device_binding.clone(),
            installation_binding: context.installation_binding.clone(),
            publisher_binding: context.publisher_binding.clone(),
            artifact_binding: context.artifact_binding.clone(),
            scope_contract_version: context.scope_contract_version.clone(),
            scope_contract_digest: context.scope_contract_digest.clone(),
            scope_binding: context.scope_binding.clone(),
            resident_epoch: artifact.resident_epoch.clone(),
            nonce: artifact.nonce.clone(),
            issued_at_ms: artifact.issued_at_ms,
            expires_at_ms: artifact.expires_at_ms,
            decision: status.decision.to_owned(),
            requested_action: context.minimum_action.clone(),
            approved_action: status.approved_action,
            reason_code: bounded_reason,
            nonce_digest: status.nonce_digest,
            replay_claimed: status.replay_claimed,
        },
    }
}

pub(crate) fn validate_approval(
    request: ApprovalValidateRequestV3,
    store: &crate::policy_store::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    if request.schema != NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA || request.version != 3 {
        return Err("native_approval_validate_request_invalid".to_owned());
    }
    let context = store
        .with_approval_fence(&request.envelope, |snapshot| {
            derive_context_with_snapshot(&request.envelope, store, snapshot)
        })
        .map_err(|error| {
            if matches!(
                error.as_str(),
                "native_policy_snapshot_context_mismatch" | "native_policy_snapshot_not_current"
            ) {
                "native_approval_policy_context_mismatch".to_owned()
            } else {
                error
            }
        })?;
    ensure_context_approvable(&context)?;
    let now = now_ms()?;
    let nonce = validate_artifact(&request.artifact, &context, store, now)?;
    let nonce_digest = encode_digest(&nonce);
    let replay_binding = replay_binding(&context, request.artifact.expires_at_ms);
    let receipt_nonce_digest = nonce_digest.clone();
    let policy_fence = crate::policy_store::ApprovalPolicyFence {
        generation: context.policy_generation,
        policy_digest: &context.policy_digest,
        rule_digest: &context.rule_digest,
        runtime_identity: &context.runtime_identity,
    };
    store.claim_approval_nonce_fenced(
        &request.artifact.resident_epoch,
        &nonce_digest,
        &replay_binding,
        now,
        &policy_fence,
        || {
            encode_approval_response(&approval_receipt(
                &context,
                &request.artifact,
                ReceiptStatus {
                    phase: "validated",
                    decision: "allow",
                    approved_action: Some("allow".to_owned()),
                    reason_code: "native_approval_validated",
                    nonce_digest: receipt_nonce_digest,
                    replay_claimed: true,
                },
            ))
        },
    )
}

/// Consume a previously claimed approval as the final native gate before the
/// harness continues. The artifact is revalidated and the resident entry is
/// atomically marked consumed while the current policy fence is held. A
/// caller cannot manufacture a Python-only receipt or consume an artifact
/// that was never claimed by Rust.
pub(crate) fn consume_approval(
    request: ApprovalConsumeRequestV3,
    store: &crate::policy_store::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    if request.schema != NATIVE_APPROVAL_CONSUME_REQUEST_V3_SCHEMA || request.version != 3 {
        return Err("native_approval_consume_request_invalid".to_owned());
    }
    let context = store
        .with_approval_fence(&request.envelope, |snapshot| {
            derive_context_with_snapshot(&request.envelope, store, snapshot)
        })
        .map_err(|error| {
            if matches!(
                error.as_str(),
                "native_policy_snapshot_context_mismatch" | "native_policy_snapshot_not_current"
            ) {
                "native_approval_policy_context_mismatch".to_owned()
            } else {
                error
            }
        })?;
    ensure_context_approvable(&context)?;
    let now = now_ms()?;
    let nonce = validate_artifact(&request.artifact, &context, store, now)?;
    let nonce_digest = encode_digest(&nonce);
    let replay_binding = replay_binding(&context, request.artifact.expires_at_ms);
    let policy_fence = crate::policy_store::ApprovalPolicyFence {
        generation: context.policy_generation,
        policy_digest: &context.policy_digest,
        rule_digest: &context.rule_digest,
        runtime_identity: &context.runtime_identity,
    };
    let receipt_nonce_digest = nonce_digest.clone();
    store.consume_approval_nonce_fenced(
        &request.artifact.resident_epoch,
        &nonce_digest,
        &replay_binding,
        now,
        &policy_fence,
        || {
            encode_approval_response(&approval_receipt(
                &context,
                &request.artifact,
                ReceiptStatus {
                    phase: "consumed",
                    decision: "allow",
                    approved_action: Some("allow".to_owned()),
                    reason_code: "native_approval_consumed",
                    nonce_digest: receipt_nonce_digest,
                    replay_claimed: true,
                },
            ))
        },
    )
}

#[cfg(test)]
#[path = "approval_v3_tests.rs"]
mod tests;
