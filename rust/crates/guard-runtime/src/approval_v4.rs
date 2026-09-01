#![forbid(unsafe_code)]

//! WebAuthn/passkey approval V4.
//!
//! V4 is deliberately parallel to V3. Rust reconstructs the action and all
//! policy/runtime/scope bindings, verifies the browser assertion, advances
//! the resident counter, then claims and consumes the existing one-shot
//! replay entry. Python only forwards the browser response.

use super::approval_context::{
    derive_context_with_snapshot, ensure_context_approvable, is_lower_hex, now_ms, replay_binding,
    ApprovalContext,
};
use super::approval_v4_crypto::{encode_base64url, verify_assertion, VerifiedAssertion};
use crate::policy_store::approval_v4_authority as authority;
use guard_contracts::{
    ApprovalArtifactV4, ApprovalChallengeRequestV4, ApprovalChallengeV4, ApprovalConsumeRequestV4,
    ApprovalReceiptV4, ApprovalResultV4, ApprovalValidateRequestV4,
    NATIVE_APPROVAL_ARTIFACT_V4_SCHEMA, NATIVE_APPROVAL_CHALLENGE_REQUEST_V4_SCHEMA,
    NATIVE_APPROVAL_CONSUME_REQUEST_V4_SCHEMA, NATIVE_APPROVAL_RECEIPT_V4_SCHEMA,
    NATIVE_APPROVAL_RESULT_V4_SCHEMA, NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde::Serialize;

const APPROVAL_SCOPE_SCHEMA: &str = "guard-native-scope.v1";
const RUNTIME_PACKAGE: &str = env!("CARGO_PKG_NAME");
const RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_TTL_MS: u64 = 5 * 60 * 1000;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024;

fn encode_response<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let encoded = crate::encode_response(value)?;
    if encoded.len() > guard_contracts::NATIVE_APPROVAL_RESPONSE_MAX_BYTES {
        return Err("native_approval_response_too_large".to_owned());
    }
    Ok(encoded)
}

fn nonce_bytes(nonce: &str) -> Result<[u8; 32], String> {
    if !is_lower_hex(nonce, 64) {
        return Err("native_approval_nonce_invalid".to_owned());
    }
    hex::decode(nonce)
        .map_err(|_| "native_approval_nonce_invalid".to_owned())?
        .try_into()
        .map_err(|_| "native_approval_nonce_invalid".to_owned())
}

fn challenge_from_context(
    context: &ApprovalContext,
    nonce: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    resident_epoch: String,
    webauthn_challenge: String,
    authority: &authority::ApprovalV4Authority,
) -> ApprovalChallengeV4 {
    ApprovalChallengeV4 {
        schema: guard_contracts::NATIVE_APPROVAL_CHALLENGE_V4_SCHEMA.to_owned(),
        version: 4,
        request_id: context.request_id.clone(),
        request_digest: context.request_digest.clone(),
        action_digest: context.action_digest.clone(),
        action_type: context.action_type,
        operation: context.operation,
        intrinsic_action: context.intrinsic_action.clone(),
        minimum_action: context.minimum_action.clone(),
        floor_class: context.action_identity.floor_class,
        approval_eligible: context.action_identity.approval_eligible,
        policy_generation: context.policy_generation,
        policy_digest: context.policy_digest.clone(),
        rule_digest: context.rule_digest.clone(),
        runtime_identity: context.runtime_identity.clone(),
        runtime_protocol_version: guard_contracts::NATIVE_PROTOCOL_VERSION,
        runtime_package: RUNTIME_PACKAGE.to_owned(),
        runtime_version: RUNTIME_VERSION.to_owned(),
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
        resident_epoch,
        nonce,
        issued_at_ms,
        expires_at_ms,
        requested_action: context.minimum_action.clone(),
        signing_key_id: authority.key_id.clone(),
        webauthn: guard_contracts::WebAuthnChallengeV4 {
            rp_id: authority.rp_id.clone(),
            origin: authority.origin.clone(),
            // Browser WebAuthn options use the credential identifier's
            // canonical, unpadded base64url representation. The enrollment
            // record remains lower-case hex so Rust can perform exact byte
            // comparisons without trusting a presentation decoder.
            credential_id: super::approval_v4_crypto::encode_base64url(&authority.credential_id),
            algorithm: authority.algorithm,
            challenge: webauthn_challenge,
            user_verification: "required".to_owned(),
        },
    }
}

fn common_matches(context: &ApprovalContext, artifact: &ApprovalArtifactV4) -> bool {
    artifact.request_id == context.request_id
        && artifact.request_digest == context.request_digest
        && artifact.action_digest == context.action_digest
        && artifact.action_type == context.action_type
        && artifact.operation == context.operation
        && artifact.intrinsic_action == context.intrinsic_action
        && artifact.minimum_action == context.minimum_action
        && artifact.floor_class == context.action_identity.floor_class
        && artifact.approval_eligible == context.action_identity.approval_eligible
        && artifact.policy_generation == context.policy_generation
        && artifact.policy_digest == context.policy_digest
        && artifact.rule_digest == context.rule_digest
        && artifact.runtime_identity == context.runtime_identity
        && artifact.runtime_binary_identity == context.runtime_identity
        && artifact.harness == context.harness
        && artifact.workspace_binding == context.workspace_binding
        && artifact.device_binding == context.device_binding
        && artifact.installation_binding == context.installation_binding
        && artifact.publisher_binding == context.publisher_binding
        && artifact.artifact_binding == context.artifact_binding
        && artifact.scope_contract_version == context.scope_contract_version
        && artifact.scope_contract_digest == context.scope_contract_digest
        && artifact.scope_binding == context.scope_binding
}

fn authority_bindings_match(
    context: &ApprovalContext,
    authority: &authority::ApprovalV4Authority,
) -> bool {
    context.device_binding.as_deref() == Some(authority.device_binding.as_str())
        && context.installation_binding.as_deref() == Some(authority.installation_binding.as_str())
}

fn validate_artifact(
    artifact: &ApprovalArtifactV4,
    context: &ApprovalContext,
    store: &crate::policy_store::PolicySnapshotStore,
    now: u64,
) -> Result<authority::ApprovalV4Authority, String> {
    let encoded = serde_json::to_vec(artifact)
        .map_err(|_| "native_approval_v4_artifact_invalid".to_owned())?;
    if encoded.is_empty() || encoded.len() > MAX_ARTIFACT_BYTES {
        return Err("native_approval_v4_artifact_invalid".to_owned());
    }
    if artifact.schema != NATIVE_APPROVAL_ARTIFACT_V4_SCHEMA || artifact.version != 4 {
        return Err("native_approval_v4_artifact_schema_mismatch".to_owned());
    }
    if !common_matches(context, artifact)
        || artifact.requested_action != context.minimum_action
        || artifact.approved_action != "allow"
        || artifact.resident_epoch != store.approval_resident_epoch()
        || artifact.scope_contract_version != APPROVAL_SCOPE_SCHEMA
        || artifact.runtime_protocol_version != guard_contracts::NATIVE_PROTOCOL_VERSION
        || artifact.runtime_package != RUNTIME_PACKAGE
        || artifact.runtime_version != RUNTIME_VERSION
        || !is_lower_hex(&artifact.resident_epoch, 64)
        || !is_lower_hex(&artifact.request_digest, 64)
        || !is_lower_hex(&artifact.action_digest, 64)
        || !is_lower_hex(&artifact.policy_digest, 64)
        || !is_lower_hex(&artifact.rule_digest, 64)
        || !is_lower_hex(&artifact.runtime_identity, 64)
        || !is_lower_hex(&artifact.runtime_binary_identity, 64)
        || !is_lower_hex(&artifact.scope_contract_digest, 64)
    {
        return Err("native_approval_v4_artifact_invalid".to_owned());
    }
    let authority = store.approval_v4_authority()?.clone();
    if !authority_bindings_match(context, &authority) || artifact.signing_key_id != authority.key_id
    {
        return Err("native_approval_v4_authority_provenance_mismatch".to_owned());
    }
    if artifact.issued_at_ms >= artifact.expires_at_ms
        || artifact.expires_at_ms - artifact.issued_at_ms
            > guard_contracts::NATIVE_APPROVAL_MAX_TTL_MS
        || artifact.expires_at_ms <= now
        || !is_lower_hex(&artifact.nonce, 64)
    {
        return Err("native_approval_v4_artifact_invalid".to_owned());
    }
    super::validate_times(artifact.issued_at_ms, artifact.expires_at_ms, now)?;
    Ok(authority)
}

fn context_and_store(
    envelope: &guard_contracts::GuardHookEnvelopeV2,
    store: &crate::policy_store::PolicySnapshotStore,
) -> Result<ApprovalContext, String> {
    store
        .with_approval_fence(envelope, |snapshot| {
            derive_context_with_snapshot(envelope, store, snapshot)
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
        })
}

pub(crate) fn create_challenge(
    request: ApprovalChallengeRequestV4,
    store: &crate::policy_store::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    if request.schema != NATIVE_APPROVAL_CHALLENGE_REQUEST_V4_SCHEMA || request.version != 4 {
        return Err("native_approval_v4_challenge_request_invalid".to_owned());
    }
    store.with_approval_fence(&request.envelope, |snapshot| {
        let context = derive_context_with_snapshot(&request.envelope, store, snapshot)?;
        ensure_context_approvable(&context)?;
        let authority = store.approval_v4_authority()?;
        if !authority_bindings_match(&context, authority) {
            return Err("native_approval_v4_authority_provenance_mismatch".to_owned());
        }
        let issued_at_ms = now_ms()?;
        let expires_at_ms = issued_at_ms
            .checked_add(DEFAULT_TTL_MS)
            .ok_or_else(|| "native_approval_v4_artifact_invalid".to_owned())?;
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| "native_approval_random_failed".to_owned())?;
        let nonce_hex = hex::encode(nonce);
        let challenge = challenge_from_context(
            &context,
            nonce_hex.clone(),
            issued_at_ms,
            expires_at_ms,
            store.approval_resident_epoch().to_owned(),
            encode_base64url(&nonce),
            authority,
        );
        let encoded = encode_response(&challenge)?;
        store.register_approval_challenge(
            &super::approval_context::encode_digest(&nonce),
            replay_binding(&context, expires_at_ms),
            issued_at_ms,
        )?;
        Ok(encoded)
    })
}

fn receipt(
    context: &ApprovalContext,
    artifact: &ApprovalArtifactV4,
    authority: &authority::ApprovalV4Authority,
    phase: &str,
    reason_code: &str,
    nonce_digest: String,
    authenticator_sign_count: u32,
) -> ApprovalResultV4 {
    ApprovalResultV4 {
        schema: NATIVE_APPROVAL_RESULT_V4_SCHEMA.to_owned(),
        version: 4,
        authority: "rust".to_owned(),
        receipt: ApprovalReceiptV4 {
            schema: NATIVE_APPROVAL_RECEIPT_V4_SCHEMA.to_owned(),
            version: 4,
            phase: phase.to_owned(),
            request_id: context.request_id.clone(),
            request_digest: context.request_digest.clone(),
            action_digest: context.action_digest.clone(),
            policy_generation: context.policy_generation,
            policy_digest: context.policy_digest.clone(),
            rule_digest: context.rule_digest.clone(),
            runtime_identity: context.runtime_identity.clone(),
            runtime_protocol_version: guard_contracts::NATIVE_PROTOCOL_VERSION,
            runtime_package: RUNTIME_PACKAGE.to_owned(),
            runtime_version: RUNTIME_VERSION.to_owned(),
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
            decision: "allow".to_owned(),
            requested_action: context.minimum_action.clone(),
            approved_action: Some("allow".to_owned()),
            reason_code: reason_code.to_owned(),
            nonce_digest,
            replay_claimed: true,
            rp_id: authority.rp_id.clone(),
            origin: authority.origin.clone(),
            credential_id_digest: digest_bytes(&authority.credential_id),
            algorithm: authority.algorithm,
            authenticator_sign_count,
        },
    }
}

fn validate_common(
    envelope: &guard_contracts::GuardHookEnvelopeV2,
    artifact: &ApprovalArtifactV4,
    store: &crate::policy_store::PolicySnapshotStore,
) -> Result<
    (
        ApprovalContext,
        authority::ApprovalV4Authority,
        [u8; 32],
        VerifiedAssertion,
    ),
    String,
> {
    let context = context_and_store(envelope, store)?;
    ensure_context_approvable(&context)?;
    let now = now_ms()?;
    let authority = validate_artifact(artifact, &context, store, now)?;
    let nonce = nonce_bytes(&artifact.nonce)?;
    let assertion = verify_assertion(
        &artifact.webauthn,
        &encode_base64url(&nonce),
        &authority.rp_id,
        &authority.origin,
        &authority.credential_id,
        &authority.cose_public_key,
        authority.algorithm,
    )?;
    Ok((context, authority, nonce, assertion))
}

pub(crate) fn validate_approval(
    request: ApprovalValidateRequestV4,
    store: &crate::policy_store::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    if request.schema != NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA || request.version != 4 {
        return Err("native_approval_v4_validate_request_invalid".to_owned());
    }
    let (context, authority, nonce, verified) =
        validate_common(&request.envelope, &request.artifact, store)?;
    let current = authority::sign_count(&authority)?;
    if current != 0 && verified.sign_count <= current {
        return Err("native_approval_v4_counter_replay".to_owned());
    }
    let assertion_digest = hex::encode(verified.assertion_digest);
    let nonce_digest = super::approval_context::encode_digest(&nonce);
    let binding = replay_binding(&context, request.artifact.expires_at_ms);
    let fence = crate::policy_store::ApprovalPolicyFence {
        generation: context.policy_generation,
        policy_digest: &context.policy_digest,
        rule_digest: &context.rule_digest,
        runtime_identity: &context.runtime_identity,
    };
    store.claim_approval_nonce_fenced(
        &request.artifact.resident_epoch,
        &nonce_digest,
        &binding,
        now_ms()?,
        &fence,
        || {
            let now = now_ms()?;
            authority::remember_assertion(
                &authority,
                &nonce_digest,
                assertion_digest.clone(),
                request.artifact.expires_at_ms,
                now,
            )?;
            let result = receipt(
                &context,
                &request.artifact,
                &authority,
                "validated",
                "native_approval_v4_validated",
                nonce_digest.clone(),
                verified.sign_count,
            );
            let encoded = match encode_response(&result) {
                Ok(encoded) => encoded,
                Err(error) => {
                    authority::forget_assertion(&authority, &nonce_digest)?;
                    return Err(error);
                }
            };
            if let Err(error) = authority::advance_sign_count(&authority, verified.sign_count) {
                authority::forget_assertion(&authority, &nonce_digest)?;
                return Err(error);
            }
            Ok(encoded)
        },
    )
}

pub(crate) fn consume_approval(
    request: ApprovalConsumeRequestV4,
    store: &crate::policy_store::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    if request.schema != NATIVE_APPROVAL_CONSUME_REQUEST_V4_SCHEMA || request.version != 4 {
        return Err("native_approval_v4_consume_request_invalid".to_owned());
    }
    let (context, authority, nonce, verified) =
        validate_common(&request.envelope, &request.artifact, store)?;
    let assertion_digest = hex::encode(verified.assertion_digest);
    let nonce_digest = super::approval_context::encode_digest(&nonce);
    if !authority::assertion_matches(&authority, &nonce_digest, &assertion_digest, now_ms()?)? {
        return Err("native_approval_v4_artifact_invalid".to_owned());
    }
    let binding = replay_binding(&context, request.artifact.expires_at_ms);
    let fence = crate::policy_store::ApprovalPolicyFence {
        generation: context.policy_generation,
        policy_digest: &context.policy_digest,
        rule_digest: &context.rule_digest,
        runtime_identity: &context.runtime_identity,
    };
    store.consume_approval_nonce_fenced(
        &request.artifact.resident_epoch,
        &nonce_digest,
        &binding,
        now_ms()?,
        &fence,
        || {
            let encoded = encode_response(&receipt(
                &context,
                &request.artifact,
                &authority,
                "consumed",
                "native_approval_v4_consumed",
                nonce_digest.clone(),
                verified.sign_count,
            ))?;
            authority::forget_assertion(&authority, &nonce_digest)?;
            Ok(encoded)
        },
    )
}

#[cfg(test)]
#[path = "approval_v4_tests.rs"]
mod tests;
