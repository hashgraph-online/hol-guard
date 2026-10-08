use super::*;

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
            credential_id: encode_base64url(&authority.credential_id),
            algorithm: authority.algorithm,
            challenge: webauthn_challenge,
            user_verification: "required".to_owned(),
        },
    }
}

pub(crate) fn create_challenge(
    request: ApprovalChallengeRequestV4,
    store: &crate::policy_store::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    if request.schema != NATIVE_APPROVAL_CHALLENGE_REQUEST_V4_SCHEMA || request.version != 4 {
        return Err("native_approval_v4_challenge_request_invalid".to_owned());
    }
    create_challenge_bound(&request.envelope, store, None, |challenge| {
        encode_response(&challenge)
    })
}

pub(crate) fn create_cloud_review_challenge(
    envelope: &guard_contracts::GuardHookEnvelopeV2,
    store: &crate::policy_store::PolicySnapshotStore,
    original: Option<(&ApprovalChallengeV4, &str)>,
) -> Result<ApprovalChallengeV4, String> {
    create_challenge_bound(envelope, store, original, Ok)
}

fn create_challenge_bound<T, F>(
    envelope: &guard_contracts::GuardHookEnvelopeV2,
    store: &crate::policy_store::PolicySnapshotStore,
    original: Option<(&ApprovalChallengeV4, &str)>,
    emit: F,
) -> Result<T, String>
where
    F: FnOnce(ApprovalChallengeV4) -> Result<T, String>,
{
    store.with_approval_fence(envelope, |snapshot| {
        if snapshot.mode != "enforce" {
            return Err("native_cloud_review_v4_nonactionable_origin".into());
        }
        let context = derive_context_with_snapshot(envelope, store, snapshot)?;
        ensure_context_approvable(&context)?;
        let authority = store.approval_v4_authority()?;
        if !authority_bindings_match(&context, authority) {
            return Err("native_approval_v4_authority_provenance_mismatch".to_owned());
        }
        authority::with_verified_authority(authority, || {
            if let Some((original, fingerprint)) = original {
                authority::verify_renewal_authority(authority, original, fingerprint)?;
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
                nonce_hex,
                issued_at_ms,
                expires_at_ms,
                store.approval_resident_epoch().to_owned(),
                encode_base64url(&nonce),
                authority,
            );
            if original.is_some_and(|(original, _)| {
                !crate::policy_store::native_cloud_review_v4::same_business_identity(
                    original, &challenge,
                ) || original.nonce == challenge.nonce
            }) {
                return Err("native_cloud_review_v4_renewal_action_mismatch".into());
            }
            let emitted = emit(challenge)?;
            store.register_approval_challenge(
                &crate::approval::approval_context::encode_digest(&nonce),
                replay_binding(&context, expires_at_ms),
                issued_at_ms,
            )?;
            Ok(emitted)
        })
    })
}
