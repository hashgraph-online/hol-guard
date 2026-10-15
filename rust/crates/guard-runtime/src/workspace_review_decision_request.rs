use super::*;
use crate::policy_store;

/// Verify one decision against the request snapshot selected by `request_id`.
/// The selector is not a binding input: all request and action material comes
/// from the private snapshot loaded by the resident.
pub(crate) fn verify_and_claim_request(
    policy_store: &policy_store::PolicySnapshotStore,
    request_id: &str,
    decision: &Value,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    let bytes = canonical_json_bytes(decision)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    claim_request(policy_store, request_id, &bytes, false).map(|(verified, _)| verified)
}

/// Private native-worker boundary. No serializable grant or mutable retry:
/// the worker receives owned input only after a fresh purpose-specific claim.
/// There is deliberately no resident RPC for exporting this value.
#[allow(dead_code)] // Worker routing is a separate integration; never enable legacy RPC dispatch.
pub(crate) fn claim_owned_business_request(
    policy_store: &policy_store::PolicySnapshotStore,
    request_id: &str,
    decision: &[u8],
) -> Result<
    (
        VerifiedWorkspaceReviewDecision,
        guard_command::business_input::PreparedBusinessInputV1,
    ),
    String,
> {
    let (verified, input) = claim_request(policy_store, request_id, decision, true)?;
    Ok((
        verified,
        input.ok_or_else(|| "native_workspace_review_business_input_missing".to_owned())?,
    ))
}

pub(crate) fn claim_owned_business_request_with<T>(
    policy_store: &policy_store::PolicySnapshotStore,
    request_id: &str,
    decision: &[u8],
    after_claim: impl FnOnce(
        &guard_command::business_input::PreparedBusinessInputV1,
        u64,
    ) -> Result<T, String>,
) -> Result<
    (
        VerifiedWorkspaceReviewDecision,
        guard_command::business_input::PreparedBusinessInputV1,
        T,
    ),
    String,
> {
    claim_owned_business_request_with_clock(policy_store, request_id, decision, now_ms, after_claim)
}

pub(crate) fn claim_owned_business_request_with_clock<T>(
    policy_store: &policy_store::PolicySnapshotStore,
    request_id: &str,
    decision: &[u8],
    clock: impl FnMut() -> Result<u64, String>,
    after_claim: impl FnOnce(
        &guard_command::business_input::PreparedBusinessInputV1,
        u64,
    ) -> Result<T, String>,
) -> Result<
    (
        VerifiedWorkspaceReviewDecision,
        guard_command::business_input::PreparedBusinessInputV1,
        T,
    ),
    String,
> {
    let envelope = decode_canonical_decision(decision)?;
    let clock = std::cell::RefCell::new(clock);
    let (mut verified, input, (after_claim, released_at_ms)) = claim_request_with_clock_and(
        policy_store,
        request_id,
        decision,
        true,
        || clock.borrow_mut()(),
        |input, claim_observed_at_ms| {
            let observed_time_ms = clock.borrow_mut()()?;
            if observed_time_ms < claim_observed_at_ms {
                return Err("native_workspace_review_clock_rollback".into());
            }
            let result = after_claim(
                input
                    .as_ref()
                    .ok_or_else(|| "native_workspace_review_business_input_missing".to_owned())?,
                observed_time_ms,
            )?;
            let release_time_ms = clock.borrow_mut()()?;
            if release_time_ms < observed_time_ms {
                return Err("native_workspace_review_clock_rollback".into());
            }
            if release_time_ms
                >= envelope
                    .expires_at_ms
                    .min(policy_store.current_snapshot()?.expires_at_ms)
            {
                return Err("native_workspace_review_decision_expired".into());
            }
            Ok((result, release_time_ms))
        },
    )?;
    verified.observed_at_ms = released_at_ms;
    Ok((
        verified,
        input.ok_or_else(|| "native_workspace_review_business_input_missing".to_owned())?,
        after_claim,
    ))
}

fn claim_request(
    policy_store: &policy_store::PolicySnapshotStore,
    request_id: &str,
    decision: &[u8],
    owned_dispatch: bool,
) -> Result<
    (
        VerifiedWorkspaceReviewDecision,
        Option<guard_command::business_input::PreparedBusinessInputV1>,
    ),
    String,
> {
    claim_request_with_clock(policy_store, request_id, decision, owned_dispatch, now_ms)
}

fn claim_request_with_clock(
    policy_store: &policy_store::PolicySnapshotStore,
    request_id: &str,
    decision: &[u8],
    owned_dispatch: bool,
    clock: impl FnMut() -> Result<u64, String>,
) -> Result<
    (
        VerifiedWorkspaceReviewDecision,
        Option<guard_command::business_input::PreparedBusinessInputV1>,
    ),
    String,
> {
    claim_request_with_clock_and(
        policy_store,
        request_id,
        decision,
        owned_dispatch,
        clock,
        |_, _| Ok(()),
    )
    .map(|(verified, input, ())| (verified, input))
}

fn claim_request_with_clock_and<T>(
    policy_store: &policy_store::PolicySnapshotStore,
    request_id: &str,
    decision: &[u8],
    owned_dispatch: bool,
    mut clock: impl FnMut() -> Result<u64, String>,
    after_claim: impl FnOnce(
        &Option<guard_command::business_input::PreparedBusinessInputV1>,
        u64,
    ) -> Result<T, String>,
) -> Result<
    (
        VerifiedWorkspaceReviewDecision,
        Option<guard_command::business_input::PreparedBusinessInputV1>,
        T,
    ),
    String,
> {
    let state_base = policy_store.state_base();
    policy_store::approval_enrollment::with_transition_lock(state_base, || {
        // The request snapshot supplies only action material. Workspace and
        // scope come from the current native policy store and state path, so
        // Python metadata cannot choose the authority's provenance.
        let snapshot = policy_store.current_snapshot()?;
        let (workspace_binding, scope_binding) = current_native_workspace_review_bindings(
            state_base,
            &snapshot.scope_contract.scope_digest,
        )?;
        let request = policy_store::workspace_review_request::load(policy_store, request_id)?;
        // This legacy response returns bindings, not owned provider bytes.
        // Never consume a business grant through a mutable-command retry path.
        if !owned_dispatch && request.business_input.is_some() {
            return Err("native_workspace_review_business_dispatch_unavailable".to_owned());
        }
        let envelope = decode_canonical_decision(decision)?;
        if owned_dispatch && (request.business_input.is_none() || envelope.decision != "allow") {
            return Err("native_workspace_review_business_dispatch_invalid".to_owned());
        }
        let authority =
            policy_store::workspace_review_authority::read_installed_record_without_time(
                state_base,
            )?
            .ok_or_else(|| "native_workspace_review_authority_missing".to_owned())?;
        ensure_current_native_workspace_review_provenance(
            &authority,
            &workspace_binding,
            &scope_binding,
        )?;
        let context = WorkspaceReviewDecisionContext {
            workspace_binding: &workspace_binding,
            device_binding: &authority.device_binding,
            installation_binding: &authority.installation_binding,
            scope_binding: &scope_binding,
            request_binding: &request.request_binding,
            action_binding: &request.action_binding,
            intent_binding: &request.intent_binding,
            revision_binding: &request.revision_binding,
            policy_binding: &request.policy_binding,
            retry_scope_binding: &request.retry_scope_binding,
        };
        // Snapshot loading and lock acquisition must not extend an approval.
        let mut verified = if owned_dispatch {
            let observed_time_ms = clock()?;
            let mut verified = verify_and_claim_at_mode(
                state_base,
                &envelope,
                &context,
                observed_time_ms,
                NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH,
            )?;
            // Durable claim storage can cross expiry too. Consume conservatively
            // but never release the input after that deadline.
            let release_time_ms = clock()?;
            if release_time_ms < observed_time_ms {
                return Err("native_workspace_review_clock_rollback".to_owned());
            }
            if release_time_ms >= envelope.expires_at_ms.min(snapshot.expires_at_ms) {
                return Err("native_workspace_review_decision_expired".to_owned());
            }
            verified.observed_at_ms = release_time_ms;
            verified
        } else {
            verify_and_claim_bytes_at(state_base, decision, &context, clock()?)?
        };
        verified.request_snapshot_digest = Some(request.request_snapshot_digest);
        let after_claim = after_claim(&request.business_input, verified.observed_at_ms)?;
        Ok((verified, request.business_input, after_claim))
    })
}

#[cfg(test)]
pub(crate) fn claim_owned_business_request_at_for_test(
    policy_store: &policy_store::PolicySnapshotStore,
    request_id: &str,
    decision: &[u8],
    times: [u64; 2],
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    let mut times = times.into_iter();
    claim_request_with_clock(policy_store, request_id, decision, true, || {
        times
            .next()
            .ok_or_else(|| "native_resident_clock_invalid".to_owned())
    })
    .map(|(verified, _)| verified)
}

pub(super) fn decode_canonical_decision(
    bytes: &[u8],
) -> Result<WorkspaceReviewDecisionEnvelopeV1, String> {
    if bytes.is_empty() || bytes.len() > NATIVE_WORKSPACE_REVIEW_MAX_DECISION_BYTES {
        return Err("native_workspace_review_decision_invalid".to_owned());
    }
    let value: Value = crate::strict_json_value(bytes)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    if canonical != bytes {
        return Err("native_workspace_review_decision_noncanonical".to_owned());
    }
    let envelope: WorkspaceReviewDecisionEnvelopeV1 = serde_json::from_value(value)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    Ok(envelope)
}
