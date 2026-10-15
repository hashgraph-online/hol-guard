//! Stable replay identity; deriving a digest never creates a claim or grant.

use super::*;

pub(crate) fn semantic_decision_digest(
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
) -> Result<String, String> {
    let context = WorkspaceReviewDecisionContext {
        workspace_binding: &envelope.workspace_binding,
        device_binding: &envelope.device_binding,
        installation_binding: &envelope.installation_binding,
        scope_binding: &envelope.scope_binding,
        request_binding: &envelope.request_binding,
        action_binding: &envelope.action_binding,
        intent_binding: &envelope.intent_binding,
        revision_binding: &envelope.revision_binding,
        policy_binding: &envelope.policy_binding,
        retry_scope_binding: &envelope.retry_scope_binding,
    };
    digest_context(
        &envelope.schema,
        envelope.version,
        &envelope.purpose,
        &context,
        &envelope.delivery_mode,
        &envelope.decision,
    )
}

/// Read-only lookup key for a previously consumed owned business approval.
/// Bindings come from the authenticated private request and platform-secure
/// state, never a browser-supplied decision. No envelope/signature is invented.
pub(crate) fn owned_request_digest(
    request: &super::super::workspace_review_request::TrustedWorkspaceReviewRequest,
    state: &super::super::workspace_review_secure_state::WorkspaceReviewSecureStateV1,
) -> Result<String, String> {
    let context = WorkspaceReviewDecisionContext {
        workspace_binding: &state.workspace_binding,
        device_binding: &state.device_binding,
        installation_binding: &state.installation_binding,
        scope_binding: &state.scope_binding,
        request_binding: &request.request_binding,
        action_binding: &request.action_binding,
        intent_binding: &request.intent_binding,
        revision_binding: &request.revision_binding,
        policy_binding: &request.policy_binding,
        retry_scope_binding: &request.retry_scope_binding,
    };
    digest_context(
        NATIVE_WORKSPACE_REVIEW_DECISION_V1_SCHEMA,
        NATIVE_WORKSPACE_REVIEW_DECISION_V1_VERSION,
        NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE,
        &context,
        NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH,
        "allow",
    )
}

fn digest_context(
    schema: &str,
    version: u16,
    purpose: &str,
    context: &WorkspaceReviewDecisionContext<'_>,
    delivery_mode: &str,
    decision: &str,
) -> Result<String, String> {
    let value = serde_json::json!({
        "schema": schema, "version": version, "purpose": purpose,
        "workspace_binding": context.workspace_binding,
        "device_binding": context.device_binding,
        "installation_binding": context.installation_binding,
        "scope_binding": context.scope_binding,
        "request_binding": context.request_binding,
        "action_binding": context.action_binding,
        "intent_binding": context.intent_binding,
        "revision_binding": context.revision_binding,
        "policy_binding": context.policy_binding,
        "retry_scope_binding": context.retry_scope_binding,
        "delivery_mode": delivery_mode, "decision": decision,
    });
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    let mut preimage = Vec::with_capacity(
        NATIVE_WORKSPACE_REVIEW_SEMANTIC_DECISION_DOMAIN.len() + canonical.len(),
    );
    preimage.extend_from_slice(NATIVE_WORKSPACE_REVIEW_SEMANTIC_DECISION_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(digest_bytes(&preimage))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_replay_keys_remain_byte_compatible() {
        let values: Vec<String> = "123456789a"
            .chars()
            .map(|c| c.to_string().repeat(64))
            .collect();
        let context = WorkspaceReviewDecisionContext {
            workspace_binding: &values[0],
            device_binding: &values[1],
            installation_binding: &values[2],
            scope_binding: &values[3],
            request_binding: &values[4],
            action_binding: &values[5],
            intent_binding: &values[6],
            revision_binding: &values[7],
            policy_binding: &values[8],
            retry_scope_binding: &values[9],
        };
        // Frozen pre-extraction v1 digests: existing durable tombstones must
        // still be found, independent of signer, transport timestamp or OS.
        for (mode, expected) in [
            (
                NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH,
                "bc4e0135ed4e6aae3a69ed1e828f4b97be0ff9eeff2d9bd7199485f048cdf70b",
            ),
            (
                NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY,
                "173e15e6ba146729594c23a286baa06ac9725df386fd1c395e80b310f1fe9e1d",
            ),
        ] {
            assert_eq!(
                digest_context(
                    NATIVE_WORKSPACE_REVIEW_DECISION_V1_SCHEMA,
                    NATIVE_WORKSPACE_REVIEW_DECISION_V1_VERSION,
                    NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE,
                    &context,
                    mode,
                    "allow"
                )
                .unwrap(),
                expected
            );
        }
    }
}
