//! Compose one authenticated generic winner with current non-overridable floors.
//!
//! Specificity and recency choose the generic row before composition. Its
//! source kind cannot give it priority over another row. Signed exact-command
//! allows may satisfy ordinary review; they do not become one-shot approvals.

use crate::policy_enforcement::{
    configured_pre_tool_policy_action, generic_command_configuration,
    sensitive_read_configuration_with_origin, validate_pre_tool_result_matrix,
};
use crate::policy_scoped_request::derive_scoped_policy_request;
use guard_command::exact_command::exact_shell_command_from_hook;
use guard_contracts::{GuardHookEnvelopeV2, PreToolResultV1};
use guard_policy_snapshot::command_expression::NormalizedCommand;
use guard_policy_snapshot::scoped_authority::{
    PolicyAction, PolicyScope, PolicySourceKind, ScopedPolicyRow,
};
use guard_policy_snapshot::PolicySnapshotV4;
use serde_json::Value;

#[cfg(test)]
#[path = "policy_scoped_enforcement_tests.rs"]
mod tests;

pub(crate) struct ScopedPolicyEvaluation {
    pub(crate) result: PreToolResultV1,
    /// The fully composed action before Watch projects policy-only restrictions.
    pub(crate) observed_policy_action: Option<&'static str>,
    /// Provenance only: the caller binds this ID to this exact admitted snapshot.
    pub(crate) selected_decision_id: Option<u64>,
}

fn action(value: &str) -> Result<PolicyAction, String> {
    match value {
        "allow" => Ok(PolicyAction::Allow),
        "warn" => Ok(PolicyAction::Warn),
        "review" => Ok(PolicyAction::Review),
        "require-reapproval" => Ok(PolicyAction::RequireReapproval),
        "sandbox-required" => Ok(PolicyAction::SandboxRequired),
        "block" => Ok(PolicyAction::Block),
        _ => Err("native_scoped_policy_action_invalid".to_owned()),
    }
}

fn name(value: PolicyAction) -> &'static str {
    match value {
        PolicyAction::Allow => "allow",
        PolicyAction::Warn => "warn",
        PolicyAction::Review => "review",
        PolicyAction::RequireReapproval => "require-reapproval",
        PolicyAction::SandboxRequired => "sandbox-required",
        PolicyAction::Block => "block",
    }
}

fn rank(value: PolicyAction) -> u8 {
    match value {
        PolicyAction::Allow => 0,
        PolicyAction::Warn => 1,
        PolicyAction::Review => 2,
        PolicyAction::RequireReapproval => 3,
        PolicyAction::SandboxRequired => 4,
        PolicyAction::Block => 5,
    }
}

fn join(left: PolicyAction, right: PolicyAction) -> PolicyAction {
    if rank(left) >= rank(right) {
        left
    } else {
        right
    }
}

fn signed_exact_allow(row: &ScopedPolicyRow) -> bool {
    row.action() == PolicyAction::Allow
        && matches!(
            row.source_kind(),
            PolicySourceKind::SignedBundle | PolicySourceKind::SignedMemory
        )
        && matches!(row.scope(), PolicyScope::Artifact | PolicyScope::Workspace)
        && row.exact_command_sha256().is_some()
        && row.artifact_hash().is_none()
}

/// Equivalent to the current Python saved-decision composition after authority validation.
fn compose(current: PolicyAction, selected: &ScopedPolicyRow) -> PolicyAction {
    let saved = selected.action();
    if saved == PolicyAction::Block {
        return saved;
    }
    if matches!(
        current,
        PolicyAction::Block | PolicyAction::SandboxRequired | PolicyAction::RequireReapproval
    ) {
        return join(current, saved);
    }
    if saved == PolicyAction::Allow {
        return if current == PolicyAction::Review && signed_exact_allow(selected) {
            saved
        } else {
            current
        };
    }
    join(current, saved)
}

/// The snapshot must have passed resident authentication and request fencing.
/// Unsupported semantics are errors, never a partial successful application.
pub(crate) fn apply_scoped_pre_tool_policy_compiled(
    snapshot: &PolicySnapshotV4,
    compiled: &crate::policy_enforcement::CompiledEffectivePolicy,
    envelope: &GuardHookEnvelopeV2,
    canonical_harness: &str,
    intrinsic: PreToolResultV1,
    now_ms: u64,
) -> Result<ScopedPolicyEvaluation, String> {
    validate_pre_tool_result_matrix(&intrinsic)?;
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err("native_policy_mode_invalid".to_owned());
    }
    if snapshot
        .scoped_authority
        .rows()
        .iter()
        .any(|row| row.artifact_hash().is_some())
    {
        return Err("native_scoped_content_context_unsupported".to_owned());
    }
    if [
        "policy_action",
        "daemon_status",
        "fail_mode",
        "permission_mode",
        "permissionMode",
    ]
    .iter()
    .any(|key| envelope.raw_payload.get(*key).is_some())
    {
        return Err("native_scoped_request_posture_unsupported".to_owned());
    }
    let request = derive_scoped_policy_request(envelope, canonical_harness)?;
    let sensitive = crate::policy_scoped_sensitive_read::derive_sensitive_read_artifact(
        envelope,
        canonical_harness,
    )
    .ok();
    let generic_configuration =
        if sensitive.is_none() && snapshot.scoped_authority.command_expressions().is_empty() {
            generic_command_configuration(
                &snapshot.effective_policy,
                snapshot.scoped_authority.managed_config(),
                envelope,
                canonical_harness,
                request
                    .artifact_id()
                    .ok_or("native_scoped_request_identity_unsupported")?,
            )?
        } else {
            None
        };
    // Retain explicit refusal for managed origins on every unproved producer.
    if sensitive.is_none()
        && generic_configuration.is_none()
        && snapshot.scoped_authority.managed_config().is_some()
    {
        return Err("native_managed_configuration_request_unsupported".to_owned());
    }
    let sensitive_configuration = sensitive
        .as_ref()
        .map(|artifact| {
            sensitive_read_configuration_with_origin(
                &snapshot.effective_policy,
                snapshot.scoped_authority.managed_config(),
                canonical_harness,
                &artifact.artifact_id,
            )
        })
        .transpose()?;
    let managed_block = crate::policy_scoped_managed::request_is_blocked(
        snapshot.scoped_authority.managed(),
        envelope,
        canonical_harness,
    )?;
    let selected = snapshot
        .scoped_authority
        .select_generic(&request, now_ms)
        .map_err(|_| "native_scoped_policy_match_invalid".to_owned())?;
    // Existing configured artifact overrides use the same actual identity as
    // the scoped lookup, not a separately discovered display label.
    let mut configured_payload = envelope.raw_payload.clone();
    configured_payload["artifact_id"] = request
        .artifact_id()
        .map_or(Value::Null, |value| value.into());
    let configured = if let Some(policy) = &sensitive_configuration {
        action(&policy.evaluated_action)?
    } else if let Some(policy) = &generic_configuration {
        action(policy.evaluated_action())?
    } else {
        action(&configured_pre_tool_policy_action(
            &snapshot.effective_policy,
            compiled,
            &configured_payload,
            &intrinsic,
        )?)?
    };
    let intrinsic_action = action(&intrinsic.minimum_action)?;
    // Proven source producers replace only their specific fallback reviews.
    // Independent scanner/native restrictions retain their original floors.
    let intrinsic_floor = if intrinsic_action == PolicyAction::Review
        && ((sensitive.is_some()
            && intrinsic.reason_code == "native_file_read_review"
            && intrinsic.action.action_type == guard_contracts::PreToolActionTypeV1::FileRead)
            || generic_configuration
                .as_ref()
                .is_some_and(|policy| policy.replaces_fallback_review(&intrinsic)))
    {
        PolicyAction::Allow
    } else {
        intrinsic_action
    };
    // Managed controls are authority floors. Neither a generic allow nor Watch
    // can release lockdown. Current supported shell facts have no extension
    // observations; unsupported control/request semantics refuse above.
    let authority_floor = if managed_block {
        PolicyAction::Block
    } else {
        intrinsic_floor
    };
    let current = join(configured, authority_floor);
    let composed = selected.map_or(current, |row| compose(current, row));
    // The classifier admitted only an explicitly modeled generic producer.
    // Its ordinary command review can be satisfied by a matched signed exact
    // allow. Other intrinsic reasons and every stronger action remain floors.
    let mut effective = if intrinsic_action == PolicyAction::Review
        && intrinsic.reason_code == "native_command_review_required"
    {
        composed
    } else {
        join(composed, authority_floor)
    };
    let generic_effective = effective;
    let expression_winner = if snapshot.scoped_authority.command_expressions().is_empty() {
        None
    } else if let Some(command) = exact_shell_command_from_hook(&envelope.raw_payload) {
        let normalized = NormalizedCommand::new(command)
            .map_err(|_| "native_scoped_request_identity_unsupported".to_owned())?;
        snapshot
            .scoped_authority
            .matching_command_rows(&request, &normalized, now_ms)
            .map_err(|_| "native_scoped_policy_match_invalid".to_owned())?
            .into_iter()
            .max_by_key(|row| (rank(row.action()), u64::MAX - row.decision_id()))
    } else {
        None
    };
    if let Some(row) = expression_winner {
        effective = join(effective, row.action());
    }
    let expression_decision_id = expression_winner
        .filter(|row| rank(effective) > rank(generic_effective) && effective == row.action())
        .map(ScopedPolicyRow::decision_id);
    let selected_decision_id = expression_decision_id.or_else(|| {
        selected
            .filter(|row| effective != current && effective == row.action())
            .map(ScopedPolicyRow::decision_id)
    });
    let observed_policy_action = if generic_configuration.is_some() {
        if snapshot.mode == "observe" && rank(effective) > 1 && rank(authority_floor) <= 1 {
            let observed = Some(name(effective));
            effective = authority_floor;
            observed
        } else {
            None
        }
    } else {
        (snapshot.mode == "observe").then(|| name(effective))
    };
    if generic_configuration.is_none()
        && snapshot.mode == "observe"
        && rank(effective) > rank(authority_floor)
        && rank(authority_floor) <= 1
        && (sensitive_configuration.is_none() || rank(effective) > 1)
    {
        effective = if let Some(policy) = &sensitive_configuration {
            join(action(&policy.observe_action)?, authority_floor)
        } else {
            PolicyAction::Warn
        };
    }
    let mut result = intrinsic;
    if effective != intrinsic_action {
        result.reason_code = "native_scoped_policy_composed".to_owned();
        result.reason = "HOL Guard applied the current policy to this action.".to_owned();
    }
    result.minimum_action = name(effective).to_owned();
    result.policy_action = name(effective).to_owned();
    result.decision = if rank(effective) <= 1 {
        "allow"
    } else {
        "deny"
    }
    .to_owned();
    result.explicitly_benign = effective == PolicyAction::Allow;
    validate_pre_tool_result_matrix(&result)?;
    Ok(ScopedPolicyEvaluation {
        result,
        observed_policy_action,
        selected_decision_id,
    })
}

#[cfg(test)]
fn apply_scoped_pre_tool_policy(
    snapshot: &PolicySnapshotV4,
    envelope: &GuardHookEnvelopeV2,
    canonical_harness: &str,
    intrinsic: PreToolResultV1,
    now_ms: u64,
) -> Result<ScopedPolicyEvaluation, String> {
    let compiled =
        crate::policy_enforcement::CompiledEffectivePolicy::new(&snapshot.effective_policy)?;
    apply_scoped_pre_tool_policy_compiled(
        snapshot,
        &compiled,
        envelope,
        canonical_harness,
        intrinsic,
        now_ms,
    )
}

#[cfg(test)]
#[path = "policy_vector_fixtures.rs"]
mod policy_vector_fixtures;

#[cfg(test)]
#[path = "policy_vector_ordinary.rs"]
pub(crate) mod policy_vector_ordinary;

#[cfg(test)]
#[path = "policy_vector_mixed.rs"]
mod policy_vector_mixed;

#[cfg(test)]
#[path = "policy_vector_generic.rs"]
mod policy_vector_generic;

#[cfg(test)]
#[path = "policy_vector_commitment_tests.rs"]
mod policy_vector_commitment_tests;

#[cfg(test)]
#[path = "policy_scoped_sensitive_tests.rs"]
mod sensitive_tests;

#[cfg(test)]
#[path = "policy_scoped_generic_tests.rs"]
mod generic_tests;
