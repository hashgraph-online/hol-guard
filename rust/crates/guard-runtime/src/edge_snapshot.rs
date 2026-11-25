use guard_contracts::GuardHookEnvelopeV2;

use crate::policy_enforcement::AdmittedPolicySnapshot;

use super::{evaluate_validated_envelope, validate_envelope_shape};

/// Evaluate against a snapshot while the policy store's request fence is
/// held. Approval challenge creation uses this entry point so the action,
/// snapshot, and derived bindings describe one coherent state.
pub(crate) fn evaluate_envelope_with_snapshot(
    envelope: GuardHookEnvelopeV2,
    snapshot: &AdmittedPolicySnapshot,
) -> Result<Vec<u8>, String> {
    validate_envelope_shape(&envelope)?;
    evaluate_validated_envelope(envelope, Some(snapshot), None, ())
}
