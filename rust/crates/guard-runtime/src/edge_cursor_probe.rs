use super::{evaluate_validated_envelope, validate_envelope_shape};
use guard_contracts::GuardHookEnvelopeV2;
use serde_json::Value;

/// Review a Cursor routing probe on the same authenticated binding as the
/// edge. Watch gives a plain probe allow and leaves the next hook to review
/// the call that actually runs.
pub(crate) fn evaluate_cursor_probe(
    envelope: GuardHookEnvelopeV2,
    policy_store: &crate::policy_store::PolicySnapshotStore,
    harness_postures: Option<&Value>,
) -> Result<Option<Vec<u8>>, String> {
    validate_envelope_shape(&envelope)?;
    let admitted = policy_store.validate_request_snapshot(
        &envelope.policy_snapshot,
        &envelope.source.guard_home,
        envelope.policy_generation,
    )?;
    let snapshot = admitted.snapshot();
    let binding = serde_json::json!({"mode": snapshot.mode, "harness_postures": harness_postures});
    if crate::hook_render_posture::recording_only_for_binding(
        Some(&binding),
        &Value::from("cursor"),
    ) {
        return Ok(None);
    }
    let lease = policy_store.command_authority_lease(snapshot)?;
    evaluate_validated_envelope(envelope, Some(admitted.as_ref()), Some(policy_store), lease)
        .map(Some)
}
