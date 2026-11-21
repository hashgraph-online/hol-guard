//! The approval binding tuple: installation, session, event, action, policy
//! generation, request nonce and continuation. A signed approval for one
//! request must not authorize a request that differs in any tuple element,
//! and it must not authorize the same request twice.
//! `docs/guard/approval-binding-tuple.md` maps each element to its field.

use super::*;
use guard_contracts::{ApprovalConsumeRequestV3, ApprovalValidateRequestV3};

fn validate(
    store: &crate::policy_store::PolicySnapshotStore,
    envelope: &GuardHookEnvelopeV2,
    artifact: &ApprovalArtifactV3,
) -> Result<Vec<u8>, String> {
    validate_approval(
        ApprovalValidateRequestV3 {
            schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
            version: 3,
            envelope: envelope.clone(),
            artifact: artifact.clone(),
        },
        store,
    )
}

fn consume(
    store: &crate::policy_store::PolicySnapshotStore,
    envelope: &GuardHookEnvelopeV2,
    artifact: &ApprovalArtifactV3,
) -> Result<Vec<u8>, String> {
    consume_approval(
        ApprovalConsumeRequestV3 {
            schema: NATIVE_APPROVAL_CONSUME_REQUEST_V3_SCHEMA.into(),
            version: 3,
            envelope: envelope.clone(),
            artifact: artifact.clone(),
        },
        store,
    )
}

fn session_envelope(
    label: &str,
) -> (
    PathBuf,
    crate::policy_store::PolicySnapshotStore,
    GuardHookEnvelopeV2,
) {
    let (root, store, mut envelope) = store_and_envelope(label);
    envelope.raw_payload = serde_json::json!({
        "tool_name": "bash",
        "command": "git status",
        "session_id": "synthetic-session-a",
    });
    (root, store, envelope)
}

/// Each case changes exactly one tuple element of the presented request and
/// keeps the artifact signed for the original request.
#[test]
fn approval_for_one_tuple_never_authorizes_a_different_tuple() {
    let (_root, store, envelope) = session_envelope("tuple-elements");
    let challenge = challenge_for(&store, &envelope);
    let artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());

    let mut other_session = envelope.clone();
    other_session.raw_payload["session_id"] = "synthetic-session-b".into();
    let mut other_action = envelope.clone();
    other_action.raw_payload["command"] = "git push --force".into();
    let mut other_event = envelope.clone();
    other_event.event = "PostToolUse".into();
    let mut other_request = envelope.clone();
    other_request.request_id = Some("fedcba9876543210fedcba9876543210".into());

    for (element, presented) in [
        ("session", other_session),
        ("action", other_action),
        ("event", other_event),
        ("request", other_request),
    ] {
        let error = validate(&store, &presented, &artifact).unwrap_err();
        assert!(
            error.starts_with("native_approval_"),
            "{element}: unexpected error {error}"
        );
    }
    // The unchanged request still validates, so the refusals above come from
    // the changed element and not from a broken fixture.
    validate(&store, &envelope, &artifact).unwrap();
}

#[test]
fn a_changed_event_is_refused_as_not_approvable() {
    let (_root, store, envelope) = session_envelope("tuple-event");
    let challenge = challenge_for(&store, &envelope);
    let artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    let mut presented = envelope.clone();
    presented.event = "PostToolUse".into();
    assert_eq!(
        validate(&store, &presented, &artifact).unwrap_err(),
        "native_approval_event_not_approvable"
    );
}

#[test]
fn a_changed_session_or_action_is_a_binding_mismatch() {
    let (_root, store, envelope) = session_envelope("tuple-session");
    let challenge = challenge_for(&store, &envelope);
    let artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    let mut session = envelope.clone();
    session.raw_payload["session_id"] = "synthetic-session-b".into();
    assert_eq!(
        validate(&store, &session, &artifact).unwrap_err(),
        "native_approval_binding_mismatch"
    );
    let mut action = envelope.clone();
    action.raw_payload["command"] = "git push --force".into();
    assert_eq!(
        validate(&store, &action, &artifact).unwrap_err(),
        "native_approval_binding_mismatch"
    );
}

type Mutation = fn(&mut ApprovalArtifactV3);

/// Re-signing a tuple element with the real approval key still fails: the
/// element is compared with the resident's own derivation, not trusted from
/// the artifact.
#[test]
fn resigned_tuple_elements_are_compared_with_the_resident_derivation() {
    let (_root, store, envelope) = session_envelope("tuple-resigned");
    let challenge = challenge_for(&store, &envelope);
    let seed = store.test_approval_signing_seed();
    let base = artifact_from_challenge(&challenge, &seed);
    let mutations: [(&str, Mutation); 6] = [
        ("installation", |a| {
            a.installation_binding = Some("b".repeat(64))
        }),
        ("session", |a| a.request_digest = "b".repeat(64)),
        ("action", |a| a.action_digest = "b".repeat(64)),
        ("policy_generation", |a| a.policy_generation += 1),
        ("policy_digest", |a| a.policy_digest = "b".repeat(64)),
        ("continuation", |a| a.resident_epoch = "b".repeat(64)),
    ];
    for (element, mutate) in mutations {
        let mut artifact = base.clone();
        mutate(&mut artifact);
        resign(&mut artifact, &seed);
        assert_eq!(
            validate(&store, &envelope, &artifact).unwrap_err(),
            "native_approval_binding_mismatch",
            "{element}"
        );
    }
}

/// The nonce is signed: changing it without the key breaks the signature.
#[test]
fn an_unsigned_nonce_change_breaks_integrity() {
    let (_root, store, envelope) = session_envelope("tuple-nonce");
    let challenge = challenge_for(&store, &envelope);
    let mut artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    artifact.nonce = "b".repeat(artifact.nonce.len());
    assert_eq!(
        validate(&store, &envelope, &artifact).unwrap_err(),
        "native_approval_integrity_mismatch"
    );
}

/// Continuation: one approval authorizes one execution. After it is claimed
/// and consumed it cannot be claimed or consumed again.
#[test]
fn a_consumed_approval_cannot_continue_a_second_execution() {
    let (_root, store, envelope) = session_envelope("tuple-continuation");
    let challenge = challenge_for(&store, &envelope);
    let artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    validate(&store, &envelope, &artifact).unwrap();
    consume(&store, &envelope, &artifact).unwrap();
    assert_eq!(
        consume(&store, &envelope, &artifact).unwrap_err(),
        "native_approval_receipt_consumed"
    );
    let error = validate(&store, &envelope, &artifact).unwrap_err();
    assert!(error.starts_with("native_approval_"), "{error}");
}
