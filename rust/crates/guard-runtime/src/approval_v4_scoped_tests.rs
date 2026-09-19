// Actual passkey lifecycle against authenticated scoped snapshot rows.
use super::*;
use guard_policy_snapshot::{
    config_digest, integrity_mac_v4, policy_digest_v4, PolicySnapshotV4,
    POLICY_SNAPSHOT_V4_PUSH_SCHEMA, POLICY_SNAPSHOT_V4_SCHEMA,
};
use serde_json::{json, Value};

const COMMAND: &str = "printf synthetic";
const CREDENTIAL: [u8; 32] = [31; 32];

fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[33; 32]).unwrap()
}

fn sign_snapshot(snapshot: &mut PolicySnapshotV4) {
    snapshot.config_digest = config_digest(&snapshot.effective_policy).unwrap();
    snapshot.policy_digest = policy_digest_v4(snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac_v4(snapshot, &[7; 32]).unwrap();
}

fn push_scoped(store: &crate::policy_store::PolicySnapshotStore, snapshot: &PolicySnapshotV4) {
    let ack: Value = serde_json::from_slice(
        &store
            .push(&json!({"schema":POLICY_SNAPSHOT_V4_PUSH_SCHEMA,"snapshot":snapshot}))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ack["status"], "accepted");
    assert_eq!(ack["source_input_digest"], snapshot.source_input_digest);
}

fn reference(snapshot: &PolicySnapshotV4) -> Value {
    json!({"generation":snapshot.generation,"policy_digest":snapshot.policy_digest,
        "runtime_identity":snapshot.runtime_identity,"source_input_digest":snapshot.source_input_digest})
}

fn setup(
    label: &str,
    action: &str,
) -> (
    std::path::PathBuf,
    crate::policy_store::PolicySnapshotStore,
    GuardHookEnvelopeV2,
    PolicySnapshotV4,
) {
    let signer = key();
    let (root, store, mut envelope) = store_and_envelope_v4(
        label,
        &cose_ed25519(signer.public_key().as_ref()),
        NATIVE_APPROVAL_V4_ALGORITHM_ED25519,
        &CREDENTIAL,
    );
    let mut value = serde_json::to_value(store.current_snapshot().unwrap()).unwrap();
    value["schema"] = POLICY_SNAPSHOT_V4_SCHEMA.into();
    value["version"] = 4.into();
    value["generation"] = 2.into();
    value["source_input_digest"] = "b".repeat(64).into();
    value["effective_policy"]["default_action"] = "allow".into();
    value["effective_policy"]["subprocess_action"] = "allow".into();
    value["effective_policy"]["unknown_publisher_action"] = "allow".into();
    value["scoped_authority"] = json!({
        "schema":"guard-native-policy-authority.v1","generic_precedence":"specificity-recency.v1",
        "rows":[{"decision_id":1,"harness":"claude-code","scope":"artifact","action":action,
            "source_kind":"signed-bundle","updated_at_us":1,"artifact_id":"claude-code:project:Bash",
            "artifact_hash":null,"workspace":null,"publisher":null,"expires_at_ms":null,
            "exact_command_sha256":guard_command::exact_command::exact_command_sha256(COMMAND),
            "requires_exact_context":false}],"managed":null
    });
    let mut snapshot: PolicySnapshotV4 = serde_json::from_value(value).unwrap();
    sign_snapshot(&mut snapshot);
    push_scoped(&store, &snapshot);
    envelope.policy_generation = snapshot.generation;
    envelope.policy_snapshot = reference(&snapshot);
    envelope.raw_payload = json!({"tool_name":"Bash","tool_input":{"command":COMMAND}});
    (root, store, envelope, snapshot)
}

fn signed_artifact(challenge: &ApprovalChallengeV4) -> ApprovalArtifactV4 {
    artifact_from_challenge(
        challenge,
        assertion(challenge, &CREDENTIAL, 0, |message| {
            key().sign(message).as_ref().to_vec()
        }),
    )
}

fn validate(
    store: &crate::policy_store::PolicySnapshotStore,
    envelope: &GuardHookEnvelopeV2,
    artifact: &ApprovalArtifactV4,
) -> Result<Vec<u8>, String> {
    validate_approval(
        ApprovalValidateRequestV4 {
            schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA.into(),
            version: 4,
            envelope: envelope.clone(),
            artifact: artifact.clone(),
        },
        store,
    )
}

fn consume(
    store: &crate::policy_store::PolicySnapshotStore,
    envelope: &GuardHookEnvelopeV2,
    artifact: &ApprovalArtifactV4,
) -> Result<Vec<u8>, String> {
    consume_approval(
        ApprovalConsumeRequestV4 {
            schema: NATIVE_APPROVAL_CONSUME_REQUEST_V4_SCHEMA.into(),
            version: 4,
            envelope: envelope.clone(),
            artifact: artifact.clone(),
        },
        store,
    )
}

#[test]
fn scoped_review_issues_real_challenge_and_consumes_signed_passkey_once() {
    let (root, store, envelope, snapshot) = setup("scoped-lifecycle", "review");
    let challenge = challenge_for(&store, &envelope, &CREDENTIAL);
    assert_eq!(challenge.minimum_action, "review");
    assert_eq!(challenge.policy_generation, snapshot.generation);
    assert_eq!(challenge.policy_digest, snapshot.policy_digest);
    let artifact = signed_artifact(&challenge);
    validate(&store, &envelope, &artifact).unwrap();
    let receipt: Value =
        serde_json::from_slice(&consume(&store, &envelope, &artifact).unwrap()).unwrap();
    assert_eq!(receipt["receipt"]["phase"], "consumed");
    assert_eq!(receipt["receipt"]["decision"], "allow");
    assert_eq!(receipt["receipt"]["policy_digest"], snapshot.policy_digest);
    assert!(consume(&store, &envelope, &artifact).is_err());
    assert!(
        store.current_snapshot().is_err(),
        "legacy accessor must still refuse V4"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scoped_reference_requires_source_and_current_generation_before_challenge() {
    let (root, store, envelope, _) = setup("scoped-reference", "review");
    let mut missing = envelope.clone();
    missing
        .policy_snapshot
        .as_object_mut()
        .unwrap()
        .remove("source_input_digest");
    let mut changed = envelope.clone();
    changed.policy_snapshot["source_input_digest"] = "c".repeat(64).into();
    let mut generation = envelope.clone();
    generation.policy_generation += 1;
    for request in [missing, changed, generation] {
        assert!(create_challenge(
            ApprovalChallengeRequestV4 {
                schema: NATIVE_APPROVAL_CHALLENGE_REQUEST_V4_SCHEMA.into(),
                version: 4,
                envelope: request,
            },
            &store
        )
        .is_err());
    }
    challenge_for(&store, &envelope, &CREDENTIAL);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scoped_terminal_rows_cannot_become_passkey_approvals() {
    for floor in ["sandbox-required", "block"] {
        let (root, store, envelope, _) = setup(&format!("scoped-floor-{floor}"), floor);
        assert_eq!(
            create_challenge(
                ApprovalChallengeRequestV4 {
                    schema: NATIVE_APPROVAL_CHALLENGE_REQUEST_V4_SCHEMA.into(),
                    version: 4,
                    envelope,
                },
                &store
            )
            .unwrap_err(),
            "native_approval_floor_not_overridable"
        );
        fs::remove_dir_all(root).unwrap();
    }
    let (root, store, envelope, _) = setup("scoped-reapproval", "require-reapproval");
    let challenge = challenge_for(&store, &envelope, &CREDENTIAL);
    assert_eq!(challenge.minimum_action, "require-reapproval");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scoped_source_replacement_after_validation_refuses_live_consumption() {
    let (root, store, envelope, mut snapshot) = setup("scoped-replacement", "review");
    let challenge = challenge_for(&store, &envelope, &CREDENTIAL);
    let artifact = signed_artifact(&challenge);
    validate(&store, &envelope, &artifact).unwrap();
    snapshot.source_input_digest = "c".repeat(64);
    sign_snapshot(&mut snapshot);
    assert!(store
        .push(&json!({"schema":POLICY_SNAPSHOT_V4_PUSH_SCHEMA,"snapshot":snapshot}))
        .is_err());
    snapshot.generation += 1;
    sign_snapshot(&mut snapshot);
    push_scoped(&store, &snapshot);
    assert!(consume(&store, &envelope, &artifact).is_err());
    let mut latest = envelope;
    latest.policy_generation = snapshot.generation;
    latest.policy_snapshot = reference(&snapshot);
    assert!(consume(&store, &latest, &artifact).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scoped_changed_request_refuses_before_claiming_original_proof() {
    let (root, store, envelope, _) = setup("scoped-request-change", "review");
    let challenge = challenge_for(&store, &envelope, &CREDENTIAL);
    let artifact = signed_artifact(&challenge);
    let mut command = envelope.clone();
    command.raw_payload["tool_input"]["command"] = "printf changed".into();
    let mut request_id = envelope.clone();
    request_id.request_id = Some("other-request".into());
    let mut workspace = envelope.clone();
    workspace.source.cwd = Some(std::env::temp_dir().to_string_lossy().into_owned());
    for changed in [command, request_id, workspace] {
        assert!(validate(&store, &changed, &artifact).is_err());
    }
    validate(&store, &envelope, &artifact).unwrap();
    consume(&store, &envelope, &artifact).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scoped_durable_authority_loss_refuses_a_validated_proof() {
    let (root, store, envelope, _) = setup("scoped-authority-loss", "review");
    let challenge = challenge_for(&store, &envelope, &CREDENTIAL);
    let artifact = signed_artifact(&challenge);
    validate(&store, &envelope, &artifact).unwrap();
    fs::remove_file(root.join("policy-snapshot-v3.json")).unwrap();
    assert!(consume(&store, &envelope, &artifact).is_err());
    fs::remove_dir_all(root).unwrap();
}
