use super::*;
use guard_contracts::{
    ApprovalChallengeRequestV3, ApprovalChallengeV3, ApprovalValidateRequestV3,
    GuardHookEnvelopeV2, GuardHookSourceMetadataV2, NativeApprovalIntegrityV3, PreToolActionTypeV1,
    PreToolOperationV1, GUARD_HOOK_ENVELOPE_V2_SCHEMA, NATIVE_APPROVAL_CHALLENGE_V3_SCHEMA,
};
use guard_policy_snapshot::{
    config_digest, digest_bytes, integrity_mac, policy_digest, verifier_key_id,
    EffectiveNativePolicyV3, PolicySnapshotV3, ScopeContractV3, SnapshotIntegrityV3,
    POLICY_SNAPSHOT_INTEGRITY_ALGORITHM, POLICY_SNAPSHOT_PUSH_SCHEMA, POLICY_SNAPSHOT_SCHEMA,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn policy() -> EffectiveNativePolicyV3 {
    EffectiveNativePolicyV3 {
        protection_posture: "protected".into(),
        security_level: "balanced".into(),
        default_action: "review".into(),
        unknown_publisher_action: "review".into(),
        changed_hash_action: "require-reapproval".into(),
        new_network_domain_action: "review".into(),
        subprocess_action: "review".into(),
        risk_actions: BTreeMap::new(),
        harness_risk_actions: BTreeMap::new(),
        harness_actions: BTreeMap::new(),
        publisher_actions: BTreeMap::new(),
        artifact_actions: BTreeMap::new(),
        sandbox_analysis: "off".into(),
        receipt_redaction_level: "full".into(),
    }
}

fn scope_digest(root: &Path) -> String {
    digest_bytes(root.to_string_lossy().as_bytes())
}

pub(super) fn root(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "hol-guard-approval-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

fn snapshot(root: &Path, key: &[u8; 32]) -> PolicySnapshotV3 {
    let effective_policy = policy();
    let mut snapshot = PolicySnapshotV3 {
        schema: POLICY_SNAPSHOT_SCHEMA.into(),
        version: 3,
        generation: 1,
        policy_digest: String::new(),
        config_digest: config_digest(&effective_policy).unwrap(),
        rule_digest: guard_rule_contract::rule_digest(),
        runtime_identity: "a".repeat(64),
        protocol_version: 1,
        mode: "enforce".into(),
        scope_contract: ScopeContractV3 {
            schema: APPROVAL_SCOPE_SCHEMA.into(),
            kind: "guard-home".into(),
            scope_digest: scope_digest(root),
            workspace_binding: "request-source".into(),
        },
        effective_policy,
        issued_at_ms: now_ms().unwrap().saturating_sub(1),
        expires_at_ms: now_ms().unwrap() + 60_000,
        integrity: SnapshotIntegrityV3 {
            algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
            key_id: verifier_key_id(key),
            mac: String::new(),
        },
    };
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, key).unwrap();
    snapshot
}

pub(super) fn store_and_envelope(
    label: &str,
) -> (
    PathBuf,
    crate::policy_store::PolicySnapshotStore,
    GuardHookEnvelopeV2,
) {
    let runtime_identity = "a".repeat(64);
    store_and_envelope_with_runtime(label, &runtime_identity)
}

fn snapshot_for_runtime(root: &Path, key: &[u8; 32], runtime_identity: &str) -> PolicySnapshotV3 {
    let mut signed = snapshot(root, key);
    signed.runtime_identity = runtime_identity.to_owned();
    signed.policy_digest = policy_digest(&signed).unwrap();
    signed.integrity.mac = integrity_mac(&signed, key).unwrap();
    signed
}

fn store_and_envelope_with_runtime(
    label: &str,
    runtime_identity: &str,
) -> (
    PathBuf,
    crate::policy_store::PolicySnapshotStore,
    GuardHookEnvelopeV2,
) {
    let root = root(label);
    let key = [7u8; 32];
    fs::write(root.join("policy-verifier.key"), key).unwrap();
    let approval_seed = [17u8; 32];
    let approval_key = approval_public_key_for_tests(&approval_seed);
    crate::policy_store::approval_authority::write_test_record(&root, &approval_key, 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            root.join("policy-verifier.key"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let store = crate::policy_store::PolicySnapshotStore::new(&root, runtime_identity).unwrap();
    let signed = snapshot_for_runtime(&root, &key, runtime_identity);
    store
        .push(
            &serde_json::to_value(guard_policy_snapshot::PolicySnapshotPushV1 {
                schema: POLICY_SNAPSHOT_PUSH_SCHEMA.into(),
                snapshot: signed.clone(),
            })
            .unwrap(),
        )
        .unwrap();
    assert!(store.test_authorities_unchanged());
    let envelope = GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.into(),
        request_id: Some("0123456789abcdef0123456789abcdef".into()),
        harness: "claude-code".into(),
        event: "PreToolUse".into(),
        raw_payload: serde_json::json!({"tool_name":"bash", "command":"git status"}),
        deadline_budget_ms: Some(500),
        policy_generation: 1,
        policy_snapshot: serde_json::to_value(signed).unwrap(),
        source: GuardHookSourceMetadataV2 {
            cwd: Some(root.to_string_lossy().into_owned()),
            home_dir: root.to_string_lossy().into_owned(),
            guard_home: root.to_string_lossy().into_owned(),
            source_ref_external_allowed: false,
        },
    };
    (root, store, envelope)
}

fn artifact_from_challenge(challenge: &ApprovalChallengeV3, key: &[u8; 32]) -> ApprovalArtifactV3 {
    let mut artifact = ApprovalArtifactV3 {
        schema: NATIVE_APPROVAL_ARTIFACT_V3_SCHEMA.into(),
        version: 3,
        request_id: challenge.request_id.clone(),
        request_digest: challenge.request_digest.clone(),
        action_digest: challenge.action_digest.clone(),
        action_type: challenge.action_type,
        operation: challenge.operation,
        intrinsic_action: challenge.intrinsic_action.clone(),
        minimum_action: challenge.minimum_action.clone(),
        floor_class: challenge.floor_class,
        approval_eligible: challenge.approval_eligible,
        policy_generation: challenge.policy_generation,
        policy_digest: challenge.policy_digest.clone(),
        rule_digest: challenge.rule_digest.clone(),
        runtime_identity: challenge.runtime_identity.clone(),
        runtime_protocol_version: challenge.runtime_protocol_version,
        runtime_package: challenge.runtime_package.clone(),
        runtime_version: challenge.runtime_version.clone(),
        runtime_binary_identity: challenge.runtime_binary_identity.clone(),
        harness: challenge.harness.clone(),
        workspace_binding: challenge.workspace_binding.clone(),
        device_binding: challenge.device_binding.clone(),
        installation_binding: challenge.installation_binding.clone(),
        publisher_binding: challenge.publisher_binding.clone(),
        artifact_binding: challenge.artifact_binding.clone(),
        scope_contract_version: challenge.scope_contract_version.clone(),
        scope_contract_digest: challenge.scope_contract_digest.clone(),
        scope_binding: challenge.scope_binding.clone(),
        resident_epoch: challenge.resident_epoch.clone(),
        nonce: challenge.nonce.clone(),
        issued_at_ms: challenge.issued_at_ms,
        expires_at_ms: challenge.expires_at_ms,
        requested_action: challenge.requested_action.clone(),
        approved_action: "allow".into(),
        integrity: NativeApprovalIntegrityV3 {
            algorithm: NATIVE_APPROVAL_INTEGRITY_ALGORITHM.into(),
            key_id: verifier_key_id(&approval_public_key_for_tests(key)),
            signature: String::new(),
        },
    };
    artifact.integrity.signature = approval_signature_for_tests(&artifact, key).unwrap();
    artifact
}

fn challenge_for(
    store: &crate::policy_store::PolicySnapshotStore,
    envelope: &GuardHookEnvelopeV2,
) -> ApprovalChallengeV3 {
    let request = ApprovalChallengeRequestV3 {
        schema: NATIVE_APPROVAL_CHALLENGE_REQUEST_V3_SCHEMA.into(),
        version: 3,
        envelope: envelope.clone(),
    };
    let bytes = create_challenge(request, store).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn validate_artifact_error(
    store: &crate::policy_store::PolicySnapshotStore,
    envelope: &GuardHookEnvelopeV2,
    artifact: ApprovalArtifactV3,
) -> String {
    validate_approval(
        ApprovalValidateRequestV3 {
            schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
            version: 3,
            envelope: envelope.clone(),
            artifact,
        },
        store,
    )
    .unwrap_err()
}

fn resign(artifact: &mut ApprovalArtifactV3, key: &[u8; 32]) {
    artifact.integrity.signature = approval_signature_for_tests(artifact, key).unwrap();
}

#[test]
fn valid_artifact_allows_exact_review_and_returns_private_receipt() {
    let (root, store, envelope) = store_and_envelope("valid");
    let challenge = challenge_for(&store, &envelope);
    assert_eq!(challenge.schema, NATIVE_APPROVAL_CHALLENGE_V3_SCHEMA);
    assert!(!challenge.request_id.is_empty());
    assert!(challenge.workspace_binding.is_some());
    assert!(challenge.device_binding.is_some());
    assert!(challenge.installation_binding.is_some());
    assert_ne!(
        challenge.device_binding, challenge.installation_binding,
        "device and installation must use distinct purpose domains"
    );
    let artifact = artifact_from_challenge(&challenge, &store.test_approval_signing_seed());
    let response = validate_approval(
        ApprovalValidateRequestV3 {
            schema: NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA.into(),
            version: 3,
            envelope,
            artifact,
        },
        &store,
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(value["receipt"]["decision"], "allow");
    assert_eq!(value["receipt"]["phase"], "validated");
    for field in [
        "request_id",
        "request_digest",
        "action_digest",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "runtime_protocol_version",
        "runtime_package",
        "runtime_version",
        "runtime_binary_identity",
        "harness",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_contract_version",
        "scope_contract_digest",
        "scope_binding",
        "resident_epoch",
        "nonce",
        "issued_at_ms",
        "expires_at_ms",
        "requested_action",
    ] {
        assert_eq!(
            value["receipt"][field],
            serde_json::to_value(&challenge).unwrap()[field]
        );
    }
    assert_eq!(value["receipt"]["nonce_digest"].as_str().unwrap().len(), 64);
    assert_eq!(value["receipt"]["replay_claimed"], true);
    assert!(value.get("command").is_none());
    assert!(value.get("path").is_none());
    assert!(value.get("url").is_none());
    let encoded = String::from_utf8(response).unwrap();
    assert!(!encoded.contains(root.to_string_lossy().as_ref()));
    assert!(!encoded.contains("git status"));
}

#[test]
fn request_identity_is_opaque_and_rust_derived_when_missing() {
    let (root, _store, mut envelope) = store_and_envelope("request-identity");
    envelope.request_id = None;
    let (request_id, request_digest) = crate::edge::request_identity(&envelope).unwrap();
    assert_eq!(request_id, format!("sha256:{request_digest}"));
    assert_eq!(request_digest.len(), 64);
    assert!(!request_id.contains(root.to_string_lossy().as_ref()));

    envelope.request_id = Some("/tmp/private-command-id".into());
    assert_eq!(
        crate::edge::request_identity(&envelope).unwrap_err(),
        "native_hook_request_id_invalid"
    );
    envelope.request_id = Some("0123456789ABCDEF0123456789ABCDEF".into());
    assert_eq!(
        crate::edge::request_identity(&envelope).unwrap_err(),
        "native_hook_request_id_invalid"
    );
}

#[test]
fn binding_mutations_are_rejected_even_when_resigned() {
    let (_root, store, envelope) = store_and_envelope("binding-mutations");
    let challenge = challenge_for(&store, &envelope);
    let key = store.test_approval_signing_seed();
    let base = artifact_from_challenge(&challenge, &key);

    macro_rules! assert_rejected {
        ($mutation:expr) => {{
            let mut artifact = base.clone();
            let mutation: fn(&mut ApprovalArtifactV3) = $mutation;
            mutation(&mut artifact);
            resign(&mut artifact, &key);
            let error = validate_artifact_error(&store, &envelope, artifact);
            assert_ne!(error, "native_approval_replay");
        }};
    }

    assert_rejected!(|artifact| artifact.request_id = "fedcba9876543210fedcba9876543210".into());
    assert_rejected!(|artifact| artifact.request_digest = "b".repeat(64));
    assert_rejected!(|artifact| artifact.action_digest = "b".repeat(64));
    assert_rejected!(|artifact| artifact.action_type = PreToolActionTypeV1::FileRead);
    assert_rejected!(|artifact| artifact.operation = PreToolOperationV1::Read);
    assert_rejected!(|artifact| artifact.intrinsic_action = "require-reapproval".into());
    assert_rejected!(|artifact| artifact.minimum_action = "require-reapproval".into());
    assert_rejected!(|artifact| artifact.policy_generation = 2);
    assert_rejected!(|artifact| artifact.policy_digest = "b".repeat(64));
    assert_rejected!(|artifact| artifact.rule_digest = "b".repeat(64));
    assert_rejected!(|artifact| artifact.runtime_identity = "b".repeat(64));
    assert_rejected!(|artifact| artifact.runtime_protocol_version = 2);
    assert_rejected!(|artifact| artifact.runtime_package = "different-runtime".into());
    assert_rejected!(|artifact| artifact.runtime_version = "9.9.9".into());
    assert_rejected!(|artifact| artifact.runtime_binary_identity = "b".repeat(64));
    assert_rejected!(|artifact| artifact.harness = "cursor".into());
    assert_rejected!(|artifact| artifact.workspace_binding = Some("b".repeat(64)));
    assert_rejected!(|artifact| artifact.device_binding = Some("b".repeat(64)));
    assert_rejected!(|artifact| artifact.installation_binding = Some("b".repeat(64)));
    assert_rejected!(|artifact| artifact.publisher_binding = Some("b".repeat(64)));
    assert_rejected!(|artifact| artifact.artifact_binding = Some("b".repeat(64)));
    assert_rejected!(|artifact| artifact.scope_contract_version = "scope-v2".into());
    assert_rejected!(|artifact| artifact.scope_contract_digest = "b".repeat(64));
    assert_rejected!(|artifact| artifact.scope_binding = Some("b".repeat(64)));
    assert_rejected!(|artifact| artifact.resident_epoch = "b".repeat(64));
    assert_rejected!(|artifact| artifact.requested_action = "require-reapproval".into());
    assert_rejected!(|artifact| artifact.approved_action = "block".into());
}

#[path = "approval_v3_lifecycle_tests.rs"]
mod lifecycle_tests;
