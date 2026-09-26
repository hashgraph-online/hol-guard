use super::{
    retry_scope_binding, signing_bytes, verify_and_claim_at, verify_envelope,
    WorkspaceReviewDecisionContext,
};
use guard_contracts::{
    WorkspaceReviewAuthorityV1, WorkspaceReviewDecisionEnvelopeV1,
    NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE, NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_SCHEMA,
    NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_VERSION,
    NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY, NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    NATIVE_WORKSPACE_REVIEW_DECISION_V1_SCHEMA, NATIVE_WORKSPACE_REVIEW_DECISION_V1_VERSION,
    NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN, NATIVE_WORKSPACE_REVIEW_KEY_ALGORITHM_ED25519,
    NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES, NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "workspace_review_decision_clock_tests.rs"]
mod clock_tests;

const NOW_MS: u64 = 2_000;
const ROOT_SEED: [u8; 32] = [42u8; 32];
const REVIEW_SEED: [u8; 32] = [9u8; 32];
static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn test_root() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "hol-guard-workspace-review-decision-{}-{suffix}-{}",
        std::process::id(),
        NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    #[cfg(windows)]
    let path = crate::resident_state::ensure_private_directory(&path, true).unwrap();
    #[cfg(not(windows))]
    fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

fn authority_record() -> WorkspaceReviewAuthorityV1 {
    let public_key = Ed25519KeyPair::from_seed_unchecked(&REVIEW_SEED)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let mut record = WorkspaceReviewAuthorityV1 {
        schema: NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_SCHEMA.to_owned(),
        version: NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_VERSION,
        purpose: NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE.to_owned(),
        key_algorithm: NATIVE_WORKSPACE_REVIEW_KEY_ALGORITHM_ED25519.to_owned(),
        key_id: digest_bytes(&public_key),
        public_key: hex::encode(public_key),
        workspace_binding: "1".repeat(64),
        device_binding: "2".repeat(64),
        installation_binding: "3".repeat(64),
        enrollment_generation: 1,
        previous_key_id: None,
        scope_contract_version: NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1.to_owned(),
        scope_binding: "4".repeat(64),
        issued_at_ms: 1_000,
        expires_at_ms: 61_000,
        status: "active".to_owned(),
        enrollment_signature: String::new(),
    };
    let signing = super::super::workspace_review_authority::signing_bytes(&record).unwrap();
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&ROOT_SEED).unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN);
    message.extend_from_slice(&signing);
    record.enrollment_signature = hex::encode(key_pair.sign(&message).as_ref());
    record
}

fn write_authority_candidate(root: &Path, record: &WorkspaceReviewAuthorityV1) -> PathBuf {
    let path = root.join("authority-candidate.json");
    let bytes = canonical_json_bytes(&serde_json::to_value(record).unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn install_authority(
    root: &Path,
) -> super::super::workspace_review_authority::VerifiedWorkspaceReviewAuthority {
    let record = authority_record();
    super::super::approval_enrollment::write_test_enrollment_bindings(
        root,
        &record.device_binding,
        &record.installation_binding,
    )
    .unwrap();
    let path = write_authority_candidate(root, &record);
    super::super::workspace_review_authority::install_record_at_for_test(root, &path, NOW_MS)
        .unwrap();
    super::super::workspace_review_authority::read_installed_record(root, NOW_MS)
        .unwrap()
        .unwrap()
}

fn bindings() -> [String; 8] {
    [
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64),
        "4".repeat(64),
        "5".repeat(64),
        "6".repeat(64),
        "7".repeat(64),
        "8".repeat(64),
    ]
}

fn context<'a>(
    bindings: &'a [String; 8],
    retry_scope_binding: &'a str,
) -> WorkspaceReviewDecisionContext<'a> {
    WorkspaceReviewDecisionContext {
        workspace_binding: &bindings[0],
        device_binding: &bindings[1],
        installation_binding: &bindings[2],
        scope_binding: &bindings[3],
        request_binding: &bindings[0],
        action_binding: &bindings[4],
        intent_binding: &bindings[5],
        revision_binding: &bindings[6],
        policy_binding: &bindings[7],
        retry_scope_binding,
    }
}

fn signed_envelope(
    authority: &super::super::workspace_review_authority::VerifiedWorkspaceReviewAuthority,
    context: &WorkspaceReviewDecisionContext<'_>,
    claim_seed: u8,
    issued_at_ms: u64,
    expires_at_ms: u64,
    domain: &[u8],
) -> WorkspaceReviewDecisionEnvelopeV1 {
    let mut envelope = WorkspaceReviewDecisionEnvelopeV1 {
        schema: NATIVE_WORKSPACE_REVIEW_DECISION_V1_SCHEMA.to_owned(),
        version: NATIVE_WORKSPACE_REVIEW_DECISION_V1_VERSION,
        purpose: NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE.to_owned(),
        authority_generation: authority.enrollment_generation,
        authority_key_id: authority.key_id.clone(),
        authority_record_digest: authority.record_digest.clone(),
        workspace_binding: context.workspace_binding.to_owned(),
        device_binding: context.device_binding.to_owned(),
        installation_binding: context.installation_binding.to_owned(),
        scope_binding: context.scope_binding.to_owned(),
        request_binding: context.request_binding.to_owned(),
        action_binding: context.action_binding.to_owned(),
        intent_binding: context.intent_binding.to_owned(),
        revision_binding: context.revision_binding.to_owned(),
        policy_binding: context.policy_binding.to_owned(),
        retry_scope_binding: context.retry_scope_binding.to_owned(),
        delivery_mode: NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY.to_owned(),
        decision: "allow".to_owned(),
        claim_id: format!("{claim_seed:02x}").repeat(32),
        issued_at_ms,
        expires_at_ms,
        decision_signature: String::new(),
    };
    let signing = signing_bytes(&envelope).unwrap();
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&REVIEW_SEED).unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(domain);
    message.extend_from_slice(&signing);
    envelope.decision_signature = hex::encode(key_pair.sign(&message).as_ref());
    envelope
}

#[test]
fn accepts_exact_retry_decision_and_claims_it_once_durably() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry_scope = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry_scope);
    let envelope = signed_envelope(
        &authority,
        &context,
        1,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );

    let verified = verify_and_claim_at(&root, &envelope, &context, NOW_MS).unwrap();
    assert_eq!(verified.decision, "allow");
    assert_eq!(verified.retry_scope_binding, retry_scope);
    assert!(!verified.replayed);
    let resumed = verify_and_claim_at(&root, &envelope, &context, NOW_MS).unwrap();
    assert!(resumed.replayed);
    let state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert_eq!(state.consumed_claims.len(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_wall_clock_rollback_before_replay_lookup() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry_scope = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry_scope);
    let envelope = signed_envelope(
        &authority,
        &context,
        9,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );

    verify_and_claim_at(&root, &envelope, &context, NOW_MS + 100).unwrap();
    let state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert_eq!(state.last_observed_time_ms, NOW_MS + 100);
    assert_eq!(
        verify_and_claim_at(&root, &envelope, &context, NOW_MS + 99).unwrap_err(),
        "native_workspace_review_clock_rollback"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_expiry_claims_seed_a_conservative_clock_floor() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry_scope = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry_scope);
    let mut state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    state.consumed_claims.push(
        super::super::workspace_review_secure_state::WorkspaceReviewClaimV1 {
            claim_id: "a".repeat(64),
            envelope_digest: "b".repeat(64),
            expires_at_ms: Some(NOW_MS + 100),
        },
    );
    super::super::workspace_review_secure_state::store(&root, &state).unwrap();

    let envelope = signed_envelope(
        &authority,
        &context,
        11,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    assert_eq!(
        verify_and_claim_at(&root, &envelope, &context, NOW_MS).unwrap_err(),
        "native_workspace_review_clock_rollback"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn expired_claim_is_not_recovered_after_post_claim_crash_window() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry_scope = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry_scope);
    let envelope = signed_envelope(
        &authority,
        &context,
        10,
        NOW_MS,
        NOW_MS + 500,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );

    verify_and_claim_at(&root, &envelope, &context, NOW_MS).unwrap();
    assert_eq!(
        verify_and_claim_at(&root, &envelope, &context, NOW_MS + 500).unwrap_err(),
        "native_workspace_review_decision_expired"
    );
    let state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert_eq!(state.consumed_claims.len(), 1);
    assert_eq!(state.last_observed_time_ms, NOW_MS + 500);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_wrong_domain_delivery_mode_and_binding_substitution() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry_scope = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry_scope);
    let envelope = signed_envelope(&authority, &context, 2, NOW_MS, 61_000, b"wrong-domain\0");
    assert_eq!(
        verify_envelope(&envelope, &authority, &context, NOW_MS).unwrap_err(),
        "native_workspace_review_decision_signature_invalid"
    );

    let mut wrong_delivery = signed_envelope(
        &authority,
        &context,
        3,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    wrong_delivery.delivery_mode = "original_continuation".to_owned();
    assert_eq!(
        verify_envelope(&wrong_delivery, &authority, &context, NOW_MS).unwrap_err(),
        "native_workspace_review_decision_invalid"
    );

    let mut wrong_scope = signed_envelope(
        &authority,
        &context,
        8,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    wrong_scope.scope_binding = "9".repeat(64);
    assert_eq!(
        verify_envelope(&wrong_scope, &authority, &context, NOW_MS).unwrap_err(),
        "native_workspace_review_decision_provenance_mismatch"
    );

    let mut wrong_action = signed_envelope(
        &authority,
        &context,
        4,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    wrong_action.action_binding = "9".repeat(64);
    let signing = signing_bytes(&wrong_action).unwrap();
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&REVIEW_SEED).unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN);
    message.extend_from_slice(&signing);
    wrong_action.decision_signature = hex::encode(key_pair.sign(&message).as_ref());
    assert_eq!(
        verify_envelope(&wrong_action, &authority, &context, NOW_MS).unwrap_err(),
        "native_workspace_review_decision_binding_mismatch"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn prunes_only_expired_claims_before_replay_capacity_is_checked() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry_scope = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry_scope);
    let mut state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    state.consumed_claims = (0..NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES)
        .map(
            |index| super::super::workspace_review_secure_state::WorkspaceReviewClaimV1 {
                claim_id: format!("{index:064x}"),
                envelope_digest: format!("{:064x}", index + 1),
                expires_at_ms: Some(NOW_MS - 1),
            },
        )
        .collect();
    super::super::workspace_review_secure_state::store(&root, &state).unwrap();

    let envelope = signed_envelope(
        &authority,
        &context,
        1,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    verify_and_claim_at(&root, &envelope, &context, NOW_MS).unwrap();
    let updated = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert_eq!(updated.consumed_claims.len(), 1);
    assert_eq!(updated.consumed_claims[0].expires_at_ms, Some(61_000));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_expired_future_and_noncanonical_or_unknown_decisions() {
    let root = test_root();
    let authority = install_authority(&root);
    let values = bindings();
    let retry_scope = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    let context = context(&values, &retry_scope);
    let expired = signed_envelope(
        &authority,
        &context,
        5,
        1_000,
        1_500,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    assert_eq!(
        verify_envelope(&expired, &authority, &context, NOW_MS).unwrap_err(),
        "native_workspace_review_decision_expired"
    );
    let future = signed_envelope(
        &authority,
        &context,
        6,
        3_000,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    assert_eq!(
        verify_envelope(&future, &authority, &context, NOW_MS).unwrap_err(),
        "native_workspace_review_decision_not_yet_valid"
    );

    let valid = signed_envelope(
        &authority,
        &context,
        7,
        NOW_MS,
        61_000,
        NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    );
    let mut value: Value = serde_json::to_value(&valid).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("remoteApproval".to_owned(), Value::Bool(true));
    let bytes = canonical_json_bytes(&value).unwrap();
    assert_eq!(
        super::super::workspace_review_decision::verify_and_claim_bytes_at(
            &root, &bytes, &context, NOW_MS
        )
        .unwrap_err(),
        "native_workspace_review_decision_invalid"
    );
    let mut noncanonical = canonical_json_bytes(&serde_json::to_value(&valid).unwrap()).unwrap();
    noncanonical.push(b'\n');
    assert_eq!(
        super::super::workspace_review_decision::verify_and_claim_bytes_at(
            &root,
            &noncanonical,
            &context,
            NOW_MS,
        )
        .unwrap_err(),
        "native_workspace_review_decision_noncanonical"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn retry_scope_is_derived_from_exact_action_intent_revision_and_policy() {
    let values = bindings();
    let expected = retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    assert_ne!(
        expected,
        retry_scope_binding(&values[4], &values[5], &values[6], &"a".repeat(64)).unwrap()
    );
}
