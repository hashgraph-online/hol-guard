use super::{
    retry_scope_binding, signing_bytes, verify_and_claim_at, verify_envelope,
    WorkspaceReviewDecisionContext,
};
#[cfg(windows)]
use guard_contracts::NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES;
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
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "workspace_review_decision_clock_tests.rs"]
mod clock_tests;
#[path = "workspace_review_interoperability_tests.rs"]
mod interoperability_tests;

#[path = "workspace_review_decision_test_authority.rs"]
mod fixtures;
#[path = "workspace_review_owned_dispatch_tests.rs"]
mod owned_dispatch_tests;
use fixtures::install_authority;
pub(crate) use fixtures::{authority_record, write_authority_candidate};

const NOW_MS: u64 = 2_000;
pub(crate) const ROOT_SEED: [u8; 32] = [42u8; 32];
pub(crate) const REVIEW_SEED: [u8; 32] = [9u8; 32];
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
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
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

pub(crate) fn signed_envelope(
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
    assert!(state.consumed_claims.is_empty());
    assert_eq!(state.claim_index.unwrap().claim_count, 1);
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
fn legacy_expiry_claims_seed_a_clock_floor_capped_at_wall_clock() {
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
            semantic_decision_digest: None,
            legacy_semantic_recovered: false,
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
    // The migration floor is capped at the honest wall clock (min(legacy
    // expiry, now_ms) = NOW_MS), so a fresh decision at now_ms is consumed
    // rather than rejected as a rollback. The stored floor still cannot move
    // backward, preserving rollback protection for later decisions.
    verify_and_claim_at(&root, &envelope, &context, NOW_MS).unwrap();
    let state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert_eq!(state.last_observed_time_ms, NOW_MS);
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
    assert!(state.consumed_claims.is_empty());
    assert_eq!(state.claim_index.unwrap().claim_count, 1);
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

#[test]
fn permanent_semantic_tombstones_fit_the_bounded_secure_state_budget() {
    let root = test_root();
    let authority = install_authority(&root);
    let mut state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    state.consumed_claims = (0..NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES)
        .map(
            |index| super::super::workspace_review_secure_state::WorkspaceReviewClaimV1 {
                claim_id: format!("{index:064x}"),
                envelope_digest: format!("{:064x}", index + 1),
                semantic_decision_digest: Some(format!("{:064x}", index + 2)),
                legacy_semantic_recovered: false,
                expires_at_ms: Some(NOW_MS - 1),
            },
        )
        .collect();
    super::super::workspace_review_secure_state::store(&root, &state).unwrap();
    let restored = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert_eq!(
        restored.consumed_claims.len(),
        NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES
    );
    assert_eq!(restored.consumed_claims, state.consumed_claims);
    drop(authority);
    fs::remove_dir_all(root).unwrap();
}
