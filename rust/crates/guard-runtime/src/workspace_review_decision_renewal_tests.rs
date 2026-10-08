use super::{
    semantic_decision_digest, signing_bytes, verify_and_claim_at, WorkspaceReviewDecisionContext,
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
    NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
const NOW_MS: u64 = 2_000;
const ROOT_SEED: [u8; 32] = [42u8; 32];
pub(super) const REVIEW_SEED: [u8; 32] = [9u8; 32];
const ROTATED_REVIEW_SEED: [u8; 32] = [17u8; 32];
static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn test_root() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "hol-guard-workspace-review-renewal-{}-{suffix}-{}",
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

fn authority_record(
    review_seed: &[u8; 32],
    generation: u64,
    previous_key_id: Option<String>,
    status: &str,
) -> WorkspaceReviewAuthorityV1 {
    let public_key = Ed25519KeyPair::from_seed_unchecked(review_seed)
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
        enrollment_generation: generation,
        previous_key_id,
        scope_contract_version: NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1.to_owned(),
        scope_binding: "4".repeat(64),
        issued_at_ms: 1_000,
        expires_at_ms: 61_000,
        status: status.to_owned(),
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

fn write_authority_candidate(
    root: &Path,
    record: &WorkspaceReviewAuthorityV1,
    name: &str,
) -> PathBuf {
    let path = root.join(name);
    let bytes = canonical_json_bytes(&serde_json::to_value(record).unwrap()).unwrap();
    #[cfg(windows)]
    {
        super::super::policy_store_persistence::persist_private_bytes(
            &path,
            &bytes,
            NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES as u64,
            "workspace_review_authority_renewal_test",
            &crate::resident_state::private_root_for_state_base(root).unwrap(),
        )
        .unwrap();
    }
    #[cfg(not(windows))]
    fs::write(&path, bytes).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn install_record(
    root: &Path,
    record: &WorkspaceReviewAuthorityV1,
    name: &str,
) -> super::super::workspace_review_authority::VerifiedWorkspaceReviewAuthority {
    super::super::approval_enrollment::write_test_enrollment_bindings(
        root,
        &record.device_binding,
        &record.installation_binding,
    )
    .unwrap();
    let path = write_authority_candidate(root, record, name);
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

pub(super) fn context<'a>(
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

pub(super) fn signed_envelope(
    authority: &super::super::workspace_review_authority::VerifiedWorkspaceReviewAuthority,
    context: &WorkspaceReviewDecisionContext<'_>,
    claim_seed: u8,
    issued_at_ms: u64,
    expires_at_ms: u64,
    decision: &str,
    review_seed: &[u8; 32],
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
        decision: decision.to_owned(),
        claim_id: format!("{claim_seed:02x}").repeat(32),
        issued_at_ms,
        expires_at_ms,
        decision_signature: String::new(),
    };
    let signing = signing_bytes(&envelope).unwrap();
    let key_pair = Ed25519KeyPair::from_seed_unchecked(review_seed).unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN);
    message.extend_from_slice(&signing);
    envelope.decision_signature = hex::encode(key_pair.sign(&message).as_ref());
    envelope
}

pub(super) fn setup() -> (
    PathBuf,
    super::super::workspace_review_authority::VerifiedWorkspaceReviewAuthority,
    [String; 8],
    String,
) {
    let root = test_root();
    let authority = install_record(
        &root,
        &authority_record(&REVIEW_SEED, 1, None, "active"),
        "authority-v1.json",
    );
    let values = bindings();
    let retry_scope =
        super::retry_scope_binding(&values[4], &values[5], &values[6], &values[7]).unwrap();
    (root, authority, values, retry_scope)
}

#[test]
fn renewed_signature_after_transport_expiry_replays_same_claim() {
    let (root, authority, values, retry_scope) = setup();
    let context = context(&values, &retry_scope);
    let first = signed_envelope(
        &authority,
        &context,
        1,
        NOW_MS,
        NOW_MS + 500,
        "allow",
        &REVIEW_SEED,
    );
    verify_and_claim_at(&root, &first, &context, NOW_MS).unwrap();

    let renewed = signed_envelope(
        &authority,
        &context,
        1,
        NOW_MS + 1_000,
        NOW_MS + 5_000,
        "allow",
        &REVIEW_SEED,
    );
    let resumed = verify_and_claim_at(&root, &renewed, &context, NOW_MS + 1_000).unwrap();
    assert!(resumed.replayed);
    assert_ne!(
        digest_bytes(&canonical_json_bytes(&serde_json::to_value(&first).unwrap()).unwrap()),
        digest_bytes(&canonical_json_bytes(&serde_json::to_value(&renewed).unwrap()).unwrap())
    );
    assert_eq!(
        semantic_decision_digest(&first),
        semantic_decision_digest(&renewed)
    );
    assert_eq!(
        super::super::workspace_review_secure_state::load(&root)
            .unwrap()
            .unwrap()
            .claim_index
            .unwrap()
            .claim_count,
        1
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn legacy_claims_allow_exact_replay_but_not_renewal() {
    let (root, authority, values, retry_scope) = setup();
    let context = context(&values, &retry_scope);
    let first = signed_envelope(
        &authority,
        &context,
        2,
        NOW_MS,
        NOW_MS + 500,
        "allow",
        &REVIEW_SEED,
    );
    let envelope_digest =
        digest_bytes(&canonical_json_bytes(&serde_json::to_value(&first).unwrap()).unwrap());
    let mut state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    state.consumed_claims.push(
        super::super::workspace_review_secure_state::WorkspaceReviewClaimV1 {
            claim_id: first.claim_id.clone(),
            envelope_digest,
            semantic_decision_digest: None,
            legacy_semantic_recovered: false,
            expires_at_ms: None,
        },
    );
    super::super::workspace_review_secure_state::store(&root, &state).unwrap();
    assert!(
        verify_and_claim_at(&root, &first, &context, NOW_MS)
            .unwrap()
            .replayed
    );

    let renewed = signed_envelope(
        &authority,
        &context,
        2,
        NOW_MS + 1_000,
        NOW_MS + 5_000,
        "allow",
        &REVIEW_SEED,
    );
    assert_eq!(
        verify_and_claim_at(&root, &renewed, &context, NOW_MS + 1_000).unwrap_err(),
        "native_workspace_review_decision_replay"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn changed_semantics_and_duplicate_claim_ids_fail_closed() {
    let (root, authority, values, retry_scope) = setup();
    let context = context(&values, &retry_scope);
    let first = signed_envelope(
        &authority,
        &context,
        3,
        NOW_MS,
        NOW_MS + 5_000,
        "allow",
        &REVIEW_SEED,
    );
    verify_and_claim_at(&root, &first, &context, NOW_MS).unwrap();

    let changed_outcome = signed_envelope(
        &authority,
        &context,
        3,
        NOW_MS + 100,
        NOW_MS + 5_000,
        "deny",
        &REVIEW_SEED,
    );
    assert_eq!(
        verify_and_claim_at(&root, &changed_outcome, &context, NOW_MS + 100).unwrap_err(),
        "native_workspace_review_decision_replay"
    );

    let duplicate_id = signed_envelope(
        &authority,
        &context,
        4,
        NOW_MS + 100,
        NOW_MS + 5_000,
        "allow",
        &REVIEW_SEED,
    );
    assert_eq!(
        verify_and_claim_at(&root, &duplicate_id, &context, NOW_MS + 100).unwrap_err(),
        "native_workspace_review_decision_replay"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn authority_rotation_preserves_semantic_tombstone_but_revocation_rejects() {
    let (root, authority, values, retry_scope) = setup();
    let context = context(&values, &retry_scope);
    let first = signed_envelope(
        &authority,
        &context,
        5,
        NOW_MS,
        NOW_MS + 5_000,
        "allow",
        &REVIEW_SEED,
    );
    verify_and_claim_at(&root, &first, &context, NOW_MS).unwrap();

    let rotated_record = authority_record(
        &ROTATED_REVIEW_SEED,
        2,
        Some(authority.key_id.clone()),
        "active",
    );
    let indexed_state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert!(indexed_state.consumed_claims.is_empty());
    assert_eq!(indexed_state.claim_index.as_ref().unwrap().claim_count, 1);
    let rotated = install_record(&root, &rotated_record, "authority-v2.json");
    assert_eq!(
        super::super::workspace_review_secure_state::load(&root)
            .unwrap()
            .unwrap()
            .claim_index,
        indexed_state.claim_index
    );
    let renewed = signed_envelope(
        &rotated,
        &context,
        5,
        NOW_MS + 100,
        NOW_MS + 5_000,
        "allow",
        &ROTATED_REVIEW_SEED,
    );
    assert!(
        verify_and_claim_at(&root, &renewed, &context, NOW_MS + 100)
            .unwrap()
            .replayed
    );

    let revoked_record = authority_record(&ROTATED_REVIEW_SEED, 3, None, "revoked");
    let revoked_path =
        write_authority_candidate(&root, &revoked_record, "authority-v3-revoked.json");
    super::super::workspace_review_authority::install_record_at_for_test(
        &root,
        &revoked_path,
        NOW_MS + 200,
    )
    .unwrap();
    assert_eq!(
        super::super::workspace_review_secure_state::load(&root)
            .unwrap()
            .unwrap()
            .claim_index,
        indexed_state.claim_index
    );
    assert_eq!(
        verify_and_claim_at(&root, &renewed, &context, NOW_MS + 200).unwrap_err(),
        "native_workspace_review_authority_revoked"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn expired_renewal_and_clock_rollback_do_not_mutate_claim_state() {
    let (root, authority, values, retry_scope) = setup();
    let context = context(&values, &retry_scope);
    let first = signed_envelope(
        &authority,
        &context,
        6,
        NOW_MS,
        NOW_MS + 100,
        "allow",
        &REVIEW_SEED,
    );
    verify_and_claim_at(&root, &first, &context, NOW_MS).unwrap();
    let renewed = signed_envelope(
        &authority,
        &context,
        6,
        NOW_MS + 200,
        NOW_MS + 250,
        "allow",
        &REVIEW_SEED,
    );
    assert_eq!(
        verify_and_claim_at(&root, &renewed, &context, NOW_MS + 300).unwrap_err(),
        "native_workspace_review_decision_expired"
    );
    assert_eq!(
        verify_and_claim_at(&root, &first, &context, NOW_MS - 1).unwrap_err(),
        "native_workspace_review_clock_rollback"
    );
    let state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert!(state.consumed_claims.is_empty());
    assert_eq!(state.claim_index.unwrap().claim_count, 1);
    fs::remove_dir_all(root).unwrap();
}

#[path = "workspace_review_claim_capacity_tests.rs"]
mod capacity_tests;
