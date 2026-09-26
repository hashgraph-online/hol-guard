use super::{
    install_record_at_for_test, load_at_for_test, signing_bytes, validate_transition,
    verify_record, verify_record_bytes, AUTHORITY_FILE_NAME,
};
use guard_contracts::{
    WorkspaceReviewAuthorityV1, NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE,
    NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_SCHEMA, NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_VERSION,
    NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN, NATIVE_WORKSPACE_REVIEW_KEY_ALGORITHM_ED25519,
    NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const NOW_MS: u64 = 2_000;
const ROOT_SEED: [u8; 32] = [42u8; 32];
static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn test_root() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "hol-guard-workspace-review-authority-{}-{suffix}-{}",
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

fn write_candidate(root: &Path, name: &str, record: &WorkspaceReviewAuthorityV1) -> PathBuf {
    let path = root.join(name);
    fs::write(
        &path,
        canonical_bytes(&sign_record(
            record.clone(),
            &ROOT_SEED,
            NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
        )),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn seed_local_enrollment(root: &Path, record: &WorkspaceReviewAuthorityV1) {
    super::super::approval_enrollment::write_test_enrollment_bindings(
        root,
        &record.device_binding,
        &record.installation_binding,
    )
    .unwrap();
}

fn stage_pending_authority(root: &Path, record: &WorkspaceReviewAuthorityV1) {
    let verified = verify_record(record, NOW_MS).unwrap();
    let bytes = canonical_bytes(record);
    let state =
        super::super::workspace_review_secure_state::WorkspaceReviewSecureStateV1::for_authority(
            &verified,
        )
        .with_pending_authority_record(&bytes)
        .unwrap();
    super::super::workspace_review_secure_state::store(root, &state).unwrap();
}

fn public_key(seed: u8) -> [u8; 32] {
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    key_pair.public_key().as_ref().try_into().unwrap()
}

fn base_record(
    seed: u8,
    generation: u64,
    previous_key_id: Option<String>,
    status: &str,
) -> WorkspaceReviewAuthorityV1 {
    let key = public_key(seed);
    WorkspaceReviewAuthorityV1 {
        schema: NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_SCHEMA.to_owned(),
        version: NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_VERSION,
        purpose: NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE.to_owned(),
        key_algorithm: NATIVE_WORKSPACE_REVIEW_KEY_ALGORITHM_ED25519.to_owned(),
        key_id: digest_bytes(&key),
        public_key: hex::encode(key),
        workspace_binding: digest_bytes(b"workspace-1"),
        device_binding: digest_bytes(b"device-1"),
        installation_binding: digest_bytes(b"installation-1"),
        enrollment_generation: generation,
        previous_key_id,
        scope_contract_version: NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1.to_owned(),
        scope_binding: digest_bytes(b"scope-workspace-review"),
        issued_at_ms: 1_000,
        expires_at_ms: 1_000 + 60_000,
        status: status.to_owned(),
        enrollment_signature: String::new(),
    }
}

fn sign_record(
    mut record: WorkspaceReviewAuthorityV1,
    seed: &[u8; 32],
    domain: &[u8],
) -> WorkspaceReviewAuthorityV1 {
    let signing = signing_bytes(&record).unwrap();
    let mut message = Vec::with_capacity(domain.len() + signing.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&signing);
    let key_pair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    record.enrollment_signature = hex::encode(key_pair.sign(&message).as_ref());
    record
}

fn initial_record() -> WorkspaceReviewAuthorityV1 {
    sign_record(
        base_record(9, 1, None, "active"),
        &ROOT_SEED,
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    )
}

fn canonical_bytes(record: &WorkspaceReviewAuthorityV1) -> Vec<u8> {
    canonical_json_bytes(&serde_json::to_value(record).unwrap()).unwrap()
}

fn assert_invalid(record: &WorkspaceReviewAuthorityV1, expected: &str) {
    assert_eq!(verify_record(record, NOW_MS).unwrap_err(), expected);
}

#[test]
fn accepts_root_signed_initial_ed25519_authority() {
    let record = initial_record();
    let verified = verify_record(&record, NOW_MS).unwrap();
    assert_eq!(verified.key_id, record.key_id);
    assert_eq!(verified.workspace_binding, record.workspace_binding);
    assert_eq!(verified.status, "active");
    assert_eq!(verified.public_key, public_key(9));
    assert!(validate_transition(None, &verified).is_ok());
}

#[test]
fn rejects_wrong_root_and_wrong_domain_signatures() {
    let record = base_record(9, 1, None, "active");
    let wrong_root = sign_record(
        record.clone(),
        &[7u8; 32],
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    );
    assert_invalid(
        &wrong_root,
        "native_workspace_review_authority_enrollment_invalid",
    );
    let wrong_domain = sign_record(record, &ROOT_SEED, b"wrong-domain\0");
    assert_invalid(
        &wrong_domain,
        "native_workspace_review_authority_enrollment_invalid",
    );
}

#[test]
fn rejects_unsupported_algorithm_and_key_id_mismatch() {
    let mut unsupported = base_record(9, 1, None, "active");
    unsupported.key_algorithm = "rsa-pss-sha256".to_owned();
    unsupported = sign_record(
        unsupported,
        &ROOT_SEED,
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    );
    assert_invalid(
        &unsupported,
        "native_workspace_review_authority_key_algorithm_unsupported",
    );

    let mut mismatched = initial_record();
    mismatched.key_id = "00".repeat(32);
    assert_invalid(
        &mismatched,
        "native_workspace_review_authority_key_id_mismatch",
    );
}

#[test]
fn rejects_invalid_bindings_scope_and_expiry() {
    let mut same_installation = initial_record();
    same_installation.device_binding = same_installation.installation_binding.clone();
    assert_invalid(
        &same_installation,
        "native_workspace_review_authority_invalid",
    );

    let mut invalid_scope = initial_record();
    invalid_scope.scope_binding = "not-a-digest".to_owned();
    assert_invalid(&invalid_scope, "native_workspace_review_authority_invalid");

    let mut expired = initial_record();
    expired = sign_record(
        expired,
        &ROOT_SEED,
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    );
    assert_eq!(
        verify_record(&expired, expired.expires_at_ms).unwrap_err(),
        "native_workspace_review_authority_expired"
    );

    let mut future_dated = initial_record();
    future_dated.issued_at_ms = NOW_MS + 1;
    future_dated = sign_record(
        future_dated,
        &ROOT_SEED,
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    );
    assert_eq!(
        verify_record(&future_dated, NOW_MS).unwrap_err(),
        "native_workspace_review_authority_not_yet_valid"
    );
}

#[test]
fn rejects_noncanonical_and_unknown_fields() {
    let record = initial_record();
    let mut bytes = canonical_bytes(&record);
    bytes.push(b'\n');
    assert_eq!(
        verify_record_bytes(&bytes, NOW_MS).unwrap_err(),
        "native_workspace_review_authority_noncanonical"
    );

    let mut value: Value = serde_json::from_slice(&canonical_bytes(&record)).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), Value::Bool(true));
    let bytes = canonical_json_bytes(&value).unwrap();
    assert_eq!(
        verify_record_bytes(&bytes, NOW_MS).unwrap_err(),
        "native_workspace_review_authority_invalid"
    );
}

#[test]
fn enforces_monotonic_rotation_and_terminal_revocation() {
    let initial = verify_record(&initial_record(), NOW_MS).unwrap();
    let rotation_record = sign_record(
        base_record(10, 2, Some(initial.key_id.clone()), "active"),
        &ROOT_SEED,
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    );
    let rotation = verify_record(&rotation_record, NOW_MS).unwrap();
    assert!(validate_transition(Some(&initial), &rotation).is_ok());

    let rollback_record = sign_record(
        base_record(10, 2, Some(initial.key_id.clone()), "active"),
        &ROOT_SEED,
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    );
    let rollback = verify_record(&rollback_record, NOW_MS).unwrap();
    assert_eq!(
        validate_transition(Some(&rotation), &rollback).unwrap_err(),
        "native_workspace_review_authority_generation_rollback"
    );

    let mut revocation_record = base_record(10, 3, None, "revoked");
    revocation_record = sign_record(
        revocation_record,
        &ROOT_SEED,
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    );
    let revocation = verify_record(&revocation_record, NOW_MS).unwrap();
    assert!(validate_transition(Some(&rotation), &revocation).is_ok());

    let reactivation_record = sign_record(
        base_record(11, 4, Some(revocation.key_id.clone()), "active"),
        &ROOT_SEED,
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    );
    let reactivation = verify_record(&reactivation_record, NOW_MS).unwrap();
    assert_eq!(
        validate_transition(Some(&revocation), &reactivation).unwrap_err(),
        "native_workspace_review_authority_revoked"
    );
}

#[test]
fn rejects_rotation_with_changed_provenance_or_scope() {
    let initial = verify_record(&initial_record(), NOW_MS).unwrap();
    let mut candidate = base_record(10, 2, Some(initial.key_id.clone()), "active");
    candidate.workspace_binding = digest_bytes(b"workspace-2");
    candidate = sign_record(
        candidate,
        &ROOT_SEED,
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    );
    let candidate = verify_record(&candidate, NOW_MS).unwrap();
    assert_eq!(
        validate_transition(Some(&initial), &candidate).unwrap_err(),
        "native_workspace_review_authority_provenance_mismatch"
    );
}

#[test]
fn resident_install_preserves_rotation_after_expiry_and_terminal_revocation() {
    let root = test_root();
    let mut expired_initial = base_record(9, 1, None, "active");
    expired_initial.expires_at_ms = 1_500;
    seed_local_enrollment(&root, &expired_initial);
    let initial_path = write_candidate(&root, "initial.json", &expired_initial);
    install_record_at_for_test(&root, &initial_path, 1_200).unwrap();

    let rotation = base_record(10, 2, Some(expired_initial.key_id.clone()), "active");
    let rotation_path = write_candidate(&root, "rotation.json", &rotation);
    install_record_at_for_test(&root, &rotation_path, NOW_MS).unwrap();
    assert_eq!(
        load_at_for_test(&root, NOW_MS)
            .unwrap()
            .unwrap()
            .enrollment_generation,
        2
    );

    let revoked = base_record(10, 3, None, "revoked");
    let revoked_path = write_candidate(&root, "revoked.json", &revoked);
    install_record_at_for_test(&root, &revoked_path, NOW_MS).unwrap();
    assert_eq!(
        load_at_for_test(&root, NOW_MS).unwrap_err(),
        "native_workspace_review_authority_revoked"
    );

    let reactivated = base_record(11, 4, Some(revoked.key_id.clone()), "active");
    let reactivated_path = write_candidate(&root, "reactivated.json", &reactivated);
    assert_eq!(
        install_record_at_for_test(&root, &reactivated_path, NOW_MS).unwrap_err(),
        "native_workspace_review_authority_revoked"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resident_rotation_preserves_last_observed_time_floor() {
    let root = test_root();
    let initial = initial_record();
    seed_local_enrollment(&root, &initial);
    let initial_path = write_candidate(&root, "initial.json", &initial);
    install_record_at_for_test(&root, &initial_path, NOW_MS).unwrap();

    let mut state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    state.last_observed_time_ms = NOW_MS + 500;
    super::super::workspace_review_secure_state::store(&root, &state).unwrap();

    let rotation = base_record(10, 2, Some(initial.key_id.clone()), "active");
    let rotation_path = write_candidate(&root, "rotation-floor.json", &rotation);
    install_record_at_for_test(&root, &rotation_path, NOW_MS + 500).unwrap();

    let rotated_state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert_eq!(rotated_state.last_observed_time_ms, NOW_MS + 500);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resident_state_is_required_after_restart_and_same_record_install() {
    let root = test_root();
    let initial = initial_record();
    seed_local_enrollment(&root, &initial);
    let initial_path = write_candidate(&root, "initial.json", &initial);
    install_record_at_for_test(&root, &initial_path, NOW_MS).unwrap();
    fs::remove_file(root.join("workspace-review-authority-v1-state.test.json")).unwrap();
    assert_eq!(
        load_at_for_test(&root, NOW_MS).unwrap_err(),
        "native_workspace_review_secure_state_unavailable"
    );
    assert_eq!(
        install_record_at_for_test(&root, &initial_path, NOW_MS).unwrap_err(),
        "native_workspace_review_secure_state_unavailable"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resident_install_requires_the_existing_local_enrollment_identity() {
    let root = test_root();
    let initial = initial_record();
    let initial_path = write_candidate(&root, "initial.json", &initial);
    assert_eq!(
        install_record_at_for_test(&root, &initial_path, NOW_MS).unwrap_err(),
        "native_workspace_review_enrollment_required"
    );
    super::super::approval_enrollment::write_test_enrollment_bindings(
        &root,
        &digest_bytes(b"different-device"),
        &initial.installation_binding,
    )
    .unwrap();
    assert_eq!(
        install_record_at_for_test(&root, &initial_path, NOW_MS).unwrap_err(),
        "native_workspace_review_authority_provenance_mismatch"
    );
    seed_local_enrollment(&root, &initial);
    install_record_at_for_test(&root, &initial_path, NOW_MS).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resident_load_recovers_a_pending_authority_file_after_crash() {
    let root = test_root();
    let initial = initial_record();
    seed_local_enrollment(&root, &initial);
    let initial_path = write_candidate(&root, "initial.json", &initial);
    install_record_at_for_test(&root, &initial_path, NOW_MS).unwrap();

    let rotation = sign_record(
        base_record(10, 2, Some(initial.key_id.clone()), "active"),
        &ROOT_SEED,
        NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN,
    );
    stage_pending_authority(&root, &rotation);
    fs::remove_file(root.join(AUTHORITY_FILE_NAME)).unwrap();

    assert_eq!(
        load_at_for_test(&root, NOW_MS)
            .unwrap()
            .unwrap()
            .enrollment_generation,
        2
    );
    let state = super::super::workspace_review_secure_state::load(&root)
        .unwrap()
        .unwrap();
    assert!(state.pending_authority_record.is_none());
    assert_eq!(
        fs::read(root.join(AUTHORITY_FILE_NAME)).unwrap(),
        canonical_bytes(&rotation)
    );
    fs::remove_dir_all(root).unwrap();
}
