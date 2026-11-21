use super::*;
#[cfg(windows)]
use crate::policy_store::policy_store_persistence;
use crate::policy_store::{approval_enrollment, workspace_review_authority};

pub(crate) fn authority_record() -> WorkspaceReviewAuthorityV1 {
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
    let signing = workspace_review_authority::signing_bytes(&record).unwrap();
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&ROOT_SEED).unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN);
    message.extend_from_slice(&signing);
    record.enrollment_signature = hex::encode(key_pair.sign(&message).as_ref());
    record
}

pub(crate) fn write_authority_candidate(
    root: &Path,
    record: &WorkspaceReviewAuthorityV1,
) -> PathBuf {
    let path = root.join("authority-candidate.json");
    let bytes = canonical_json_bytes(&serde_json::to_value(record).unwrap()).unwrap();
    #[cfg(windows)]
    {
        policy_store_persistence::persist_private_bytes(
            &path,
            &bytes,
            NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES as u64,
            "workspace_review_authority_test",
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

pub(super) fn install_authority(
    root: &Path,
) -> workspace_review_authority::VerifiedWorkspaceReviewAuthority {
    let record = authority_record();
    approval_enrollment::write_test_enrollment_bindings(
        root,
        &record.device_binding,
        &record.installation_binding,
    )
    .unwrap();
    let path = write_authority_candidate(root, &record);
    workspace_review_authority::install_record_at_for_test(root, &path, NOW_MS).unwrap();
    workspace_review_authority::read_installed_record(root, NOW_MS)
        .unwrap()
        .unwrap()
}
