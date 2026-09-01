#[cfg(test)]
fn test_enrollment_signature(record: &ApprovalAuthorityV4) -> Result<String, String> {
    let signing_bytes = record_signing_bytes(record)?;
    let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[42u8; 32])
        .map_err(|_| "native_approval_v4_authority_invalid".to_owned())?;
    let mut message =
        Vec::with_capacity(NATIVE_APPROVAL_V4_ENROLLMENT_DOMAIN.len() + signing_bytes.len());
    message.extend_from_slice(NATIVE_APPROVAL_V4_ENROLLMENT_DOMAIN);
    message.extend_from_slice(&signing_bytes);
    Ok(hex::encode(key_pair.sign(&message).as_ref()))
}

/// Test-only fixture writer. Production accepts only externally supplied
/// records and never exposes an enrollment private key.
#[cfg(test)]
pub(crate) fn test_record_bytes(record: &ApprovalAuthorityV4) -> Result<Vec<u8>, String> {
    let mut signed = record.clone();
    signed.enrollment_signature = test_enrollment_signature(&signed)?;
    let value = serde_json::to_value(&signed)
        .map_err(|_| "native_approval_v4_authority_invalid".to_owned())?;
    canonical_json_bytes(&value).map_err(|_| "native_approval_v4_authority_invalid".to_owned())
}

#[cfg(test)]
pub(crate) fn write_test_record(
    state_base: &Path,
    record: &ApprovalAuthorityV4,
) -> Result<(), String> {
    let bytes = test_record_bytes(record)?;
    let path = state_base.join(AUTHORITY_FILE_NAME);
    fs::write(&path, &bytes).map_err(|_| "native_approval_v4_authority_invalid".to_owned())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| "native_approval_v4_authority_invalid".to_owned())?;
    }
    let signed: ApprovalAuthorityV4 = serde_json::from_slice(&bytes)
        .map_err(|_| "native_approval_v4_authority_invalid".to_owned())?;
    let (credential_id, cose_public_key) = validate_record(&signed)?;
    let authority = ApprovalV4Authority {
        credential_id,
        cose_public_key,
        algorithm: signed.algorithm,
        rp_id: signed.rp_id.clone(),
        origin: signed.origin.clone(),
        key_id: signed.key_id.clone(),
        device_binding: signed.device_binding.clone(),
        installation_binding: signed.installation_binding.clone(),
        enrollment_generation: signed.enrollment_generation,
        status: signed.status,
        path,
        fingerprint: String::new(),
        record_digest: guard_policy_snapshot::digest_bytes(&bytes),
        state_base: state_base.to_owned(),
        sign_count: Arc::new(Mutex::new(0)),
        assertions: Arc::new(Mutex::new(HashMap::new())),
    };
    let state = secure_state_value(&authority, 0)?;
    crate::policy_store::approval_v4_secure_state::store(state_base, &state)
}

use super::*;
use guard_contracts::NATIVE_APPROVAL_V4_ALGORITHM_ED25519;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::time::{SystemTime, UNIX_EPOCH};

fn test_root() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "hol-guard-approval-v4-authority-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

fn cose_for(seed: u8) -> Vec<u8> {
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    cose.extend_from_slice(key_pair.public_key().as_ref());
    cose
}

fn record(
    credential_id: u8,
    cose_public_key: &[u8],
    generation: u64,
    previous_key_id: Option<String>,
    status: &str,
) -> ApprovalAuthorityV4 {
    ApprovalAuthorityV4 {
        schema: guard_contracts::NATIVE_APPROVAL_AUTHORITY_V4_SCHEMA.to_owned(),
        version: 4,
        key_id: guard_policy_snapshot::digest_bytes(cose_public_key),
        rp_id: "example.com".to_owned(),
        origin: "https://example.com".to_owned(),
        credential_id: hex::encode([credential_id; 32]),
        cose_public_key: hex::encode(cose_public_key),
        algorithm: NATIVE_APPROVAL_V4_ALGORITHM_ED25519,
        device_binding: "d".repeat(64),
        installation_binding: "e".repeat(64),
        enrollment_generation: generation,
        previous_key_id,
        status: status.to_owned(),
        enrollment_signature: String::new(),
    }
}

fn write_candidate(root: &Path, name: &str, record: &ApprovalAuthorityV4) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, test_record_bytes(record).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn write_provisional_state(state_base: &Path, bytes: &[u8], sign_count: u32) {
    let signed: ApprovalAuthorityV4 = serde_json::from_slice(bytes).unwrap();
    let (credential_id, cose_public_key) = validate_record(&signed).unwrap();
    let authority = ApprovalV4Authority {
        credential_id,
        cose_public_key,
        algorithm: signed.algorithm,
        rp_id: signed.rp_id.clone(),
        origin: signed.origin.clone(),
        key_id: signed.key_id.clone(),
        device_binding: signed.device_binding.clone(),
        installation_binding: signed.installation_binding.clone(),
        enrollment_generation: signed.enrollment_generation,
        status: signed.status.clone(),
        path: state_base.join(AUTHORITY_FILE_NAME),
        fingerprint: String::new(),
        record_digest: guard_policy_snapshot::digest_bytes(bytes),
        state_base: state_base.to_owned(),
        sign_count: Arc::new(Mutex::new(sign_count)),
        assertions: Arc::new(Mutex::new(HashMap::new())),
    };
    let state = secure_state_value(&authority, sign_count).unwrap();
    crate::policy_store::approval_v4_secure_state::store(state_base, &state).unwrap();
}

#[test]
fn rotation_is_strictly_monotonic_and_revocation_is_terminal() {
    let root = test_root();
    let first_cose = cose_for(31);
    let first = record(1, &first_cose, 1, None, "active");
    write_test_record(&root, &first).unwrap();
    let authority = load(&root).unwrap().unwrap();
    advance_sign_count(&authority, 7).unwrap();

    let second_cose = cose_for(32);
    let second = record(2, &second_cose, 2, Some(first.key_id.clone()), "active");
    let second_path = write_candidate(&root, "candidate-v4.json", &second);
    // Simulate a crash after the new secure counter record was committed but
    // before the public authority replacement. Recovery may trust this state
    // only because the candidate is root-authenticated and its exact digest
    // is already pinned in the secure record.
    let second_bytes = test_record_bytes(&second).unwrap();
    write_provisional_state(&root, &second_bytes, 0);
    install_record(&root, &second_path).unwrap();
    let rotated = load(&root).unwrap().unwrap();
    assert_eq!(rotated.enrollment_generation, 2);
    assert_eq!(sign_count(&rotated).unwrap(), 0);

    let rollback = record(3, &first_cose, 2, Some(second.key_id.clone()), "active");
    let rollback_path = write_candidate(&root, "rollback-v4.json", &rollback);
    assert_eq!(
        install_record(&root, &rollback_path).unwrap_err(),
        "native_approval_v4_authority_generation_rollback"
    );

    let revoked = record(2, &second_cose, 3, None, "revoked");
    let revoked_path = write_candidate(&root, "revoked-v4.json", &revoked);
    install_record(&root, &revoked_path).unwrap();
    assert_eq!(
        load(&root).unwrap_err(),
        "native_approval_v4_authority_revoked"
    );

    let reactivated = record(3, &first_cose, 4, Some(revoked.key_id.clone()), "active");
    let reactivated_path = write_candidate(&root, "reactivated-v4.json", &reactivated);
    assert_eq!(
        install_record(&root, &reactivated_path).unwrap_err(),
        "native_approval_v4_authority_revoked"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_cose_and_missing_secure_state_never_load() {
    let root = test_root();
    let malformed = record(1, &[0xa1, 0x01, 0x01], 1, None, "active");
    let malformed_path = write_candidate(&root, "malformed-v4.json", &malformed);
    assert_eq!(
        install_record(&root, &malformed_path).unwrap_err(),
        "native_approval_v4_authority_invalid"
    );

    let valid_cose = cose_for(34);
    let mut mismatched_origin = record(1, &valid_cose, 1, None, "active");
    mismatched_origin.origin = "https://other.example.com".to_owned();
    let mismatched_path = write_candidate(&root, "mismatched-origin-v4.json", &mismatched_origin);
    assert_eq!(
        install_record(&root, &mismatched_path).unwrap_err(),
        "native_approval_v4_authority_invalid"
    );

    let valid_cose = cose_for(33);
    let valid = record(1, &valid_cose, 1, None, "active");
    let valid_bytes = test_record_bytes(&valid).unwrap();
    fs::write(root.join(AUTHORITY_FILE_NAME), valid_bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            root.join(AUTHORITY_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    assert_eq!(
        load(&root).unwrap_err(),
        "native_approval_v4_secure_state_unavailable"
    );
    fs::remove_dir_all(root).unwrap();
}
