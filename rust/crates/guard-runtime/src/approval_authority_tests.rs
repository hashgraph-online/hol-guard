use super::*;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_root_is_only_a_test_fixture() {
    verify_test_root_matches_compiled_key();
}

#[test]
fn test_record_contains_distinct_provenance_bindings() {
    let public_key = [17u8; 32];
    let signature =
        enrollment_signature_for_tests(&public_key, 1, &test_enrollment_root_seed()).unwrap();
    let bytes = canonical_record_for_enrollment(&public_key, 1, &signature).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_ne!(value["device_binding"], value["installation_binding"]);
    assert_ne!(value["device_binding"], value["key_id"]);
    assert_ne!(value["installation_binding"], value["key_id"]);
}

#[test]
fn fresh_private_state_without_public_authority_is_unenrolled() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hol-guard-approval-authority-fresh-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    crate::resident_state::protect_windows_private_path(&root, true).unwrap();
    assert!(load(&root).unwrap().is_none());
    let _ = fs::remove_dir_all(root);
}
