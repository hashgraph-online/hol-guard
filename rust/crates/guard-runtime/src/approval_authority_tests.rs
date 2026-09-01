use super::*;
use serde_json::Value;

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
