use super::super::{signing_bytes, verify_record};
use super::{base_record, NOW_MS};
use guard_policy_snapshot::digest_bytes;

#[test]
fn verifies_python_issuer_canonical_certificate() {
    let mut record = base_record(9, 1, None, "active");
    record.workspace_binding = "1".repeat(64);
    record.device_binding = "2".repeat(64);
    record.installation_binding = "3".repeat(64);
    record.scope_binding = "4".repeat(64);
    assert_eq!(
        digest_bytes(&signing_bytes(&record).unwrap()),
        "df5f21e909cbe2d7f4083b8292cf4fb3b6a29743825c7d74bc871fee1c3bbbf7"
    );
    record.enrollment_signature = concat!(
        "aecd796bba8372b95c3b4caef42b1d95885582fc218f037c789dbce58259df312728",
        "22ade2ae94f9f6a488b06c5d865b28d4a61fe272e584c01edb9c6633a309"
    )
    .to_owned();
    assert!(verify_record(&record, NOW_MS).is_ok());
    record.scope_binding = "5".repeat(64);
    assert_eq!(
        verify_record(&record, NOW_MS).unwrap_err(),
        "native_workspace_review_authority_enrollment_invalid"
    );
}
