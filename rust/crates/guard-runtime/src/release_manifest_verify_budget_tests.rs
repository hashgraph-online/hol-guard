//! Budget bounds, command framing and raw-byte hashing for the release
//! manifest verifier.

use super::super::Limits;
use super::*;

#[test]
fn the_runtime_budgets_bound_hashing_and_traversal() {
    let fixture = setup();
    write_unsigned(&fixture.manifest_path, &manifest(&fixture.runtime));
    let verify_within = |limits: Limits| {
        verify_release_manifest(
            &fixture.manifest_path,
            &fixture.runtime,
            &unsigned_ok(),
            &limits,
        )
        .reason_code
    };

    assert_eq!(
        verify_within(Limits {
            runtime_bytes: 1,
            ..LIMITS
        }),
        "release_manifest_size_limit_exceeded"
    );
    assert_eq!(
        verify_within(Limits {
            runtime_entries: 1,
            ..LIMITS
        }),
        "release_manifest_file_limit_exceeded"
    );
    assert_eq!(
        verify_within(Limits {
            runtime_files: 0,
            ..LIMITS
        }),
        "release_manifest_file_limit_exceeded"
    );
}

#[test]
fn the_command_answers_a_framed_request() {
    let fixture = setup();
    let payload = manifest(&fixture.runtime);
    let key = key_pair(3);
    write_signed(&fixture.manifest_path, &payload, &key);
    let request = json!({
        "schema": "release-manifest-verify.v1",
        "manifest_path": fixture.manifest_path,
        "runtime_root": fixture.runtime,
        "trusted_keys": {"release-1": hex::encode(key.public_key().as_ref())},
        "require_signature": true,
        "expected_native_version": "2.1.0",
    });

    let response = crate::release_manifest_verify_command::run_command(
        serde_json::to_vec(&request).unwrap().as_slice(),
    )
    .unwrap();

    assert_eq!(
        serde_json::from_slice::<Value>(&response).unwrap(),
        json!({
            "status": "healthy",
            "reason_code": "release_manifest_valid",
            "version": "2.1.0",
            "build_id": "build-1",
            "installer_identity": "org.hol.guard",
            "signature_state": "valid",
        })
    );
    for refused in [
        json!({"schema": "other", "manifest_path": "m", "runtime_root": "r", "require_signature": true}),
        json!({"schema": "release-manifest-verify.v1", "manifest_path": "m", "runtime_root": "r"}),
        json!({"schema": "release-manifest-verify.v1", "manifest_path": "m", "runtime_root": "r",
               "require_signature": true, "trusted_keys": {"k": "zz"}}),
        json!({"schema": "release-manifest-verify.v1", "manifest_path": "m", "runtime_root": "r",
               "require_signature": true, "unexpected": 1}),
    ] {
        assert!(crate::release_manifest_verify_command::run_command(
            serde_json::to_vec(&refused).unwrap().as_slice()
        )
        .is_err());
    }
}

#[test]
fn runtime_files_hash_their_raw_bytes() {
    let fixture = setup();
    let raw = b"guard\r\n-runtime\x1a-after-control-z";
    let runtime_file = fixture.root.join("runtime-file");
    std::fs::write(&runtime_file, raw).unwrap();

    let (digest, consumed, metadata) = super::super::files::hash_regular_file(&runtime_file, 1024)
        .unwrap_or_else(|_| panic!("hash failed"));

    assert_eq!(digest, hex::encode(Sha256::digest(raw)));
    assert_eq!(consumed, raw.len() as u64);
    assert_eq!(metadata.len(), consumed);
}
