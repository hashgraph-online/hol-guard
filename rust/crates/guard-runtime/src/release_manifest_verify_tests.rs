use std::path::{Path, PathBuf};

use base64::Engine as _;
use guard_command::inventory_fingerprints::python_compact_json;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{verify_release_manifest, Expectations, Verification, LIMITS};

#[path = "release_manifest_verify_budget_tests.rs"]
mod budget;

const RUNTIME_BYTES: &[u8] = b"guard-runtime";

fn manifest(runtime: &Path) -> Value {
    let executable = runtime.join("bin").join("hol-guard");
    std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
    std::fs::write(&executable, RUNTIME_BYTES).unwrap();
    json!({
        "schemaVersion": "hol-guard-release-manifest.v1",
        "version": "2.1.0",
        "buildId": "build-1",
        "sourceCommit": "a".repeat(40),
        "platform": "macos",
        "architecture": "arm64",
        "policySchemaVersion": "hol-guard-mdm-policy.v1",
        "installerIdentity": "org.hol.guard",
        "files": [{"path": "bin/hol-guard", "sha256": hex::encode(Sha256::digest(RUNTIME_BYTES))}],
    })
}

fn key_pair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn write_signed(path: &Path, payload: &Value, key: &Ed25519KeyPair) {
    let signature = key.sign(python_compact_json(payload).as_bytes());
    let mut signed = payload.clone();
    signed["signature"] = json!({
        "keyId": "release-1",
        "value": base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
    });
    std::fs::write(path, serde_json::to_vec(&signed).unwrap()).unwrap();
}

fn write_unsigned(path: &Path, payload: &Value) {
    std::fs::write(path, serde_json::to_vec(payload).unwrap()).unwrap();
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    runtime: PathBuf,
    manifest_path: PathBuf,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let runtime = root.join("runtime");
    let manifest_path = runtime.join("release-manifest.json");
    Fixture {
        _dir: dir,
        root,
        runtime,
        manifest_path,
    }
}

fn unsigned_ok() -> Expectations {
    Expectations::default()
}

fn verify(fixture: &Fixture, expected: &Expectations) -> Verification {
    verify_release_manifest(&fixture.manifest_path, &fixture.runtime, expected, &LIMITS)
}

fn trusting(key: &Ed25519KeyPair) -> Expectations {
    Expectations {
        trusted_keys: [("release-1".to_owned(), key.public_key().as_ref().to_vec())].into(),
        require_signature: true,
        ..Expectations::default()
    }
}

#[test]
fn a_signed_manifest_covering_its_runtime_is_healthy() {
    let fixture = setup();
    let payload = manifest(&fixture.runtime);
    let key = key_pair(1);
    write_signed(&fixture.manifest_path, &payload, &key);

    let result = verify(&fixture, &trusting(&key));

    assert_eq!(result.status, "healthy");
    assert_eq!(result.reason_code, "release_manifest_valid");
    assert_eq!(result.signature_state, "valid");
    assert_eq!(result.version.as_deref(), Some("2.1.0"));
    assert_eq!(result.build_id.as_deref(), Some("build-1"));
    assert_eq!(result.installer_identity.as_deref(), Some("org.hol.guard"));
}

#[test]
fn a_signature_over_other_content_is_invalid() {
    let fixture = setup();
    let key = key_pair(1);
    write_signed(&fixture.manifest_path, &manifest(&fixture.runtime), &key);
    let mut signed: Value =
        serde_json::from_slice(&std::fs::read(&fixture.manifest_path).unwrap()).unwrap();
    signed["buildId"] = json!("build-2");
    write_unsigned(&fixture.manifest_path, &signed);

    let result = verify(&fixture, &trusting(&key));

    assert_eq!(result.reason_code, "release_manifest_invalid");
    assert_eq!(result.version, None);
}

#[test]
fn signing_trust_is_named_by_its_reason() {
    let fixture = setup();
    let payload = manifest(&fixture.runtime);
    write_unsigned(&fixture.manifest_path, &payload);
    let required = Expectations {
        require_signature: true,
        ..Expectations::default()
    };
    let unsigned = verify(&fixture, &required);
    assert_eq!(
        (
            unsigned.status,
            unsigned.reason_code,
            unsigned.signature_state
        ),
        ("tampered", "release_manifest_unsigned", "unsigned")
    );

    write_signed(&fixture.manifest_path, &payload, &key_pair(1));
    let no_anchor = verify(&fixture, &required);
    assert_eq!(
        no_anchor.reason_code,
        "release_manifest_trust_anchor_absent"
    );
    assert_eq!(no_anchor.signature_state, "unverified");

    let other_key = verify(&fixture, &trusting(&key_pair(2)));
    assert_eq!(other_key.reason_code, "release_manifest_invalid");

    let mut unknown_id = trusting(&key_pair(1));
    let key = unknown_id.trusted_keys.remove("release-1").unwrap();
    unknown_id.trusted_keys.insert("release-2".to_owned(), key);
    assert_eq!(
        verify(&fixture, &unknown_id).reason_code,
        "release_manifest_untrusted_key"
    );
}

#[test]
fn a_changed_runtime_file_is_a_hash_mismatch() {
    let fixture = setup();
    let payload = manifest(&fixture.runtime);
    write_unsigned(&fixture.manifest_path, &payload);
    std::fs::write(fixture.runtime.join("bin/hol-guard"), b"tampered").unwrap();

    let result = verify(&fixture, &unsigned_ok());

    assert_eq!(result.reason_code, "release_manifest_hash_mismatch");
    assert_eq!(result.signature_state, "unsigned");
}

#[test]
fn a_listed_path_must_stay_inside_the_runtime() {
    for path in ["../outside", "/etc/passwd", "bin\\hol-guard", ""] {
        let fixture = setup();
        let mut payload = manifest(&fixture.runtime);
        payload["files"] = json!([{"path": path, "sha256": "0".repeat(64)}]);
        write_unsigned(&fixture.manifest_path, &payload);

        assert_eq!(
            verify(&fixture, &unsigned_ok()).reason_code,
            "release_manifest_invalid",
            "{path}"
        );
    }
}

#[cfg(unix)]
#[test]
fn links_inside_the_runtime_are_escapes() {
    let fixture = setup();
    let outside = fixture.root.join("outside");
    std::fs::write(&outside, b"outside").unwrap();
    std::fs::create_dir_all(&fixture.runtime).unwrap();
    std::os::unix::fs::symlink(&outside, fixture.runtime.join("link")).unwrap();
    let mut payload = manifest(&fixture.runtime);
    payload["files"] = json!([{"path": "link", "sha256": hex::encode(Sha256::digest(b"outside"))}]);
    write_unsigned(&fixture.manifest_path, &payload);
    assert_eq!(
        verify(&fixture, &unsigned_ok()).reason_code,
        "release_manifest_path_escape"
    );

    // An unlisted link is found by the coverage walk.
    let fixture = setup();
    let payload = manifest(&fixture.runtime);
    let outside = fixture.root.join("outside");
    std::fs::write(&outside, b"outside").unwrap();
    std::os::unix::fs::symlink(&outside, fixture.runtime.join("unlisted")).unwrap();
    write_unsigned(&fixture.manifest_path, &payload);
    assert_eq!(
        verify(&fixture, &unsigned_ok()).reason_code,
        "release_manifest_path_escape"
    );
}

#[cfg(unix)]
#[test]
fn a_dangling_manifest_link_is_tamper_not_absence() {
    let fixture = setup();
    std::fs::create_dir_all(&fixture.runtime).unwrap();
    std::os::unix::fs::symlink(fixture.root.join("missing"), &fixture.manifest_path).unwrap();

    let result = verify(&fixture, &unsigned_ok());

    assert_eq!(
        (result.status, result.reason_code),
        ("tampered", "release_manifest_path_escape")
    );
}

#[test]
fn a_missing_manifest_is_absent() {
    let fixture = setup();
    let result = verify(&fixture, &unsigned_ok());
    assert_eq!(
        (result.status, result.reason_code),
        ("absent", "release_manifest_absent")
    );
}

#[test]
fn the_platform_and_architecture_must_match() {
    let fixture = setup();
    write_unsigned(&fixture.manifest_path, &manifest(&fixture.runtime));

    let platform = verify(
        &fixture,
        &Expectations {
            platform: Some("windows".to_owned()),
            ..Expectations::default()
        },
    );
    let architecture = verify(
        &fixture,
        &Expectations {
            architecture: Some("x86_64".to_owned()),
            ..Expectations::default()
        },
    );
    let same_architecture = verify(
        &fixture,
        &Expectations {
            architecture: Some("ARM64".to_owned()),
            ..Expectations::default()
        },
    );

    assert_eq!(
        (platform.status, platform.reason_code),
        ("unsupported", "release_manifest_platform_mismatch")
    );
    assert_eq!(
        architecture.reason_code,
        "release_manifest_architecture_mismatch"
    );
    assert_eq!(same_architecture.reason_code, "release_manifest_valid");
}

#[cfg(unix)]
#[test]
fn a_group_writable_runtime_file_is_insecure() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = setup();
    let payload = manifest(&fixture.runtime);
    write_unsigned(&fixture.manifest_path, &payload);
    let executable = fixture.runtime.join("bin/hol-guard");
    std::fs::set_permissions(
        &fixture.manifest_path,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o664)).unwrap();
    let uid = std::fs::metadata(&executable).unwrap().uid();
    let owned_by = |uid| Expectations {
        owner_uid: Some(uid),
        ..Expectations::default()
    };

    assert_eq!(
        verify(&fixture, &owned_by(uid)).reason_code,
        "release_runtime_insecure_permissions"
    );
    assert_eq!(
        verify(&fixture, &owned_by(uid.wrapping_add(1))).reason_code,
        "release_manifest_wrong_owner"
    );
    std::fs::set_permissions(
        &fixture.manifest_path,
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert_eq!(
        verify(&fixture, &owned_by(uid)).reason_code,
        "release_manifest_insecure_permissions"
    );
}

#[test]
fn every_runtime_file_must_be_listed_and_present() {
    let fixture = setup();
    let payload = manifest(&fixture.runtime);
    write_unsigned(&fixture.manifest_path, &payload);
    std::fs::write(fixture.runtime.join("extra"), b"extra").unwrap();
    assert_eq!(
        verify(&fixture, &unsigned_ok()).reason_code,
        "release_manifest_coverage_gap"
    );

    let fixture = setup();
    let mut payload = manifest(&fixture.runtime);
    payload["files"]
        .as_array_mut()
        .unwrap()
        .push(json!({"path": "bin/missing", "sha256": "0".repeat(64)}));
    write_unsigned(&fixture.manifest_path, &payload);
    assert_eq!(
        verify(&fixture, &unsigned_ok()).reason_code,
        "release_manifest_file_missing"
    );

    let fixture = setup();
    let mut payload = manifest(&fixture.runtime);
    let entry = payload["files"][0].clone();
    payload["files"].as_array_mut().unwrap().push(entry);
    write_unsigned(&fixture.manifest_path, &payload);
    assert_eq!(
        verify(&fixture, &unsigned_ok()).reason_code,
        "release_manifest_duplicate_path"
    );
}

#[test]
fn the_release_is_bound_to_the_installer_and_native_version() {
    let fixture = setup();
    write_unsigned(&fixture.manifest_path, &manifest(&fixture.runtime));
    let check = |expected: Expectations| verify(&fixture, &expected).reason_code;

    assert_eq!(
        check(Expectations {
            installer_identity: Some("HOLGuardMachine".to_owned()),
            ..Expectations::default()
        }),
        "release_manifest_installer_identity_mismatch"
    );
    assert_eq!(
        check(Expectations {
            native_version: Some("2.1.1".to_owned()),
            ..Expectations::default()
        }),
        "release_manifest_native_version_mismatch"
    );
    // PEP 440 equality, not spelling.
    assert_eq!(
        check(Expectations {
            native_version: Some("2.1.0.0".to_owned()),
            ..Expectations::default()
        }),
        "release_manifest_valid"
    );
    assert_eq!(
        check(Expectations {
            minimum_version: Some("2.2.0".to_owned()),
            ..Expectations::default()
        }),
        "release_manifest_version_rollback"
    );
    assert_eq!(
        check(Expectations {
            minimum_version: Some("not a version".to_owned()),
            ..Expectations::default()
        }),
        "release_manifest_invalid"
    );
}

#[test]
fn a_version_outside_pep_440_has_its_own_reason() {
    let fixture = setup();
    let mut payload = manifest(&fixture.runtime);
    payload["version"] = json!("latest");
    write_unsigned(&fixture.manifest_path, &payload);

    let result = verify(&fixture, &unsigned_ok());

    assert_eq!(result.reason_code, "release_manifest_version_invalid");
    assert_eq!(result.version.as_deref(), Some("latest"));
}

#[test]
fn a_malformed_manifest_is_invalid() {
    let mutations: [fn(&mut Value); 5] = [
        |payload| payload["schemaVersion"] = json!("other"),
        |payload| payload["sourceCommit"] = json!(""),
        |payload| payload["files"] = json!([]),
        |payload| payload["files"][0]["sha256"] = json!("00"),
        |payload| payload["signature"] = json!("text"),
    ];
    for mutate in mutations {
        let fixture = setup();
        let mut payload = manifest(&fixture.runtime);
        mutate(&mut payload);
        write_unsigned(&fixture.manifest_path, &payload);
        assert_eq!(
            verify(&fixture, &unsigned_ok()).reason_code,
            "release_manifest_invalid"
        );
    }
}
