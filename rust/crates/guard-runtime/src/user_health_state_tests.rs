use std::fs;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{run_command, P256_SPKI_PREFIX, PEM_BEGIN, PEM_END, STATE_NAME};

fn guard_home() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap().join("guard");
    fs::create_dir(&home).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    (directory, home)
}

/// The owner of the nearest directory that exists: the account running the
/// tests.
#[cfg(unix)]
fn owner(home: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;

    home.ancestors()
        .find_map(|ancestor| fs::metadata(ancestor).ok())
        .unwrap()
        .uid()
}

#[cfg(not(unix))]
fn owner(_home: &Path) -> u32 {
    0
}

/// A state as `_new_state` creates it, around a fresh throwaway key.
fn state() -> Value {
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
            .unwrap();
    let body = Base64::encode_string(document.as_ref());
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    let pem = format!("{PEM_BEGIN}\n{}\n{PEM_END}\n", lines.join("\n"));
    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(pair.public_key().as_ref());
    json!({
        "schemaVersion": "hol-guard-user-health-state.v1",
        "enabled": true,
        "workspaceId": "workspace-1",
        "deviceId": "device-1",
        "machineInstallationId": "0123456789abcdef0123456789abcdef",
        "installationGeneration": "fedcba9876543210fedcba9876543210",
        "sequence": 0,
        "lastLeaseDigest": null,
        "keyId": Base64UrlUnpadded::encode_string(&Sha256::digest(&spki)),
        "publicKeySpki": Base64::encode_string(&spki),
        "privateKeyPem": pem,
        "pendingOutbox": null,
        "updatedAt": "2026-10-31T22:47:00.123456+00:00",
    })
}

fn request(home: &Path, op: &str) -> Value {
    json!({
        "schema": "user-health-state.v1",
        "op": op,
        "guard_home": home,
        "owner_uid": owner(home),
    })
}

fn run(request: &Value) -> Result<Value, String> {
    run_command(serde_json::to_vec(request).unwrap().as_slice())
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn read(home: &Path) -> Value {
    run(&request(home, "read")).unwrap()
}

fn write(home: &Path, state: &Value) -> Value {
    let mut request = request(home, "write");
    request["state"] = state.clone();
    run(&request).unwrap()
}

fn refused(class: &str, reason_code: &str) -> Value {
    json!({"ok": false, "error_class": class, "reason_code": reason_code})
}

fn names(home: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(home)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_missing_home_or_state_reads_as_absent() {
    let (_directory, home) = guard_home();

    assert_eq!(read(&home), json!({"ok": true, "state": null}));
    assert_eq!(
        read(&home.join("missing")),
        json!({"ok": true, "state": null})
    );
}

#[test]
fn a_written_state_reads_back_unchanged_and_leaves_no_temporary_file() {
    let (_directory, home) = guard_home();
    let state = state();

    assert_eq!(write(&home, &state), json!({"ok": true}));

    assert_eq!(read(&home), json!({"ok": true, "state": state}));
    assert_eq!(names(&home), vec![STATE_NAME.to_owned()]);
}

#[test]
fn a_state_is_stored_as_canonical_json() {
    let (_directory, home) = guard_home();
    let state = state();
    write(&home, &state);

    let stored = fs::read_to_string(home.join(STATE_NAME)).unwrap();

    assert!(stored.starts_with("{\"deviceId\":\"device-1\",\"enabled\":true,"));
    assert!(!stored.contains(": "));
    assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), state);
}

#[test]
fn a_leased_state_needs_its_digest_and_a_fresh_one_needs_none() {
    let (_directory, home) = guard_home();
    let mut leased = state();
    leased["sequence"] = json!(u64::MAX);
    leased["lastLeaseDigest"] = json!("ab".repeat(32));
    let mut missing_digest = leased.clone();
    missing_digest["lastLeaseDigest"] = Value::Null;
    let mut stray_digest = state();
    stray_digest["lastLeaseDigest"] = json!("ab".repeat(32));

    assert_eq!(write(&home, &leased), json!({"ok": true}));
    for invalid in [missing_digest, stray_digest] {
        assert_eq!(
            write(&home, &invalid),
            refused("value", "user_health_state_invalid")
        );
    }
    assert_eq!(read(&home), json!({"ok": true, "state": leased}));
}

#[test]
fn a_malformed_state_is_never_written() {
    let (_directory, home) = guard_home();
    let other_key = state();
    let mutations: [(&str, Value); 14] = [
        ("schemaVersion", json!("hol-guard-user-health-state.v0")),
        ("enabled", json!(1)),
        ("workspaceId", json!("")),
        ("deviceId", json!(7)),
        (
            "machineInstallationId",
            json!("0123456789ABCDEF0123456789ABCDEF"),
        ),
        ("installationGeneration", json!("0123")),
        ("sequence", json!(-1)),
        ("sequence", json!(1.5)),
        ("keyId", json!("A".repeat(43))),
        ("publicKeySpki", other_key["publicKeySpki"].clone()),
        ("privateKeyPem", other_key["privateKeyPem"].clone()),
        ("pendingOutbox", json!("x".repeat(400_001))),
        ("updatedAt", json!("2026-10-31T22:47:00")),
        ("updatedAt", json!(null)),
    ];
    for (field, value) in mutations {
        let mut invalid = state();
        invalid[field] = value;
        assert_eq!(
            write(&home, &invalid),
            refused("value", "user_health_state_invalid"),
            "{field}"
        );
    }
    let mut extra = state();
    extra["note"] = json!("x");
    let mut missing = state();
    missing.as_object_mut().unwrap().remove("pendingOutbox");
    for invalid in [extra, missing, json!([])] {
        assert_eq!(
            write(&home, &invalid),
            refused("value", "user_health_state_invalid")
        );
    }
    assert!(names(&home).is_empty());
}

#[test]
fn a_stored_state_that_fails_validation_is_refused() {
    let (_directory, home) = guard_home();
    write(&home, &state());
    let path = home.join(STATE_NAME);
    let mut stored: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    stored["keyId"] = json!("A".repeat(43));
    fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();

    assert_eq!(read(&home), refused("value", "user_health_state_invalid"));
    fs::write(&path, b"{not json").unwrap();
    assert_eq!(read(&home), refused("value", "user_health_state_invalid"));
}

#[test]
fn a_write_needs_an_existing_guard_home() {
    let (_directory, home) = guard_home();

    assert_eq!(
        write(&home.join("missing"), &state()),
        refused("os", "user_health_state_io_failed")
    );
}

#[test]
fn a_request_outside_the_two_operations_is_refused() {
    let (_directory, home) = guard_home();
    let mut wrong_schema = request(&home, "read");
    wrong_schema["schema"] = json!("user-health-state.v0");
    let mut extra = request(&home, "read");
    extra["path"] = json!("/etc/passwd");
    let mut read_with_state = request(&home, "read");
    read_with_state["state"] = state();

    for rejected in [
        request(&home, "write"),
        request(&home, "remove"),
        read_with_state,
        wrong_schema,
        extra,
    ] {
        assert_eq!(
            run(&rejected),
            Err("user_health_state_request_invalid".to_owned()),
            "{rejected}"
        );
    }
    assert!(names(&home).is_empty());
}

#[cfg(unix)]
#[test]
fn a_written_state_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    let (_directory, home) = guard_home();
    write(&home, &state());

    let mode = fs::metadata(home.join(STATE_NAME))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn a_state_others_may_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let (_directory, home) = guard_home();
    write(&home, &state());
    fs::set_permissions(home.join(STATE_NAME), fs::Permissions::from_mode(0o640)).unwrap();

    assert_eq!(
        read(&home),
        refused("permission", "user_health_state_acl_invalid")
    );
}

#[cfg(unix)]
#[test]
fn a_guard_home_others_may_read_is_refused_for_both_operations() {
    use std::os::unix::fs::PermissionsExt;

    let (_directory, home) = guard_home();
    write(&home, &state());
    fs::set_permissions(&home, fs::Permissions::from_mode(0o750)).unwrap();

    let acl_invalid = refused("permission", "user_health_state_acl_invalid");
    assert_eq!(read(&home), acl_invalid);
    assert_eq!(write(&home, &state()), acl_invalid);
}

#[cfg(unix)]
#[test]
fn a_state_of_another_owner_is_refused() {
    let (_directory, home) = guard_home();
    write(&home, &state());
    let mut foreign = request(&home, "read");
    foreign["owner_uid"] = json!(owner(&home).wrapping_add(1));

    assert_eq!(
        run(&foreign).unwrap(),
        refused("permission", "user_health_state_acl_invalid")
    );
}

#[cfg(unix)]
#[test]
fn a_linked_state_or_guard_home_is_refused() {
    let (directory, home) = guard_home();
    let elsewhere = directory.path().join("elsewhere.json");
    fs::write(&elsewhere, serde_json::to_vec(&state()).unwrap()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, home.join(STATE_NAME)).unwrap();
    let linked_home = directory.path().join("linked");
    std::os::unix::fs::symlink(&home, &linked_home).unwrap();

    let acl_invalid = refused("permission", "user_health_state_acl_invalid");
    assert_eq!(read(&home), acl_invalid);
    assert_eq!(read(&linked_home), acl_invalid);
    assert_eq!(write(&linked_home, &state()), acl_invalid);
}

#[cfg(not(unix))]
#[test]
fn a_state_reads_back_without_owner_bits() {
    let (_directory, home) = guard_home();
    let state = state();
    write(&home, &state);
    let mut any_owner = request(&home, "read");
    any_owner["owner_uid"] = json!(4242);

    assert_eq!(
        run(&any_owner).unwrap(),
        json!({"ok": true, "state": state})
    );
}
