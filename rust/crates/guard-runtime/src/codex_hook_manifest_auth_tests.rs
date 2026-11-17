use std::fs;
use std::path::{Path, PathBuf};

use guard_policy_snapshot::local_authority_integrity::sign_local_authority_payload;
use serde_json::{json, Value};

use super::{authenticate_text, load_path, unsigned, MAX_MANIFEST_BYTES, PURPOSE};
use crate::codex_hook_key::{answer, read_matching};

const GENERATED_AT: &str = "2026-07-17T12:00:00+00:00";

fn home() -> tempfile::TempDir {
    tempfile::tempdir().expect("home")
}

fn text(home: &tempfile::TempDir) -> &str {
    home.path().to_str().expect("utf-8 home")
}

/// The home's key identity, creating the key on first use.
fn ensured(home: &tempfile::TempDir) -> (String, String) {
    let identity = answer("key_ensure", text(home)).expect("known op");
    let field = |name: &str| identity[name].as_str().expect("identity field").to_owned();
    (field("key_id"), field("installation_id"))
}

/// A manifest for `installation_id` signed under the home's key at `signed_at`.
fn signed(home: &tempfile::TempDir, installation_id: &str, signed_at: &str) -> Value {
    let key = read_matching(text(home), None, None).expect("key");
    let mut manifest = json!({
        "generated_at": GENERATED_AT,
        "installation_id": installation_id,
        "schema_version": 2,
    });
    let fields = sign_local_authority_payload(
        &manifest,
        key.key.as_slice(),
        &key.key_id,
        PURPOSE,
        signed_at,
    )
    .expect("signed");
    manifest["authentication"] = json!({
        "algorithm": "hmac-sha256",
        "integrity_version": fields.integrity_version,
        "payload_hash": fields.payload_hash,
        "payload_mac": fields.payload_mac,
        "integrity_key_id": fields.integrity_key_id,
        "signed_at": fields.signed_at,
    });
    manifest
}

fn manifest_path(home: &tempfile::TempDir, name: &str) -> PathBuf {
    let directory = home.path().join("managed").join("codex");
    fs::create_dir_all(&directory).expect("directory");
    directory.join(name)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn private_file(home: &tempfile::TempDir, name: &str, body: &[u8]) -> PathBuf {
    let path = manifest_path(home, name);
    fs::write(&path, body).expect("write");
    set_mode(&path, 0o600);
    path
}

#[test]
fn an_oversized_manifest_is_refused_before_it_is_parsed() {
    let home = home();
    let oversized = " ".repeat(MAX_MANIFEST_BYTES as usize + 1);
    let path = private_file(&home, "oversized.manifest.json", oversized.as_bytes());
    assert_eq!(
        load_path(text(&home), &path).unwrap_err(),
        "codex_hook_manifest_invalid"
    );
    assert_eq!(
        authenticate_text(text(&home), &oversized, None, None).unwrap_err(),
        "codex_hook_manifest_invalid"
    );
}

#[test]
fn a_missing_manifest_or_one_that_is_not_a_regular_file_is_refused() {
    let home = home();
    let missing = manifest_path(&home, "missing.manifest.json");
    assert_eq!(
        load_path(text(&home), &missing).unwrap_err(),
        "codex_hook_manifest_missing"
    );
    let directory = manifest_path(&home, "directory.manifest.json");
    fs::create_dir(&directory).expect("directory");
    assert_eq!(
        load_path(text(&home), &directory).unwrap_err(),
        "codex_hook_manifest_not_regular"
    );
}

#[cfg(unix)]
#[test]
fn a_linked_manifest_is_not_a_regular_file() {
    let home = home();
    let target = private_file(&home, "target.manifest.json", b"{}");
    let link = manifest_path(&home, "link.manifest.json");
    std::os::unix::fs::symlink(&target, &link).expect("link");
    assert_eq!(
        load_path(text(&home), &link).unwrap_err(),
        "codex_hook_manifest_not_regular"
    );
}

#[cfg(unix)]
#[test]
fn a_manifest_others_can_read_is_refused() {
    let home = home();
    let path = private_file(&home, "open.manifest.json", b"{}");
    set_mode(&path, 0o644);
    assert_eq!(
        load_path(text(&home), &path).unwrap_err(),
        "codex_hook_manifest_permissions_unsafe"
    );
}

#[test]
fn a_manifest_that_is_not_an_authenticated_object_is_refused_with_its_reason() {
    let home = home();
    let refused = |raw: &str| authenticate_text(text(&home), raw, None, None).unwrap_err();
    assert_eq!(refused("not json"), "codex_hook_manifest_invalid");
    assert_eq!(refused("[]"), "codex_hook_manifest_invalid");
    assert_eq!(refused("{}"), "codex_hook_manifest_authentication_missing");
    assert_eq!(
        refused(r#"{"authentication": "mac"}"#),
        "codex_hook_manifest_authentication_missing"
    );
    assert_eq!(
        refused(r#"{"authentication": {"algorithm": "none"}}"#),
        "codex_hook_manifest_authentication_invalid"
    );
}

#[test]
fn a_manifest_signed_under_the_home_key_opens_with_its_authentication() {
    let home = home();
    let (_, installation_id) = ensured(&home);
    let manifest = signed(&home, &installation_id, GENERATED_AT);
    let raw = manifest.to_string();
    let opened = authenticate_text(text(&home), &raw, None, None).expect("authentic");
    assert_eq!(Value::Object(opened.clone()), manifest);
    let path = private_file(&home, "hooks-live.manifest.json", raw.as_bytes());
    assert_eq!(load_path(text(&home), &path).expect("loaded"), opened);
    let bare = unsigned(opened);
    assert!(!bare.contains_key("authentication"));
    assert_eq!(bare["schema_version"], 2);
}

#[test]
fn a_changed_manifest_fails_its_authentication() {
    let home = home();
    let (_, installation_id) = ensured(&home);
    let mut manifest = signed(&home, &installation_id, GENERATED_AT);
    manifest["schema_version"] = json!(3);
    assert_eq!(
        authenticate_text(text(&home), &manifest.to_string(), None, None).unwrap_err(),
        "codex_hook_manifest_mac_invalid"
    );
}

#[test]
fn a_manifest_for_another_installation_is_refused() {
    let home = home();
    ensured(&home);
    let manifest = signed(&home, "another-installation", GENERATED_AT);
    assert_eq!(
        authenticate_text(text(&home), &manifest.to_string(), None, None).unwrap_err(),
        "codex_hook_manifest_installation_mismatch"
    );
}

#[test]
fn a_signature_made_at_another_time_than_the_manifest_is_refused() {
    let home = home();
    let (_, installation_id) = ensured(&home);
    let manifest = signed(&home, &installation_id, "2026-07-18T12:00:00+00:00");
    assert_eq!(
        authenticate_text(text(&home), &manifest.to_string(), None, None).unwrap_err(),
        "codex_hook_manifest_authentication_invalid"
    );
}

#[test]
fn a_named_key_must_be_the_one_the_home_holds() {
    let home = home();
    let (key_id, installation_id) = ensured(&home);
    let raw = signed(&home, &installation_id, GENERATED_AT).to_string();
    assert!(authenticate_text(text(&home), &raw, Some(&key_id), Some(&installation_id)).is_ok());
    assert_eq!(
        authenticate_text(text(&home), &raw, Some("other-key"), None).unwrap_err(),
        "codex_hook_manifest_key_mismatch"
    );
    assert_eq!(
        authenticate_text(text(&home), &raw, None, Some("other-installation")).unwrap_err(),
        "codex_hook_manifest_key_mismatch"
    );
}

#[test]
fn a_home_without_a_usable_key_authenticates_nothing() {
    let home = home();
    let raw = r#"{"authentication": {"algorithm": "hmac-sha256"}}"#;
    assert_eq!(
        authenticate_text(text(&home), raw, None, None).unwrap_err(),
        "codex_hook_manifest_secret_missing"
    );
    assert_eq!(
        authenticate_text("relative/home", raw, None, None).unwrap_err(),
        "codex_hook_manifest_secret_invalid"
    );
}
