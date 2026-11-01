//! Pinned Python version syntax and inert installed-metadata reads.

use gauntlet_evidence::{valid_package_version, verify_installed_version_metadata};
use serde_json::{json, Value};
use std::path::Path;

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NATIVE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const RELATIVE: &str =
    "lib/python3.12/site-packages/codex_plugin_scanner/_native/runtime-manifest.json";

#[test]
fn python_package_version_vectors_match() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python_package_versions.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        fixture["source_sha"],
        "b4efd8171b06d0e13cbe12a077c376ecdc891fd1"
    );
    for case in fixture["cases"].as_array().unwrap() {
        assert_eq!(
            valid_package_version(case["value"].as_str().unwrap()),
            case["accepted"].as_bool().unwrap(),
            "{}",
            case["value"]
        );
    }
}

#[test]
fn changed_or_symlinked_installed_manifest_cannot_match_pins() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let path = root.join(RELATIVE);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let manifest =
        json!({"package_version":"3.50.0a1","source_sha":SOURCE,"runtime_sha256":NATIVE});
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert_eq!(
        verify_installed_version_metadata(&root, "3.50.0a1", SOURCE, NATIVE).unwrap(),
        "3.50.0a1"
    );
    assert!(verify_installed_version_metadata(&root, "3.50.0", SOURCE, NATIVE).is_err());
    std::fs::write(&path, b"{\"package_version\":\"3.50.0a1\"}").unwrap();
    assert!(verify_installed_version_metadata(&root, "3.50.0a1", SOURCE, NATIVE).is_err());
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("/etc/hosts", &path).unwrap();
    assert!(verify_installed_version_metadata(&root, "3.50.0a1", SOURCE, NATIVE).is_err());
}
