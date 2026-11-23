//! The relay's binding of a claimed package call to its verified archives.

use guard_command::restricted_archive::RestrictedArchiveDownload;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{apply, bind, Binding, Retained};

const URL: &str = "https://example.com/pkg-1.0.0.tgz";
const BYTES: &[u8] = b"archive bytes";

fn evaluation(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("an object")
}

fn requiring() -> Map<String, Value> {
    evaluation(json!({
        "reasons": [{"code": "external_tarball_source", "message": "from a tarball"}],
    }))
}

fn params() -> Value {
    json!({"name": "install", "arguments": {"packages": [URL]}})
}

fn download(path: &std::path::Path, bytes: &[u8]) -> RestrictedArchiveDownload {
    RestrictedArchiveDownload {
        path: path.to_path_buf(),
        sha256: hex::encode(Sha256::digest(bytes)),
        size: bytes.len() as u64,
        source_url: URL.to_owned(),
        final_url: URL.to_owned(),
    }
}

#[test]
fn a_call_with_no_retained_archive_is_bound_only_when_it_needs_none() {
    let none = Retained::default();
    assert_eq!(
        bind(&params(), &evaluation(json!({})), &none),
        Binding::Unchanged
    );
    assert_eq!(bind(&params(), &requiring(), &none), Binding::Unbound);
    assert_eq!(Binding::Unchanged.bound(), None);
    assert_eq!(Binding::Unbound.bound(), Some(false));
}

#[test]
fn a_blob_that_is_gone_refuses_the_binding() {
    let root = tempfile::tempdir().unwrap();
    let missing = Retained::new(vec![download(&root.path().join("gone.tgz"), BYTES)]);
    assert_eq!(bind(&params(), &requiring(), &missing), Binding::Unbound);
}

#[test]
fn edits_rewrite_the_named_nodes_and_refuse_a_missing_one() {
    let mut value = params();
    let edits = [json!({"path": ["arguments", "packages", 0], "value": "/blob.tgz"})];
    assert_eq!(apply(&mut value, &edits), Some(()));
    assert_eq!(value["arguments"]["packages"][0], json!("/blob.tgz"));
    let mut untouched = params();
    let missing = [json!({"path": ["arguments", "absent"], "value": "/blob.tgz"})];
    assert_eq!(apply(&mut untouched, &missing), None);
}

#[cfg(unix)]
#[test]
fn a_verified_blob_binds_the_request_and_is_removed_when_dropped() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("pkg.tgz");
    std::fs::write(&path, BYTES).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    let retained = Retained::new(vec![download(&path, BYTES)]);
    let binding = bind(&params(), &requiring(), &retained);
    let local = path.to_string_lossy().into_owned();
    assert_eq!(
        binding,
        Binding::Bound(json!({"name": "install", "arguments": {"packages": [local]}}))
    );
    assert_eq!(binding.bound(), Some(true));
    drop(retained);
    assert!(!path.exists());
}
