use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use super::writable_only_by_owner;

fn file(directory: &Path, name: &str, mode: u32) -> std::path::PathBuf {
    let path = directory.join(name);
    fs::write(&path, b"x").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn judged(path: &Path, checker: Option<&Path>) -> bool {
    let metadata = fs::symlink_metadata(path).unwrap();
    writable_only_by_owner(&metadata, metadata.uid(), path, checker)
}

#[test]
fn world_write_is_never_trusted_and_an_owner_only_file_always_is() {
    let directory = tempfile::tempdir().unwrap();
    assert!(judged(&file(directory.path(), "owner", 0o600), None));
    assert!(judged(&file(directory.path(), "read", 0o644), None));
    assert!(!judged(&file(directory.path(), "world", 0o602), None));
    assert!(!judged(&file(directory.path(), "both", 0o666), None));
}

#[test]
fn group_write_needs_a_checker_the_same_group_can_already_write() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o775)).unwrap();
    let target = file(directory.path(), "manifest", 0o664);
    assert!(!judged(&target, None), "no checker, no trust");
    let writable = file(directory.path(), "checker", 0o664);
    assert!(judged(&target, Some(&writable)));
    let sealed = file(directory.path(), "sealed", 0o644);
    assert!(
        !judged(&target, Some(&sealed)),
        "a checker the group cannot write proves nothing"
    );
    assert!(!judged(&target, Some(&directory.path().join("missing"))));
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        !judged(&target, Some(&writable)),
        "nor does a checker in a folder the group cannot write"
    );
}
