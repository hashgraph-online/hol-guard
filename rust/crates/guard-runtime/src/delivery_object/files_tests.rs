use super::*;
use std::fs;

#[test]
fn reads_a_regular_file_within_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("object.json");
    fs::write(&path, b"{}").unwrap();
    assert!(matches!(read(&path, 2), Ok(bytes) if bytes == b"{}"));
    assert!(read(&path, 1).is_err());
}

#[test]
fn refuses_a_missing_path_and_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read(&dir.path().join("absent"), 10).is_err());
    assert!(read(dir.path(), 10).is_err());
}

#[cfg(unix)]
#[test]
fn refuses_a_symlink_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.json");
    fs::write(&target, b"{}").unwrap();
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(read(&link, 10).is_err());
}

#[cfg(unix)]
#[test]
fn accepts_a_hard_linked_data_file() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original.json");
    fs::write(&original, b"{}").unwrap();
    let linked = dir.path().join("linked.json");
    fs::hard_link(&original, &linked).unwrap();
    assert!(matches!(read(&linked, 10), Ok(bytes) if bytes == b"{}"));
}
