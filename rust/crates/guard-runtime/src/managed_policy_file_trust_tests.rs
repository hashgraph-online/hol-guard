//! Nothing this account owns is machine authority, and a write this runtime
//! makes lands on a file it created rather than on a name something else left
//! behind.

use super::*;

use std::fs;
use tempfile::TempDir;

#[test]
fn a_relative_path_is_never_machine_controlled() {
    assert!(!machine_controlled_file_is_trusted(
        Path::new("managed-policy.json"),
        MachineSystem::Other
    ));
}

#[test]
fn a_windows_path_is_not_answered_from_posix_mode_bits() {
    // The answer needs the file's ACL, which this runtime does not read, so a
    // Windows path is never reported as trusted on the strength of its mode.
    assert!(!machine_controlled_file_is_trusted(
        Path::new("/tmp"),
        MachineSystem::Windows
    ));
}

#[test]
fn a_path_this_account_owns_is_not_machine_controlled() {
    let root = TempDir::new().expect("tempdir");
    let file = root.path().join("managed-policy.json");
    fs::write(&file, b"{}").expect("write");

    assert!(!machine_controlled_file_is_trusted(
        &file,
        MachineSystem::Other
    ));
    assert!(!machine_controlled_directory_is_trusted(
        root.path(),
        MachineSystem::Other
    ));
}

#[test]
fn the_leaf_has_to_be_the_kind_the_caller_asked_for() {
    // `/` is root-owned and restricted on every machine these tests run on, so
    // it answers the directory question and not the file one.
    assert!(!machine_controlled_file_is_trusted(
        Path::new("/"),
        MachineSystem::Other
    ));
}

#[test]
fn a_replacement_puts_the_bytes_where_the_name_points() {
    let root = TempDir::new().expect("tempdir");
    let path = root.path().join("managed-policy-cache.json");
    fs::write(&path, b"stale").expect("write");

    replace_restricted_file(&path, b"fresh").expect("replace");

    assert_eq!(fs::read(&path).expect("read"), b"fresh");
    // Nothing is left beside it: the name it was written under is gone.
    let siblings: Vec<_> = fs::read_dir(root.path())
        .expect("read dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert_eq!(siblings.len(), 1, "{siblings:?}");
}

/// A link at the destination is replaced, not written through, so an account
/// that can plant one does not get the bytes delivered to its own target.
#[test]
#[cfg(unix)]
fn a_link_at_the_destination_is_replaced_rather_than_followed() {
    let root = TempDir::new().expect("tempdir");
    let target = root.path().join("elsewhere.json");
    fs::write(&target, b"untouched").expect("write");
    let path = root.path().join("managed-policy-cache.json");
    std::os::unix::fs::symlink(&target, &path).expect("symlink");

    replace_restricted_file(&path, b"fresh").expect("replace");

    assert_eq!(fs::read(&target).expect("read"), b"untouched");
    assert_eq!(fs::read(&path).expect("read"), b"fresh");
    assert!(
        !fs::symlink_metadata(&path)
            .expect("metadata")
            .file_type()
            .is_symlink(),
        "the link itself was replaced"
    );
}

#[test]
#[cfg(unix)]
fn a_restricted_file_is_written_for_its_owner_alone() {
    use std::os::unix::fs::PermissionsExt;

    let root = TempDir::new().expect("tempdir");
    let path = root.path().join("managed-policy-cache.json");

    replace_restricted_file(&path, b"fresh").expect("replace");

    let mode = fs::metadata(&path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "{mode:o}");
}

#[test]
#[cfg(unix)]
fn a_restricted_directory_is_created_for_its_owner_alone() {
    use std::os::unix::fs::PermissionsExt;

    let root = TempDir::new().expect("tempdir");
    let nested = root.path().join("state").join("hol-guard");

    create_restricted_directory(&nested).expect("create");

    let mode = fs::metadata(&nested)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "{mode:o}");
    // An existing directory is left exactly as it is.
    create_restricted_directory(&nested).expect("again");
}
