//! Linux/macOS local-filesystem requirements: renameat2(RENAME_EXCHANGE) or
//! renameatx_np(RENAME_SWAP), hard-link publication, and directory fsync. These
//! exercise the real primitive and rollback state transitions without hooks,
//! fake callbacks, threads racing a timer, or fabricated Windows capability.
//!
//! Retirement map: workspace-write execution atomic-copy/mode preservation ->
//! successful_publication_*; changed target -> replacement_before_*;
//! absent-target race -> new_publication_*; raced-user preservation ->
//! exchange_rollback_* and rollback_preserves_*.
//! Synthetic zero-write/fsync-failure Python mocks are not claimed replaced.

use super::*;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn fixture() -> (TempDir, Directory) {
    let temporary = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(temporary.path()).unwrap();
    let directory = Directory::open(&path).unwrap();
    (temporary, directory)
}

fn recovery(root: &Directory) -> Directory {
    root.mkdir_all(Path::new("recovery")).unwrap();
    root.directory(Path::new("recovery")).unwrap()
}

#[test]
fn successful_publication_creates_a_new_target_without_recovery_debris() {
    let (_temporary, root) = fixture();
    root.atomic_replace(Path::new("target"), None, b"generated\n")
        .unwrap();
    assert_eq!(
        root.read(Path::new("target"), 64).unwrap().bytes,
        b"generated\n"
    );
    assert_eq!(
        root.entries(Path::new("."), 10).unwrap(),
        vec![OsString::from("target")]
    );
}

#[test]
fn successful_publication_replaces_exact_old_target_and_preserves_mode() {
    let (_temporary, root) = fixture();
    root.create(Path::new("target"), b"old\n", false).unwrap();
    fs::set_permissions(
        root.path().join("target"),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    let original = root.read(Path::new("target"), 64).unwrap();
    root.atomic_replace(
        Path::new("target"),
        Some((&original.identity, &original.digest)),
        b"new\n",
    )
    .unwrap();
    let promoted = root.read(Path::new("target"), 64).unwrap();
    assert_eq!(promoted.bytes, b"new\n");
    assert!(!same_object(&original.identity, &promoted.identity));
    assert_eq!(
        fs::metadata(root.path().join("target"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert_eq!(
        root.entries(Path::new("."), 10).unwrap(),
        vec![OsString::from("target")]
    );
}

#[test]
fn replacement_before_promotion_preserves_same_byte_new_inode_and_changed_user_bytes() {
    for replacement in [b"old\n".as_slice(), b"user edit\n".as_slice()] {
        let (_temporary, root) = fixture();
        root.create(Path::new("target"), b"old\n", false).unwrap();
        let approved = root.read(Path::new("target"), 64).unwrap();
        fs::rename(root.path().join("target"), root.path().join("approved-old")).unwrap();
        root.create(Path::new("target"), replacement, false)
            .unwrap();
        let user = root.read(Path::new("target"), 64).unwrap();
        assert!(!same_object(&approved.identity, &user.identity));
        let error = root
            .atomic_replace(
                Path::new("target"),
                Some((&approved.identity, &approved.digest)),
                b"generated\n",
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let retained = root.read(Path::new("target"), 64).unwrap();
        assert_eq!(retained.bytes, replacement);
        assert!(same_object(&retained.identity, &user.identity));
        assert_eq!(
            root.read(Path::new("approved-old"), 64).unwrap().bytes,
            b"old\n"
        );
    }
}

#[test]
fn new_publication_does_not_overwrite_a_target_created_after_admission() {
    let (_temporary, root) = fixture();
    assert_eq!(
        root.read(Path::new("target"), 64).err().unwrap().kind(),
        io::ErrorKind::NotFound
    );
    let staging = recovery(&root);
    staging
        .create(Path::new("new"), b"generated\n", false)
        .unwrap();
    root.create(Path::new("target"), b"concurrent user\n", false)
        .unwrap();
    let user = root.read(Path::new("target"), 64).unwrap();
    assert!(publish_new(&staging, OsStr::new("new"), &root, OsStr::new("target")).is_err());
    let retained = root.read(Path::new("target"), 64).unwrap();
    assert!(same_object(&retained.identity, &user.identity));
    assert_eq!(retained.bytes, b"concurrent user\n");
    assert_eq!(
        staging.read(Path::new("new"), 64).unwrap().bytes,
        b"generated\n"
    );
    finish_recovery(&root, OsStr::new("recovery"), staging).unwrap();
    assert_eq!(
        fs::read(root.path().join("recovery/new")).unwrap(),
        b"generated\n"
    );
}

#[test]
fn exchange_rollback_restores_a_displaced_raced_user_object() {
    for replacement in [b"approved\n".as_slice(), b"concurrent user\n".as_slice()] {
        let (_temporary, root) = fixture();
        root.create(Path::new("target"), b"approved\n", false)
            .unwrap();
        let approved = root.read(Path::new("target"), 64).unwrap();
        let staging = recovery(&root);
        staging
            .create(Path::new("new"), b"generated\n", false)
            .unwrap();
        let written = staging.read(Path::new("new"), 64).unwrap();
        // Model a user replacement between the preflight read and native swap.
        // Keeping the approved inode alive makes same-byte replacement exact.
        fs::rename(root.path().join("target"), root.path().join("approved-old")).unwrap();
        root.create(Path::new("target"), replacement, false)
            .unwrap();
        let user = root.read(Path::new("target"), 64).unwrap();
        exchange(&staging, OsStr::new("new"), &root, OsStr::new("target")).unwrap();
        let displaced = staging.read(Path::new("new"), 64).unwrap();
        assert!(!matches(&displaced, (&approved.identity, &approved.digest)));
        rollback(&root, OsStr::new("target"), &staging, &written).unwrap();
        let restored = root.read(Path::new("target"), 64).unwrap();
        assert!(same_object(&restored.identity, &user.identity));
        assert_eq!(restored.bytes, replacement);
        assert_eq!(
            staging.read(Path::new("new"), 64).err().unwrap().kind(),
            io::ErrorKind::NotFound
        );
        finish_recovery(&root, OsStr::new("recovery"), staging).unwrap();
        assert_eq!(
            fs::symlink_metadata(root.path().join("recovery"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }
}

#[test]
fn rollback_preserves_a_second_user_replacement_and_the_displaced_original() {
    let (_temporary, root) = fixture();
    root.create(Path::new("target"), b"approved\n", false)
        .unwrap();
    let approved = root.read(Path::new("target"), 64).unwrap();
    let staging = recovery(&root);
    staging
        .create(Path::new("new"), b"generated\n", false)
        .unwrap();
    let written = staging.read(Path::new("new"), 64).unwrap();
    exchange(&staging, OsStr::new("new"), &root, OsStr::new("target")).unwrap();
    fs::rename(
        root.path().join("target"),
        root.path().join("generated-old"),
    )
    .unwrap();
    root.create(Path::new("target"), b"second user edit\n", false)
        .unwrap();
    let second_user = root.read(Path::new("target"), 64).unwrap();
    rollback(&root, OsStr::new("target"), &staging, &written).unwrap();
    let retained = root.read(Path::new("target"), 64).unwrap();
    assert!(same_object(&retained.identity, &second_user.identity));
    assert_eq!(retained.bytes, b"second user edit\n");
    let displaced = staging.read(Path::new("new"), 64).unwrap();
    assert!(matches(&displaced, (&approved.identity, &approved.digest)));
    finish_recovery(&root, OsStr::new("recovery"), staging).unwrap();
    assert_eq!(
        fs::read(root.path().join("recovery/new")).unwrap(),
        b"approved\n"
    );
}

#[test]
fn rollback_preserves_user_modifications_to_the_published_inode() {
    let (_temporary, root) = fixture();
    root.create(Path::new("target"), b"approved\n", false)
        .unwrap();
    let staging = recovery(&root);
    staging
        .create(Path::new("new"), b"generated\n", false)
        .unwrap();
    let written = staging.read(Path::new("new"), 64).unwrap();
    exchange(&staging, OsStr::new("new"), &root, OsStr::new("target")).unwrap();
    fs::write(root.path().join("target"), b"user edited output\n").unwrap();
    let modified = root.read(Path::new("target"), 64).unwrap();
    assert!(same_object(&modified.identity, &written.identity));
    assert_ne!(modified.digest, written.digest);
    rollback(&root, OsStr::new("target"), &staging, &written).unwrap();
    assert_eq!(
        root.read(Path::new("target"), 64).unwrap().bytes,
        b"user edited output\n"
    );
    finish_recovery(&root, OsStr::new("recovery"), staging).unwrap();
    assert_eq!(
        fs::read(root.path().join("recovery/new")).unwrap(),
        b"approved\n"
    );
}
