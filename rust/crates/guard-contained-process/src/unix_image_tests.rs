use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;

#[test]
fn trusted_image_root_rejects_overlap_and_restores_only_the_owner_mode() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let executable = root.join("shell");
    fs::copy("/bin/sh", &executable).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();

    let adopt =
        || crate::PinnedCommand::new_with_image_root(&executable, &[], &root, &[], Some(&root));
    let first = adopt().unwrap();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
        0o500
    );
    let error = adopt().err().expect("reject an overlapping mode owner");
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
        0o500
    );
    drop(first);
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
        0o750
    );

    // Ownership must disappear with the image, not permanently reserve a root.
    let next = adopt().unwrap();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
        0o500
    );
    drop(next);
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
        0o750
    );
}
