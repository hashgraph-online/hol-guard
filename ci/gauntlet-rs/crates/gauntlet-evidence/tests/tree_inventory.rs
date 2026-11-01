//! Inert custody behavior; installed-root positive cases require the Linux VM.

use gauntlet_evidence::{inventory_tree, TreeKind};
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn empty_sdk_has_python_empty_array_digest() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let inventory = inventory_tree(&root, TreeKind::Sdk).unwrap();
    assert_eq!(
        inventory.digest,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    );
    assert_eq!(inventory.entries, 0);
    assert_eq!(inventory.bytes, 0);
}

#[test]
fn sdk_inventory_tracks_inert_bytes_and_refuses_escape_and_writeable_entries() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("package")).unwrap();
    std::fs::write(root.join("package/data.json"), b"original").unwrap();
    symlink("package/data.json", root.join("alias")).unwrap();
    let original = inventory_tree(&root, TreeKind::Sdk).unwrap();
    assert_eq!(original.entries, 3);
    assert_eq!(original.bytes, 8);

    std::fs::write(root.join("package/data.json"), b"changed").unwrap();
    let changed = inventory_tree(&root, TreeKind::Sdk).unwrap();
    assert_ne!(original.digest, changed.digest);

    let writable = root.join("package/data.json");
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(inventory_tree(&root, TreeKind::Sdk).is_err());
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o644)).unwrap();

    symlink("/etc", root.join("escape")).unwrap();
    assert!(inventory_tree(&root, TreeKind::Sdk).is_err());
}

#[test]
fn installed_prefix_refuses_unowned_root() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    if rustix::process::getuid().as_raw() != 0 {
        assert!(inventory_tree(&root, TreeKind::InstalledPrefix).is_err());
    }
}
