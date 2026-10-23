use super::{
    hash_file_after_chunk, inventory_tree, inventory_tree_with_after_scan,
    inventory_tree_with_hooks, stable_symlink_target, TreeContext, TreeKind,
};
use crate::io::open_absolute_directory;
use rustix::fs::{fstat, open, Mode, OFlags};
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn descriptor_relative_resolution_allows_inside_chain_and_refuses_escape() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("sdk");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("nested")).unwrap();
    std::fs::write(root.join("data"), b"inert").unwrap();
    std::fs::write(temporary.path().join("outside"), b"outside").unwrap();
    symlink("../data", root.join("nested/inside")).unwrap();
    symlink("nested/inside", root.join("chain")).unwrap();
    let root = root.canonicalize().unwrap();
    assert_eq!(inventory_tree(&root, TreeKind::Sdk).unwrap().entries, 4);

    symlink("../../outside", root.join("nested/escape")).unwrap();
    assert!(inventory_tree(&root, TreeKind::Sdk).is_err());
}

#[test]
fn refuses_file_changed_after_hashing_starts() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("mutable");
    std::fs::write(&path, vec![b'a'; 2 * 1024 * 1024]).unwrap();
    let descriptor = open(&path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
    let before = fstat(&descriptor).unwrap();
    let result = hash_file_after_chunk(descriptor, &before, || {
        let mut writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all(b"b").unwrap();
        writer.sync_all().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    });
    assert_eq!(
        result.unwrap_err().to_string(),
        "tree file changed while hashing"
    );
}

#[test]
fn refuses_a_replaced_visible_root_after_scanning() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("sdk");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("data"), b"first generation").unwrap();
    let old = temporary.path().join("retired-sdk");
    let result = inventory_tree_with_after_scan(&root, TreeKind::Sdk, || {
        std::fs::rename(&root, &old).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("data"), b"replacement").unwrap();
    });
    assert_eq!(
        result.unwrap_err().to_string(),
        "tree root changed during inventory"
    );
}

#[test]
fn refuses_a_new_nested_entry_after_that_directory_was_scanned() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("sdk");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/data"), b"first").unwrap();
    let root = root.canonicalize().unwrap();
    let result = inventory_tree_with_hooks(&root, TreeKind::Sdk, || {}, &mut |relative| {
        if relative == "nested" {
            std::fs::write(root.join("nested/late"), b"unaccounted").unwrap();
        }
    });
    assert_eq!(
        result.unwrap_err().to_string(),
        "tree directory changed while scanning"
    );
}

#[test]
fn refuses_a_changed_symlink_target_between_read_and_containment() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("sdk");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("first"), b"first").unwrap();
    std::fs::write(root.join("second"), b"second").unwrap();
    let link = root.join("current");
    symlink("first", &link).unwrap();
    let root = root.canonicalize().unwrap();
    let descriptor = open_absolute_directory(&root).unwrap();
    let context = TreeContext {
        root_fd: &descriptor,
        kind: TreeKind::Sdk,
    };
    let result = stable_symlink_target(&descriptor, &context, "current", "current", || {
        std::fs::remove_file(&link).unwrap();
        symlink("second", &link).unwrap();
    });
    assert_eq!(
        result.unwrap_err().to_string(),
        "tree symlink changed during inventory"
    );
}
