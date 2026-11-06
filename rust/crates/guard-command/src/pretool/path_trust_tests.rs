use super::{link_target, trusted_link_spelling};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

/// A private scratch directory in the canonical system temporary directory,
/// which is root's sticky `/tmp` or this user's own directory.
fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("guard-path-trust-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for directory in ["real", "sub", "open/real"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    for directory in ["", "real", "sub", "open", "open/real"] {
        let mode = if directory == "open" { 0o777 } else { 0o755 };
        std::fs::set_permissions(root.join(directory), std::fs::Permissions::from_mode(mode))
            .unwrap();
    }
    root
}

#[test]
fn relative_link_targets_resolve_from_the_canonical_parent() {
    let parent = Path::new("/private/var/folders/a");
    assert_eq!(
        link_target(parent, Path::new("../../tmp")),
        Some(PathBuf::from("/private/var/tmp"))
    );
    assert_eq!(
        link_target(parent, Path::new("./b")),
        Some(PathBuf::from("/private/var/folders/a/b"))
    );
    assert_eq!(
        link_target(parent, Path::new("/private/tmp")),
        Some(PathBuf::from("/private/tmp"))
    );
    assert_eq!(
        link_target(Path::new("/"), Path::new("../tmp")),
        Some(PathBuf::from("/tmp"))
    );
    // A `..` after a named step may climb out of another link.
    assert_eq!(link_target(parent, Path::new("b/../c")), None);
    assert_eq!(link_target(parent, Path::new("/private/../tmp")), None);
}

#[test]
fn a_trusted_link_to_a_parent_relative_target_counts_as_its_target() {
    let root = scratch("parent-relative");
    symlink("../real", root.join("sub/up")).unwrap();
    symlink("../open/real", root.join("sub/open")).unwrap();
    symlink("real/../real", root.join("sub/climb")).unwrap();
    std::fs::create_dir(root.join("sub/real")).unwrap();
    let outcome = (
        trusted_link_spelling(&root.join("sub/up"), &root.join("real")),
        // The same checks apply to the resolved target: a directory other
        // users can write may swap it, so the spelling is not the target.
        trusted_link_spelling(&root.join("sub/open"), &root.join("open/real")),
        trusted_link_spelling(&root.join("sub/climb"), &root.join("sub/real")),
    );
    std::fs::remove_dir_all(&root).unwrap();
    assert!(outcome.0);
    assert!(!outcome.1);
    assert!(!outcome.2);
}
