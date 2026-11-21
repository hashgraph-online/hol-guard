//! The workspace prefix walk: which absolute spellings still stand inside the
//! workspace once the shell has taken their `..` steps.

use super::inside_workspace;
use std::path::Path;

#[test]
fn a_parent_step_leaves_the_workspace_the_path_is_spelled_from() {
    let workspace = Path::new("/projects/app");
    assert!(inside_workspace(
        Path::new("/projects/app/src/main.rs"),
        workspace
    ));
    assert!(inside_workspace(
        Path::new("/projects/app/build/../src"),
        workspace
    ));
    assert!(inside_workspace(
        Path::new("/projects/app/./src"),
        workspace
    ));
    assert!(!inside_workspace(
        Path::new("/projects/app/../other"),
        workspace
    ));
    assert!(!inside_workspace(
        Path::new("/projects/app/../../../etc/hosts"),
        workspace
    ));
    assert!(!inside_workspace(
        Path::new("/projects/app-sibling"),
        workspace
    ));
    assert!(!inside_workspace(Path::new("/etc/hosts"), workspace));
}

#[test]
fn a_walk_past_the_file_system_root_names_nothing_inside() {
    assert!(!inside_workspace(
        Path::new("/../../../etc/hosts"),
        Path::new("/projects/app")
    ));
}

/// A link's `..` is its target's parent, so a path that walks past one lands
/// where the file system puts it rather than where the spelling suggests. Only
/// a link an unprivileged process can plant makes this reachable, which is a
/// Unix layout; Windows reserves the call.
#[cfg(unix)]
#[test]
fn a_parent_step_past_a_link_keeps_the_review_the_spelling_would_lose() {
    let root = tempfile::tempdir().expect("temp root");
    let workspace = root.path().join("project");
    let elsewhere = root.path().join("other/nested");
    std::fs::create_dir_all(&workspace).expect("workspace");
    std::fs::create_dir_all(&elsewhere).expect("linked directory");
    let link = root.path().join("alias");
    std::os::unix::fs::symlink(&elsewhere, &link).expect("link");

    // `alias/..` is `other`, so `alias/../project/file.txt` resolves beside the
    // linked directory and never reaches the workspace it spells.
    assert!(!inside_workspace(
        &link.join("../project/file.txt"),
        &workspace
    ));
    // A directory that does not exist yet is not a link, so an ordinary step
    // inside the workspace still walks lexically.
    assert!(inside_workspace(
        &workspace.join("src/../src/main.rs"),
        &workspace
    ));
}
