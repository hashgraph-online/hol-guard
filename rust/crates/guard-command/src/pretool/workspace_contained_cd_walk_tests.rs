use super::first_from;
use std::path::{Path, PathBuf};

struct Scratch {
    _hold: tempfile::TempDir,
    root: PathBuf,
}

fn scratch() -> Scratch {
    let hold = tempfile::tempdir().expect("walk scratch");
    let root = std::fs::canonicalize(hold.path()).expect("canonical scratch");
    Scratch { _hold: hold, root }
}

fn marked(directory: &Path) -> bool {
    directory.join("marker").is_file()
}

#[test]
fn a_marker_at_the_workspace_root_is_found_from_a_directory_below_it() {
    let held = scratch();
    let root = held.root.clone();
    let workspace = root.join("workspace");
    let deep = workspace.join("packages/web/src");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(workspace.join("marker"), "").unwrap();

    assert_eq!(
        first_from(&deep, &workspace, marked).as_deref(),
        Some(workspace.as_path())
    );
    // A directory the command has not created yet still resolves to the
    // project above it. Nothing on that path exists to resolve, so the walk
    // is the lexical one the tool would make once `cd` had created it.
    assert_eq!(
        first_from(&workspace.join("missing/deep"), &workspace, marked).as_deref(),
        Some(workspace.as_path())
    );
    assert_eq!(
        first_from(&workspace, &workspace, marked).as_deref(),
        Some(workspace.as_path())
    );
}

#[test]
fn the_nearest_marker_below_the_root_is_enough() {
    let held = scratch();
    let root = held.root.clone();
    let workspace = root.join("workspace");
    let crate_directory = workspace.join("crates/engine");
    let deep = crate_directory.join("src");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(crate_directory.join("marker"), "").unwrap();

    assert_eq!(
        first_from(&deep, &workspace, marked).as_deref(),
        Some(crate_directory.as_path())
    );
}

#[test]
fn nothing_above_the_workspace_root_is_read() {
    let held = scratch();
    let root = held.root.clone();
    let workspace = root.join("workspace");
    std::fs::create_dir_all(workspace.join("packages/web")).unwrap();
    // The marker sits beside the workspace, where the walk must never reach.
    std::fs::write(root.join("marker"), "").unwrap();

    assert!(first_from(&workspace.join("packages/web"), &workspace, marked).is_none());
    assert!(first_from(&workspace, &workspace, marked).is_none());
}

#[test]
fn a_directory_outside_the_workspace_is_read_but_never_walked_from() {
    let held = scratch();
    let root = held.root.clone();
    let workspace = root.join("workspace");
    let sibling = root.join("sibling");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(sibling.join("inner")).unwrap();
    std::fs::write(sibling.join("marker"), "").unwrap();

    // The directory itself is still read, as the single-directory checks did.
    assert_eq!(
        first_from(&sibling, &workspace, marked).as_deref(),
        Some(sibling.as_path())
    );
    // Its parents are not, so a path that already left the workspace cannot
    // climb to a marker the workspace does not hold.
    assert!(first_from(&sibling.join("inner"), &workspace, marked).is_none());
}

#[test]
fn a_parent_step_in_the_path_stops_the_walk() {
    let held = scratch();
    let root = held.root.clone();
    let workspace = root.join("workspace");
    std::fs::create_dir_all(workspace.join("packages")).unwrap();
    std::fs::write(root.join("marker"), "").unwrap();

    // `workspace/../..` is lexically below the workspace, and walking up from
    // it would read directories above the root.
    let climbed = workspace.join("..").join("..");
    assert!(first_from(&climbed, &workspace, marked).is_none());
}

/// A name below the workspace is not a place below it. `workspace/link` may
/// point anywhere, so a marker found through it has to resolve under the
/// workspace before the walk counts it; otherwise a tool planted outside
/// would admit a command the sandbox never bounds.
#[cfg(unix)]
#[test]
fn a_symlink_to_an_external_parent_is_not_walked_through() {
    let held = scratch();
    let root = held.root.clone();
    let workspace = root.join("workspace");
    let outside = root.join("outside");
    std::fs::create_dir_all(workspace.join("packages")).unwrap();
    std::fs::create_dir_all(outside.join("deep")).unwrap();
    std::fs::write(outside.join("marker"), "").unwrap();
    std::os::unix::fs::symlink(&outside, workspace.join("link")).unwrap();

    assert!(first_from(&workspace.join("link/deep"), &workspace, marked).is_none());
}

/// A symlink that lands back inside the workspace names a directory the
/// sandbox does bound. The walk reads the physical project that directory
/// enters, which is the project the tool would bind.
#[cfg(unix)]
#[test]
fn a_symlink_inside_the_workspace_is_still_walked_through() {
    let held = scratch();
    let root = held.root.clone();
    let workspace = root.join("workspace");
    let project = workspace.join("project");
    std::fs::create_dir_all(project.join("deep")).unwrap();
    std::fs::write(project.join("marker"), "").unwrap();
    std::os::unix::fs::symlink(&project, workspace.join("link")).unwrap();

    assert_eq!(
        first_from(&workspace.join("link/deep"), &workspace, marked).as_deref(),
        Some(project.as_path())
    );
}

/// A symlink that leaves the workspace ends the walk even when the workspace
/// root also holds a marker. The tool climbs the physical parents of the
/// entered directory, so the lexical root is not a place it would read.
#[cfg(unix)]
#[test]
fn an_external_symlink_stops_the_walk_when_the_root_also_has_a_marker() {
    let held = scratch();
    let root = held.root.clone();
    let workspace = root.join("workspace");
    let outside = root.join("outside");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(outside.join("deep")).unwrap();
    std::fs::write(workspace.join("marker"), "").unwrap();
    std::fs::write(outside.join("marker"), "").unwrap();
    std::os::unix::fs::symlink(&outside, workspace.join("link")).unwrap();

    assert!(first_from(&workspace.join("link/deep"), &workspace, marked).is_none());
}

/// The entered directory is the symlink, and the marker is only at the
/// workspace root. The tool has already landed outside, so that root marker
/// is not one it would read.
#[cfg(unix)]
#[test]
fn an_external_symlink_is_not_climbed_to_the_workspace_marker() {
    let held = scratch();
    let root = held.root.clone();
    let workspace = root.join("workspace");
    let outside = root.join("outside");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(outside.join("deep")).unwrap();
    std::fs::write(workspace.join("marker"), "").unwrap();
    std::os::unix::fs::symlink(&outside, workspace.join("link")).unwrap();

    assert!(first_from(&workspace.join("link"), &workspace, marked).is_none());
    assert!(first_from(&workspace.join("link/deep"), &workspace, marked).is_none());
    assert!(first_from(&workspace.join("link/missing"), &workspace, marked).is_none());
}

/// The nearer physical project wins over a marker at the workspace root.
/// `uv` stops at the first `pyproject.toml` it climbs to, so a root environment
/// must not admit a run that entered a nested project through a symlink.
#[cfg(unix)]
#[test]
fn an_internal_symlink_binds_the_nearer_physical_project() {
    let held = scratch();
    let root = held.root.clone();
    let workspace = root.join("workspace");
    let pkg = workspace.join("projects/pkg");
    let src = pkg.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(workspace.join("marker"), "").unwrap();
    std::fs::write(pkg.join("marker"), "").unwrap();
    std::os::unix::fs::symlink(&src, workspace.join("link")).unwrap();

    assert_eq!(
        first_from(&workspace.join("link"), &workspace, marked).as_deref(),
        Some(pkg.as_path())
    );
    // The directory does not exist yet. The first ancestor that does is the
    // link, and the tool would climb from where that link resolves.
    assert_eq!(
        first_from(&workspace.join("link/missing"), &workspace, marked).as_deref(),
        Some(pkg.as_path())
    );
}
