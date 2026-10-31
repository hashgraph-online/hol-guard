use super::*;

fn project() -> (tempfile::TempDir, PathBuf) {
    let scratch = tempfile::tempdir().expect("scratch");
    let workspace = scratch
        .path()
        .canonicalize()
        .expect("canonical")
        .join("app");
    std::fs::create_dir_all(workspace.join("node_modules")).expect("modules");
    (scratch, workspace)
}

#[test]
fn vites_bundle_directory_is_created_under_the_projects_modules() {
    let (_scratch, workspace) = project();
    let root = workspace.join("node_modules/.vite-temp");
    create_bundle_directory(&root, &workspace).expect("created");
    assert!(real_directory(&root));
    // An existing real directory is kept as it is.
    create_bundle_directory(&root, &workspace).expect("kept");
}

#[test]
fn a_linked_or_outside_bundle_directory_is_refused() {
    let (scratch, workspace) = project();
    let elsewhere = scratch.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("elsewhere");
    let modules = workspace.join("node_modules");
    let linked = modules.join(".vite-temp");
    std::os::unix::fs::symlink(&elsewhere, &linked).expect("linked root");
    assert!(create_bundle_directory(&linked, &workspace).is_err());
    std::fs::remove_file(&linked).expect("unlink");
    std::fs::remove_dir(&modules).expect("modules");
    std::os::unix::fs::symlink(&elsewhere, &modules).expect("linked modules");
    assert!(create_bundle_directory(&modules.join(".vite-temp"), &workspace).is_err());
    assert!(!elsewhere.join(".vite-temp").exists());
    let outside = elsewhere.join("node_modules/.vite-temp");
    std::fs::create_dir_all(outside.parent().expect("parent")).expect("outside");
    assert!(create_bundle_directory(&outside, &workspace).is_err());
    assert!(!outside.exists());
}

#[test]
fn only_a_linkless_climb_reaches_the_workspace() {
    let (scratch, workspace) = project();
    assert!(reached_without_links(
        &workspace.join("node_modules"),
        &workspace
    ));
    assert!(reached_without_links(&workspace, &workspace));
    assert!(!reached_without_links(
        &workspace.join("missing"),
        &workspace
    ));
    assert!(!reached_without_links(scratch.path(), &workspace));
    let alias = scratch.path().join("alias");
    std::os::unix::fs::symlink(&workspace, &alias).expect("alias");
    assert!(!reached_without_links(
        &alias.join("node_modules"),
        &workspace
    ));
}
