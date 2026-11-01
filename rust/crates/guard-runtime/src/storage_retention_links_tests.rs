use super::*;

use std::os::unix::fs::symlink;

#[test]
fn prune_ignores_symlinks() {
    let (_directory, root) = canonical_tempdir();
    let home = root.as_path();
    let real = snapshot(home, "guard.db.corrupt-real", 30.0 * DAY, 8);
    let link = home.join("guard.db.corrupt-link");
    symlink(&real, &link).expect("link");
    snapshot(home, "guard.db.corrupt-new", 0.0, 8);

    prune(home, 1, 0.0, BUDGET);
    assert!(fs::symlink_metadata(&link)
        .expect("link")
        .file_type()
        .is_symlink());
    assert_eq!(quarantine_summary(home)["count"], 1);
}

#[test]
fn staging_sweep_refuses_a_linked_runtime_tree() {
    let (_directory, root) = canonical_tempdir();
    let guard_home = root.as_path().join("guard-home");
    let stale = root.as_path().join("target-tree").join("home");
    fs::create_dir_all(&stale).expect("target");
    fs::create_dir(&guard_home).expect("home");
    symlink(
        root.as_path().join("target-tree"),
        guard_home.join(UPDATE_RUNTIME_DIR_NAME),
    )
    .expect("link");

    prune_staging(&guard_home, 0.0, now() + 30.0 * DAY);
    assert!(stale.exists());
}

#[test]
fn a_linked_staging_child_is_unlinked_not_followed() {
    let (_directory, root) = canonical_tempdir();
    let runtime = staging(root.as_path());
    let outside = root.as_path().join("outside");
    fs::create_dir(&outside).expect("outside");
    fs::write(outside.join("keep"), b"keep").expect("keep");
    symlink(&outside, runtime.join("link")).expect("link");

    prune_staging(&root.as_path().join("guard-home"), 0.0, now() + 1.0);
    assert!(fs::symlink_metadata(runtime.join("link")).is_err());
    assert_eq!(fs::read(outside.join("keep")).expect("keep"), b"keep");
}
