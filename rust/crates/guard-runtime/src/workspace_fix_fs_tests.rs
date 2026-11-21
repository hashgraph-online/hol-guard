use std::fs;
use std::path::{Path, PathBuf};

use super::*;

const BASE: &str = "{\"dependencies\": {\"left-pad\": \"1.0.0\"}}\n";
const FIXED: &str = "{\"dependencies\": {\"left-pad\": \"1.3.0\"}}\n";

fn project() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    fs::create_dir_all(root.join("packages/app")).unwrap();
    fs::write(root.join("package.json"), BASE).unwrap();
    fs::write(root.join("packages/app/package.json"), BASE).unwrap();
    (dir, root)
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn replace(root: &Path, relative: &str) -> Result<Replaced, Code> {
    replace_if_unchanged(
        root,
        relative,
        &sha256_hex(BASE.as_bytes()),
        FIXED.as_bytes(),
    )
}

#[test]
fn reads_a_nested_manifest_and_refuses_bad_paths() {
    let (_dir, root) = project();
    let manifest = read_manifest(&root, "packages/app/package.json").unwrap();
    assert_eq!(manifest.bytes, BASE.as_bytes());
    for bad in [
        "",
        "/package.json",
        "../package.json",
        "packages/../package.json",
        "./package.json",
        "packages//app/package.json",
        "packages\\app\\package.json",
        "packages/app/other.json",
    ] {
        assert!(
            matches!(read_manifest(&root, bad), Err("manifest_path_invalid")),
            "{bad}"
        );
    }
    assert!(matches!(
        read_manifest(&root, "missing/package.json"),
        Err("manifest_missing")
    ));
    fs::create_dir(root.join("big")).unwrap();
    fs::write(root.join("big/package.json"), vec![b' '; 1024 * 1024 + 1]).unwrap();
    assert!(matches!(
        read_manifest(&root, "big/package.json"),
        Err("manifest_too_large")
    ));
    fs::create_dir(root.join("dir")).unwrap();
    fs::create_dir(root.join("dir/package.json")).unwrap();
    assert!(matches!(
        read_manifest(&root, "dir/package.json"),
        Err("manifest_not_regular")
    ));
}

#[cfg(unix)]
#[test]
fn symlinks_are_never_followed_at_any_component() {
    use std::os::unix::fs::symlink;
    let (_dir, root) = project();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("package.json"), BASE).unwrap();
    symlink(
        outside.path().join("package.json"),
        root.join("linked.json"),
    )
    .unwrap();
    fs::create_dir(root.join("leaf")).unwrap();
    symlink(
        outside.path().join("package.json"),
        root.join("leaf/package.json"),
    )
    .unwrap();
    symlink(outside.path(), root.join("escape")).unwrap();
    assert!(matches!(
        read_manifest(&root, "leaf/package.json"),
        Err("manifest_is_symlink")
    ));
    assert!(matches!(
        read_manifest(&root, "escape/package.json"),
        Err("manifest_path_invalid")
    ));
    assert!(matches!(
        replace_if_unchanged(
            &root,
            "escape/package.json",
            &sha256_hex(BASE.as_bytes()),
            FIXED.as_bytes()
        ),
        Err("manifest_path_invalid")
    ));
    let linked = replace(&root, "leaf/package.json").unwrap();
    assert!(matches!(
        linked,
        Replaced::Stale {
            reason: "manifest_is_symlink",
            ..
        }
    ));
    assert_eq!(
        fs::read_to_string(outside.path().join("package.json")).unwrap(),
        BASE
    );
    assert_eq!(entries(outside.path()), ["package.json"]);
}

#[cfg(unix)]
#[test]
fn a_symlinked_root_is_refused() {
    let (_dir, root) = project();
    let holder = tempfile::tempdir().unwrap();
    let link = holder.path().join("root");
    std::os::unix::fs::symlink(&root, &link).unwrap();
    assert!(matches!(
        read_manifest(&link, "package.json"),
        Err("manifest_root_unavailable")
    ));
}

#[cfg(unix)]
#[test]
fn replaces_an_unchanged_manifest_and_leaves_no_scratch_files() {
    let (_dir, root) = project();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("package.json"), fs::Permissions::from_mode(0o640)).unwrap();
    }
    assert_eq!(replace(&root, "package.json"), Ok(Replaced::Applied));
    assert_eq!(
        fs::read_to_string(root.join("package.json")).unwrap(),
        FIXED
    );
    assert_eq!(entries(&root), ["package.json", "packages"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(root.join("package.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o640);
    }
}

#[cfg(unix)]
#[test]
fn a_manifest_changed_before_the_call_is_left_alone() {
    let (_dir, root) = project();
    fs::write(root.join("package.json"), "{\"user\": true}\n").unwrap();
    assert_eq!(
        replace(&root, "package.json"),
        Ok(Replaced::Stale {
            reason: "manifest_changed",
            preserved: None
        })
    );
    assert_eq!(
        fs::read_to_string(root.join("package.json")).unwrap(),
        "{\"user\": true}\n"
    );
    assert_eq!(entries(&root), ["package.json", "packages"]);
}

#[cfg(unix)]
#[test]
fn a_manifest_replaced_after_the_check_is_put_back_and_not_overwritten() {
    let (_dir, root) = project();
    let user = "{\"user\": \"edit\"}\n";
    let result = replace_with_hooks(
        &root,
        "package.json",
        &sha256_hex(BASE.as_bytes()),
        FIXED.as_bytes(),
        || {
            // An editor's atomic save lands between the check and the swap.
            fs::write(root.join("saved.tmp"), user).unwrap();
            fs::rename(root.join("saved.tmp"), root.join("package.json")).unwrap();
        },
        || {},
    );
    assert_eq!(
        result,
        Ok(Replaced::Stale {
            reason: "manifest_changed",
            preserved: None
        })
    );
    assert_eq!(fs::read_to_string(root.join("package.json")).unwrap(), user);
    assert_eq!(entries(&root), ["package.json", "packages"]);
}

#[cfg(unix)]
#[test]
fn a_file_created_in_the_gap_is_kept_and_the_moved_edit_is_preserved() {
    let (_dir, root) = project();
    let user = "{\"user\": \"edit\"}\n";
    let result = replace_with_hooks(
        &root,
        "package.json",
        &sha256_hex(BASE.as_bytes()),
        FIXED.as_bytes(),
        || fs::write(root.join("package.json"), "{\"user\": \"first\"}\n").unwrap(),
        || fs::write(root.join("package.json"), user).unwrap(),
    );
    let Ok(Replaced::Stale {
        reason: "manifest_changed",
        preserved: Some(kept),
    }) = result
    else {
        panic!("expected a preserved file, got {result:?}");
    };
    assert_eq!(fs::read_to_string(root.join("package.json")).unwrap(), user);
    assert_eq!(
        fs::read_to_string(root.join(kept)).unwrap(),
        "{\"user\": \"first\"}\n"
    );
}

#[cfg(unix)]
#[test]
fn a_file_created_after_the_move_wins_over_the_fix() {
    let (_dir, root) = project();
    let user = "{\"user\": \"edit\"}\n";
    let result = replace_with_hooks(
        &root,
        "package.json",
        &sha256_hex(BASE.as_bytes()),
        FIXED.as_bytes(),
        || {},
        || fs::write(root.join("package.json"), user).unwrap(),
    );
    assert_eq!(
        result,
        Ok(Replaced::Stale {
            reason: "manifest_changed",
            preserved: None
        })
    );
    assert_eq!(fs::read_to_string(root.join("package.json")).unwrap(), user);
    assert_eq!(entries(&root), ["package.json", "packages"]);
}

#[cfg(not(unix))]
#[test]
fn replacing_is_refused_without_descriptor_relative_writes() {
    let (_dir, root) = project();
    let before = fs::read(root.join("package.json")).unwrap();
    assert_eq!(replace(&root, "package.json"), Err("fix_apply_unsupported"));
    assert_eq!(fs::read(root.join("package.json")).unwrap(), before);
    assert_eq!(entries(&root), ["package.json", "packages"]);
}

#[test]
fn finds_the_nearest_lockfiles_up_to_the_root() {
    let (_dir, root) = project();
    assert!(lockfiles_for(&root, "packages/app/package.json").is_empty());
    fs::write(root.join("yarn.lock"), "").unwrap();
    fs::write(root.join("package-lock.json"), "{}").unwrap();
    assert_eq!(
        lockfiles_for(&root, "packages/app/package.json"),
        ["package-lock.json", "yarn.lock"]
    );
    fs::write(root.join("packages/app/pnpm-lock.yaml"), "").unwrap();
    assert_eq!(
        lockfiles_for(&root, "packages/app/package.json"),
        ["packages/app/pnpm-lock.yaml"]
    );
}
