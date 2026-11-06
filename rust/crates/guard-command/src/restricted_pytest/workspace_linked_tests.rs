use super::super::workspace_overlay::apply_linked;
use super::*;

fn linked(root: &Path) -> LinkedGit {
    LinkedGit {
        common: root.join("main/.git"),
        admin: root.join("main/.git/worktrees/wt"),
    }
}

fn pair(common: &str, admin: &str) -> LinkedGit {
    LinkedGit {
        common: PathBuf::from(common),
        admin: PathBuf::from(admin),
    }
}

#[test]
fn only_a_checkout_git_and_its_direct_admin_entry_are_accepted() {
    let workspace = Path::new("/r/wt");
    assert!(linked(Path::new("/r")).checked(workspace).is_ok());
    for value in [
        pair("/r/main/git", "/r/main/git/worktrees/wt"),
        pair("/r/main/.git", "/r/main/.git/worktrees/a/b"),
        pair("/r/main/.git", "/r/main/.git/wt"),
        pair("/r/main/.git", "/r/main/.git/worktrees/.."),
        pair("r/main/.git", "r/main/.git/worktrees/wt"),
    ] {
        assert!(value.checked(workspace).is_err(), "{value:?}");
    }
    // A workspace inside the shared directory, or holding it, or relative.
    for workspace in ["/r/main/.git/wt", "/r", "wt"] {
        assert!(linked(Path::new("/r"))
            .checked(Path::new(workspace))
            .is_err());
    }
}

#[test]
fn overlay_layers_must_be_absolute_and_apart() {
    let value = linked(Path::new("/r"));
    let workspace = Path::new("/r/wt");
    let upper = Path::new("/t/upper");
    let layers = [Path::new("/t/s/upper"), Path::new("/t/s/work")];
    assert!(value.with_layers(workspace, &layers, &[upper]).is_ok());
    for layers in [
        vec![Path::new("t/s/upper")],
        vec![Path::new("/r/main/x")],
        vec![Path::new("/r/wt/x")],
        vec![Path::new("/t")],
        vec![Path::new("/t/upper/x")],
        vec![Path::new("/t/s"), Path::new("/t/s/work")],
    ] {
        assert!(
            value.with_layers(workspace, &layers, &[upper]).is_err(),
            "{layers:?}"
        );
    }
}

#[test]
fn the_overlay_pattern_admits_only_shared_stores_and_admin_files() {
    let value = linked(Path::new("/r"));
    let only = regex::Regex::new(&value.overlay_pattern().unwrap()).unwrap();
    for path in [
        "objects/ab/cdef",
        "refs/heads/fix/x",
        "logs/refs/heads/main",
        "packed-refs",
        "worktrees/wt/index",
        "worktrees/wt/HEAD",
        "worktrees/wt/AUTO_MERGE.lock",
        "worktrees/wt/MERGE_HEAD.lock",
        "worktrees/wt/logs",
        "worktrees/wt/logs/HEAD",
    ] {
        assert!(only.is_match(&format!("/r/main/.git/{path}")), "{path}");
    }
    for path in [
        "config",
        "description",
        "hooks/pre-commit",
        "info/attributes",
        "objects",
        "worktrees/wt/gitdir",
        "worktrees/wt/commondir",
        "worktrees/wt/config.worktree",
        "worktrees/wt/index/x",
        "worktrees/wt/AUTO_MERGE.lock/x",
        "worktrees/other/HEAD",
    ] {
        assert!(!only.is_match(&format!("/r/main/.git/{path}")), "{path}");
    }
}

fn tree(name: &str) -> (PathBuf, LinkedGit) {
    let root = std::env::temp_dir().join(format!("guard-linked-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for directory in [
        "main/.git/objects/ab",
        "main/.git/refs/heads",
        "main/.git/worktrees/wt",
        "wt",
        "upper",
        "shared",
    ] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    let root = root.canonicalize().unwrap();
    let value = linked(&root);
    (root, value)
}

fn put(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn run(root: &Path, value: &LinkedGit) -> Result<usize, RestrictedPytestError> {
    apply_linked(
        &root.join("upper"),
        &root.join("wt"),
        &[],
        Some((value, &root.join("shared"))),
    )
}

#[test]
fn a_linked_run_applies_shared_stores_and_admin_files() {
    let (root, value) = tree("applied");
    put(&root.join("upper/report.md"), "report");
    put(&root.join("shared/objects/ab/cdef"), "object");
    put(&root.join("shared/refs/heads/weekly"), "abc\n");
    put(&root.join("shared/worktrees/wt/index"), "index");
    put(&root.join("shared/worktrees/wt/logs/HEAD"), "log");
    run(&root, &value).unwrap();
    let read = |path: &str| fs::read_to_string(root.join(path)).unwrap();
    assert_eq!(read("wt/report.md"), "report");
    assert_eq!(read("main/.git/objects/ab/cdef"), "object");
    assert_eq!(read("main/.git/refs/heads/weekly"), "abc\n");
    assert_eq!(read("main/.git/worktrees/wt/index"), "index");
    assert_eq!(read("main/.git/worktrees/wt/logs/HEAD"), "log");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn any_other_shared_change_discards_both_layers() {
    for (index, path) in [
        "config",
        "description",
        "hooks/pre-commit",
        "objects/info/alternates",
        "refs/remotes/origin/config",
        "worktrees/wt/gitdir",
        "worktrees/wt/commondir",
        "worktrees/other/HEAD",
    ]
    .iter()
    .enumerate()
    {
        let (root, value) = tree(&format!("denied-{index}"));
        put(&root.join("upper/report.md"), "report");
        put(&root.join("shared/refs/heads/weekly"), "abc\n");
        put(&root.join("shared").join(path), "x");
        assert!(run(&root, &value).is_err(), "{path}");
        assert!(!root.join("wt/report.md").exists(), "{path}");
        assert!(!root.join("main/.git/refs/heads/weekly").exists(), "{path}");
        assert!(!root.join("main/.git").join(path).exists(), "{path}");
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn a_broad_or_sensitive_main_checkout_is_not_admissible() {
    let home = Path::new("/w/home");
    assert!(admissible_checkout(&home.join("main/.git"), Some(home)));
    for common in [
        "/.git",
        "/tmp/.git",
        "/w/home/.git",
        "/w/.git",
        "/w/home/.ssh/.git",
    ] {
        assert!(
            !admissible_checkout(Path::new(common), Some(home)),
            "{common}"
        );
    }
}
