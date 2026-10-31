//! Reading a repository's own worktree registry, and the suffix match Git uses
//! to resolve a `git worktree remove` argument that stands for no directory.

use super::{absent, git_reads_as_suffix, registered_worktrees, REGISTERED_WORKTREE_LIMIT};
use std::fs;
use std::path::{Path, PathBuf};

/// A repository directory with a worktree registry holding one entry per named
/// worktree, each pointing at `<root>/<name>/.git` the way Git writes it.
fn registry_with(root: &Path, names: &[&str]) -> PathBuf {
    let repository = root.join("checkout");
    let registry = repository.join(".git").join("worktrees");
    fs::create_dir_all(&registry).unwrap();
    for name in names {
        let entry = registry.join(name);
        fs::create_dir_all(&entry).unwrap();
        let worktree = root.join(name);
        fs::write(
            entry.join("gitdir"),
            format!("{}\n", worktree.join(".git").display()),
        )
        .unwrap();
    }
    repository
}

#[test]
fn a_path_that_stands_for_nothing_is_absent() {
    let root = tempfile::tempdir().unwrap();
    assert!(absent(&root.path().join("never-created")));
    assert!(!absent(root.path()));
    fs::write(root.path().join("file"), "x").unwrap();
    assert!(!absent(&root.path().join("file")));
}

#[test]
fn a_repository_with_no_registry_registers_nothing() {
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("checkout");
    fs::create_dir_all(repository.join(".git")).unwrap();
    assert_eq!(registered_worktrees(&repository), Some(Vec::new()));
}

#[test]
fn a_registry_names_the_parent_of_each_pointer() {
    let root = tempfile::tempdir().unwrap();
    let repository = registry_with(root.path(), &["report-wt", "app-portal-fix"]);
    let mut registered = registered_worktrees(&repository).unwrap();
    registered.sort();
    let mut expected = vec![
        root.path().join("report-wt"),
        root.path().join("app-portal-fix"),
    ];
    expected.sort();
    assert_eq!(registered, expected);
}

#[test]
fn a_registry_this_route_cannot_read_is_not_an_empty_one() {
    let root = tempfile::tempdir().unwrap();
    let repository = registry_with(root.path(), &["report-wt"]);
    let registry = repository.join(".git").join("worktrees");

    // An entry whose pointer is missing.
    fs::remove_file(registry.join("report-wt").join("gitdir")).unwrap();
    assert_eq!(registered_worktrees(&repository), None);

    // A pointer too long to be a path.
    fs::write(registry.join("report-wt").join("gitdir"), "x".repeat(4097)).unwrap();
    assert_eq!(registered_worktrees(&repository), None);

    // More registrations than this route reads.
    fs::remove_dir_all(&registry).unwrap();
    let names: Vec<String> = (0..=REGISTERED_WORKTREE_LIMIT)
        .map(|index| format!("wt-{index}"))
        .collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    registry_with(root.path(), &names);
    assert_eq!(registered_worktrees(&repository), None);
}

#[test]
fn git_resolves_a_suffix_only_at_a_directory_boundary() {
    let registered = Path::new("/w/app-portal-fix");
    assert!(git_reads_as_suffix(registered, "app-portal-fix"));
    assert!(git_reads_as_suffix(registered, "w/app-portal-fix"));
    assert!(git_reads_as_suffix(registered, "/w/app-portal-fix"));
    // The filesystem's comparison ignores case on the platforms Git treats as
    // case-insensitive, so a target differing only in case still resolves.
    assert!(git_reads_as_suffix(registered, "App-Portal-Fix"));
    // A trailing part that starts mid-component is not a match.
    assert!(!git_reads_as_suffix(registered, "portal-fix"));
    assert!(!git_reads_as_suffix(registered, "fix"));
    // A longer target cannot be the trailing part of a shorter path.
    assert!(!git_reads_as_suffix(
        registered,
        "/elsewhere/w/app-portal-fix"
    ));
    // A relative target never matches an absolute registration.
    assert!(!git_reads_as_suffix(registered, "../app-portal-fix"));
}

#[test]
fn a_windows_registration_matches_at_its_own_separator() {
    let registered = Path::new(r"C:\w\app-portal-fix");
    assert!(git_reads_as_suffix(registered, "app-portal-fix"));
    assert!(!git_reads_as_suffix(registered, "portal-fix"));
}

#[test]
fn a_relative_backlink_is_a_registry_this_route_cannot_read() {
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("org").join("app");
    let entry = repository.join(".git").join("worktrees").join("portal-fix");
    fs::create_dir_all(&entry).unwrap();
    // Git 2.48 writes the backlink in this form under
    // `worktree.useRelativePaths`, and resolves it against the registration
    // before it matches a removal's argument. Read as text the registration
    // stands for no part of `org/app-portal-fix`, so comparing it would let a
    // removal of that absent-looking target through and Git would then take
    // away the registered checkout it resolves to.
    fs::write(entry.join("gitdir"), "../../../../app-portal-fix/.git\n").unwrap();
    assert!(!git_reads_as_suffix(
        Path::new("../../../../app-portal-fix"),
        "org/app-portal-fix"
    ));
    assert!(registered_worktrees(&repository).is_none());
}
