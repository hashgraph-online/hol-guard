//! The documents the workspace sandbox reopens: a committed, secret-free
//! page whose name its credential denials match, and nothing else beside it.

use super::sandbox_readable_documents;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A committed page named for a key, as `docs/auth-evidence` keeps them.
pub(crate) const PAGE: &str = "docs/auth-evidence/private-key-jwt-client-auth.md";
/// Key-named files beside it that stay hidden: an untracked page, a
/// committed page holding a key, a committed link to the page, a committed
/// key file, a committed environment file and a page in a store directory.
pub(crate) const HIDDEN: [&str; 6] = [
    "docs/auth-evidence/private-key-rotation.md",
    "docs/auth-evidence/private-key-sample.md",
    "docs/auth-evidence/private-key-link.md",
    "docs/private-key.pem",
    ".env",
    "docs/secrets/private-key-notes.md",
];

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn git(workspace: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(workspace)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// Makes `workspace` a repository committing [`PAGE`] and the hidden files
/// except the untracked page.
pub(crate) fn populate(workspace: &Path) {
    let page = "# private_key_jwt\n\nThe client signs a JWT assertion with its own key.\n";
    write(&workspace.join(PAGE), page);
    write(&workspace.join(HIDDEN[0]), page);
    let header = concat!("-----BEGIN RSA PRIVATE", " KEY-----");
    write(
        &workspace.join(HIDDEN[1]),
        &format!("```\n{header}\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\n```\n"),
    );
    std::os::unix::fs::symlink("private-key-jwt-client-auth.md", workspace.join(HIDDEN[2]))
        .unwrap();
    write(&workspace.join(HIDDEN[3]), page);
    write(&workspace.join(HIDDEN[4]), "MODE=1\n");
    write(&workspace.join(HIDDEN[5]), page);
    git(workspace, &["init", "-q"]);
    let mut add = vec!["add", "-f", PAGE];
    add.extend(&HIDDEN[1..]);
    git(workspace, &add);
}

/// A temporary repository from [`populate`], removed when the guard drops.
fn repository() -> (tempfile::TempDir, PathBuf) {
    let owner = tempfile::tempdir().unwrap();
    let root = owner.path().canonicalize().unwrap();
    populate(&root);
    (owner, root)
}

#[test]
fn only_the_committed_secret_free_page_is_reopened() {
    let (_owner, workspace) = repository();
    assert_eq!(
        sandbox_readable_documents(&workspace),
        [workspace.join(PAGE)]
    );
    // A subdirectory session reopens the same page, by the same path.
    assert_eq!(
        sandbox_readable_documents(&workspace.join("docs")),
        [workspace.join(PAGE)]
    );
}

#[test]
fn outside_a_repository_nothing_is_reopened() {
    let owner = tempfile::tempdir().unwrap();
    let root = owner.path().canonicalize().unwrap();
    write(&root.join(PAGE), "# private_key_jwt\n");
    assert!(sandbox_readable_documents(&root).is_empty());
    assert!(sandbox_readable_documents(Path::new("/nonexistent/guard")).is_empty());
}
