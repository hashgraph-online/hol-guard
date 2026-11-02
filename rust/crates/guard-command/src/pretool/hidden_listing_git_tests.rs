//! What the repository's administrative tree is never read as content: the
//! `.git` directory itself, whatever a gitfile or a symlink points at, and
//! the guarded names that sit beside it.

use super::*;

#[test]
fn the_administrative_tree_and_guarded_names_keep_their_review() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    for document in [
        // The repository's own administrative tree is not its content: this
        // script carries the author of the commit being rebased.
        ".git/worktrees/fix/rebase-merge/author-script.sh",
        ".git/config.toml",
        // An environment file is never a document, whatever it is named.
        ".config/.env.production.json",
        ".envrc/settings.json",
        // A credential store and a harness home stay guarded.
        ".ssh/config.toml",
        ".aws/config.json",
        // A directory classified as a credential store keeps its review even
        // when the file in it is named as source: `credential_named_path`
        // stands aside for a source extension, so the directory half of the
        // screen has to be applied in its own right.
        ".secrets/read.py",
        // A tool's own tree is not the repository's content, however the file
        // in it is spelled, and neither is a login file under a directory the
        // repository does own.
        ".cursor/mcp.json",
        ".next/mcp.json",
        // A hidden leaf is that tool's own file wherever it sits, so the whole
        // login screen still applies to it.
        ".next/.claude.json",
        ".github/id_ed25519.json",
        // A directory spelled like an ordinary project config file opens no
        // hidden tree; the name is benign as the final component only.
        ".dockerignore/notes.md",
        // A name without a document extension is bytes of some other kind.
        ".codex-plugin/runtime.bin",
    ] {
        plant(&repo.join(document), "x\n");
        assert!(!read(&repo.join(document), &home, &repo), "{document}");
    }
    // A hidden file at the leaf of the work tree is not a document below a
    // hidden directory. It is read under `hidden_project_document`, which
    // screens the name for a tool's login; this rule must not reach past it,
    // and the names that screen holds stay held.
    for document in [".mcp.json", ".claude.json"] {
        plant(&repo.join(document), "x\n");
        assert!(!read(&repo.join(document), &home, &repo), "{document}");
    }
    // A hidden directory in a plain folder that is no checkout keeps its
    // review: the proof is the work tree, not the dot in the name.
    let plain = home.join("plain");
    plant(&plain.join(".codex-plugin/plugin.json"), "{}\n");
    assert!(!read(
        &plain.join(".codex-plugin/plugin.json"),
        &home,
        &plain
    ));
    // A sibling checkout's hidden tree is not the session's own content: the
    // same manifest reads from the checkout the session is working in and
    // keeps its review from the one beside it.
    let sibling = home.join("app-fix");
    std::fs::create_dir_all(sibling.join(".git")).unwrap();
    plant(&sibling.join(".codex-plugin/plugin.json"), "{}\n");
    assert!(!read(
        &sibling.join(".codex-plugin/plugin.json"),
        &home,
        &repo
    ));
    assert!(read(
        &sibling.join(".codex-plugin/plugin.json"),
        &home,
        &sibling
    ));
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn a_link_does_not_borrow_the_proof_for_the_administrative_tree() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    plant(&repo.join(".git/config.toml"), "[remote]\n");
    std::fs::create_dir_all(repo.join(".codex-plugin")).unwrap();
    std::os::unix::fs::symlink(
        repo.join(".git/config.toml"),
        repo.join(".codex-plugin/plugin.json"),
    )
    .unwrap();
    // The rule reads the resolved path, so a document name in a hidden
    // directory the repository owns cannot stand in for the `.git` tree.
    assert!(!read(&repo.join(".codex-plugin/plugin.json"), &home, &repo));
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn an_administrative_directory_named_by_a_gitfile_keeps_its_review() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    // `git init --separate-git-dir` puts the administrative directory inside
    // the work tree under a name of its own, so the hook bodies and remote
    // URLs in it are reachable by a path that never spells `.git`. The
    // pointer names that directory, and naming it is what holds the read.
    std::fs::create_dir_all(repo.join(".vcs-meta/hooks")).unwrap();
    std::fs::write(repo.join(".git"), "gitdir: .vcs-meta\n").unwrap();
    plant(&repo.join(".vcs-meta/hooks/pre-commit.sh"), "#!/bin/sh\n");
    assert!(!read(
        &repo.join(".vcs-meta/hooks/pre-commit.sh"),
        &home,
        &repo
    ));
    // Repository content beside it still reads quietly.
    plant(&repo.join(".codex-plugin/plugin.json"), "{}\n");
    assert!(read(&repo.join(".codex-plugin/plugin.json"), &home, &repo));
    std::fs::remove_dir_all(root).unwrap();
}
/// A `.git` symlink points at the administrative directory just as a gitfile
/// names it, and the canonical read path then spells the target rather than
/// `.git`, so the component screen never sees it. Creating the link needs a
/// POSIX symlink, so the proof is Unix-only; the rule itself resolves the link
/// on every platform.
#[cfg(unix)]
#[test]
fn an_administrative_directory_a_git_symlink_points_at_keeps_its_review() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    std::fs::create_dir_all(repo.join(".vcs-meta/hooks")).unwrap();
    std::os::unix::fs::symlink(".vcs-meta", repo.join(".git")).unwrap();
    plant(&repo.join(".vcs-meta/hooks/pre-commit.sh"), "#!/bin/sh\n");
    assert!(!read(
        &repo.join(".vcs-meta/hooks/pre-commit.sh"),
        &home,
        &repo
    ));
    // Repository content beside it still reads quietly.
    plant(&repo.join(".codex-plugin/plugin.json"), "{}\n");
    assert!(read(&repo.join(".codex-plugin/plugin.json"), &home, &repo));
    std::fs::remove_dir_all(root).unwrap();
}
/// A `.git` symlink this rule cannot resolve names an unknown administrative
/// directory, and an unknown one holds the read.
#[cfg(unix)]
#[test]
fn an_unresolvable_git_symlink_holds_a_hidden_read() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    std::fs::create_dir_all(repo.join(".codex-plugin")).unwrap();
    std::os::unix::fs::symlink("nowhere", repo.join(".git")).unwrap();
    plant(&repo.join(".codex-plugin/plugin.json"), "{}\n");
    assert!(!read(&repo.join(".codex-plugin/plugin.json"), &home, &repo));
    std::fs::remove_dir_all(root).unwrap();
}
