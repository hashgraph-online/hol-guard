#![cfg(unix)]
//! A dependency link between a checkout and a separate clone of the same
//! repository stays quiet, as it does between a checkout and its linked
//! worktree. A clone is told apart by the remote URLs both configurations
//! name, so an unrelated repository, a different remote, a hidden or file
//! target and an existing name keep their review.
//!
//! The reviewed cases run from the original checkout, so the link sits outside
//! the working directory. A link inside the working directory is admitted by
//! the older workspace link rule for any readable source, whatever its owner.

use crate::pretool_git_session_ops::{git, session, Session};
use std::path::{Path, PathBuf};

fn action(session: &Session, command: &str, cwd: &Path) -> String {
    session.evaluate_at(command, cwd).minimum_action
}

fn origin(session: &Session, repository: &Path, url: &str) {
    git(&session.home, repository, &["remote", "add", "origin", url]);
}

fn set_origin(session: &Session, repository: &Path, url: &str) {
    git(
        &session.home,
        repository,
        &["remote", "set-url", "origin", url],
    );
}

/// `home/org/app-portal-clone`, a `git clone` of the primary checkout.
fn local_clone(session: &Session) -> PathBuf {
    let clone = session.org.join("app-portal-clone");
    git(
        &session.home,
        &session.home,
        &[
            "clone",
            "--quiet",
            session.primary.to_str().unwrap(),
            clone.to_str().unwrap(),
        ],
    );
    std::fs::create_dir_all(clone.join("node_modules/pkg")).unwrap();
    clone
}

/// A fresh repository outside `org` that names `url` as its origin, the shape
/// a second clone of the hosted repository has.
fn repository_with_origin(session: &Session, name: &str, url: &str) -> PathBuf {
    let repository = session.home.join(name);
    std::fs::create_dir_all(&repository).unwrap();
    git(
        &session.home,
        &repository,
        &["init", "--quiet", "-b", "main"],
    );
    origin(session, &repository, url);
    repository
}

#[test]
fn dependency_link_into_a_local_clone_is_quiet_from_either_checkout() {
    let session = session("clone-link-local");
    let clone = local_clone(&session);
    let primary = session.primary.display();
    let clone_text = clone.display();
    for cwd in [&session.org, &session.primary, &clone] {
        for command in [
            format!("ln -s {primary}/node_modules {clone_text}/deps"),
            format!("ln -s {clone_text}/node_modules {primary}/deps"),
            format!(
                "ln -s {primary}/node_modules {clone_text}/deps && ls -la {clone_text}/ | grep deps"
            ),
        ] {
            assert_eq!(action(&session, &command, cwd), "allow", "{command}");
        }
    }
}

#[test]
fn dependency_link_into_a_clone_beside_the_checkout_needs_no_shared_parent() {
    let session = session("clone-link-sibling");
    let clone = session.home.join("app-portal-clone");
    git(
        &session.home,
        &session.home,
        &[
            "clone",
            "--quiet",
            session.primary.to_str().unwrap(),
            clone.to_str().unwrap(),
        ],
    );
    let primary = session.primary.display();
    let clone_text = clone.display();
    std::fs::create_dir_all(clone.join("vendor")).unwrap();
    for cwd in [&session.primary, &clone] {
        for command in [
            format!("ln -s {primary}/node_modules {clone_text}/node_modules"),
            format!("ln -s {clone_text}/vendor {primary}/vendor"),
        ] {
            assert_eq!(action(&session, &command, cwd), "allow", "{command}");
        }
    }
}

#[test]
fn dependency_link_between_clones_of_one_hosted_repository_is_quiet() {
    let session = session("clone-link-hosted");
    let remote = repository_with_origin(
        &session,
        "app-portal-remote",
        "https://github.com/example-org/app-portal.git",
    );
    let primary = session.primary.display();
    let remote_text = remote.display();
    for cwd in [&session.primary, &remote] {
        let command = format!("ln -s {primary}/node_modules {remote_text}/node_modules");
        assert_eq!(action(&session, &command, cwd), "allow", "{command}");
    }
}

#[test]
fn dependency_link_into_an_unrelated_repository_stays_reviewed() {
    let session = session("clone-link-unrelated");
    let primary = session.primary.display();
    let plain = repository_with_origin(
        &session,
        "plain",
        "https://github.com/example-org/other-app.git",
    );
    let bare = session.home.join("bare");
    std::fs::create_dir_all(&bare).unwrap();
    git(&session.home, &bare, &["init", "--quiet", "-b", "main"]);
    for repository in [&plain, &bare] {
        let name = repository.display();
        let command = format!("ln -s {primary}/node_modules {name}/node_modules");
        assert_ne!(
            action(&session, &command, &session.primary),
            "allow",
            "{command}"
        );
    }
}

#[test]
fn dependency_link_into_a_clone_keeps_every_other_boundary() {
    let session = session("clone-link-bounds");
    let clone = local_clone(&session);
    std::fs::write(clone.join("tracked-file.txt"), "x\n").unwrap();
    // A credential directory the link could name, so the screen below is
    // answering about a path that is really there.
    std::fs::create_dir_all(session.home.join(".ssh")).unwrap();
    let home = session.home.display();
    let primary = session.primary.display();
    let clone_text = clone.display();
    for command in [
        // Hidden, file and credential targets.
        format!("ln -s {primary}/.git {clone_text}/deps"),
        format!("ln -s {primary}/.git/hooks {clone_text}/deps"),
        format!("ln -s {primary}/tracked.txt {clone_text}/deps"),
        format!("ln -s {home}/.ssh {clone_text}/deps"),
        // The link is a fresh, visible name.
        format!("ln -s {primary}/node_modules {clone_text}/tracked-file.txt"),
        format!("ln -s {primary}/node_modules {clone_text}/.deps"),
        format!("ln -sf {primary}/node_modules {clone_text}/deps"),
        format!("ln -s {primary}/node_modules {clone_text}/node_modules/pkg/deps"),
        // A relative target still resolves to a screened path: one that
        // leaves the repositories the proof knows is refused like any other.
        format!("ln -s ../../.ssh {clone_text}/deps"),
        format!("ln -s ../app-portal/.git {clone_text}/deps"),
    ] {
        assert_ne!(
            action(&session, &command, &session.primary),
            "allow",
            "{command}"
        );
    }
    // A name that is already a directory is where `ln` writes the link, under
    // the target's own base name, and that name is free there.
    let command = format!("ln -s {primary}/node_modules {clone_text}/node_modules");
    assert_eq!(
        action(&session, &command, &session.primary),
        "allow",
        "{command}"
    );
    // A relative target resolves against the directory holding the new link,
    // so this names the same directory as the absolute spelling above and is
    // screened identically.
    let command = format!("ln -s ../app-portal/node_modules {clone_text}/deps");
    assert_eq!(
        action(&session, &command, &session.primary),
        "allow",
        "{command}"
    );
}

#[test]
fn matching_remote_urls_do_not_relate_checkouts_that_rewrite_or_include() {
    let session = session("clone-link-rewrite");
    let primary = session.primary.display();
    let url = "https://github.com/example-org/app-portal.git";
    for (name, extra) in [
        (
            "rewritten",
            "[url \"https://git.example.invalid/\"]\n\tinsteadOf = https://github.com/\n",
        ),
        (
            "pushrewritten",
            "[url \"https://git.example.invalid/\"]\n\tpushInsteadOf = https://github.com/\n",
        ),
        (
            "deprecated-header",
            "[url.evil]\n\tinsteadOf = https://github.com/\n",
        ),
        ("included", "[include]\n\tpath = ../shared.gitconfig\n"),
    ] {
        let repository = repository_with_origin(&session, name, url);
        let config = repository.join(".git/config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(extra);
        std::fs::write(&config, text).unwrap();
        let command = format!(
            "ln -s {primary}/node_modules {}/node_modules",
            repository.display()
        );
        assert_ne!(
            action(&session, &command, &session.primary),
            "allow",
            "{name}: {command}"
        );
    }
}

#[test]
fn relative_remote_paths_do_not_relate_checkouts() {
    let session = session("clone-link-relative");
    let primary = session.primary.display();
    for url in ["../upstream", "upstream", "./upstream"] {
        set_origin(&session, &session.primary, url);
        let other = repository_with_origin(&session, "other", url);
        let command = format!(
            "ln -s {primary}/node_modules {}/node_modules",
            other.display()
        );
        assert_ne!(
            action(&session, &command, &session.primary),
            "allow",
            "{url}: {command}"
        );
        std::fs::remove_dir_all(&other).unwrap();
    }
}

#[test]
fn scp_like_remote_urls_relate_checkouts() {
    let session = session("clone-link-scp");
    let url = "git@github.com:example-org/app-portal.git";
    set_origin(&session, &session.primary, url);
    let remote = repository_with_origin(&session, "app-portal-scp", url);
    let command = format!(
        "ln -s {}/node_modules {}/node_modules",
        session.primary.display(),
        remote.display()
    );
    assert_eq!(
        action(&session, &command, &session.primary),
        "allow",
        "{command}"
    );
}

#[test]
fn dependency_link_into_the_working_checkout_from_a_subdirectory_is_quiet() {
    let session = session("clone-link-subdirectory");
    let clone = local_clone(&session);
    let primary = session.primary.display();
    let clone_text = clone.display();
    std::fs::create_dir_all(clone.join("packages/web")).unwrap();
    std::fs::create_dir_all(session.primary.join("packages/web")).unwrap();
    for (cwd, command) in [
        (
            clone.join("packages/web"),
            format!("ln -s {primary}/node_modules {clone_text}/deps"),
        ),
        (
            session.primary.join("packages/web"),
            format!("ln -s {clone_text}/node_modules {primary}/deps"),
        ),
    ] {
        assert_eq!(action(&session, &command, &cwd), "allow", "{command}");
    }
}
