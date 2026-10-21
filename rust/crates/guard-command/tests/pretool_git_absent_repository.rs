//! `git -C <directory>` where Git's own discovery walk finds no repository.
//! The command can only print `fatal: not a git repository` — or, when the
//! directory is not there, the path it could not enter — so it reads nothing
//! and must not ask. Agents reach this shape while probing for a checkout
//! that a scratch or sibling directory may or may not hold.
//!
//! The target still has to land where the read screens already reach, because
//! the answer stays `fatal:` only while nobody else can turn that directory
//! into a repository first. A `..` spelling, a path outside home and the
//! owned temporary root, a hidden name and a symlink therefore keep the
//! review the route proofs give them.
//!
//! The fixture roots live below the shared temporary directory because
//! `CARGO_TARGET_TMPDIR` sits inside this repository, where the discovery
//! walk would find the repository's own `.git` and answer a different
//! question.
#![cfg(unix)]

use std::path::{Path, PathBuf};

use crate::git_helper_fixture as fixture;
use crate::pretool_home_layout_reads::{assert_decision, repository};

struct Scratch {
    _cleanup: fixture::FixtureCleanup,
    root: PathBuf,
}

fn scratch(name: &str) -> Scratch {
    let root = std::fs::canonicalize("/tmp").unwrap().join(format!(
        "guard-absent-repository-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    Scratch {
        _cleanup: fixture::FixtureCleanup(root.clone()),
        root: fixture::canonical_spelling(root),
    }
}

/// The declared home, carrying the configuration a developer machine has:
/// an LFS filter, a credential helper, a pager and an external diff driver.
/// None of it can run on a route that discovers no repository, because Git
/// dies in its own setup before it reads any of it, so the route is proved
/// without the configuration probe the same reads need inside a checkout.
fn home(root: &Path) -> PathBuf {
    let home = directory(root, "home");
    std::fs::write(
        home.join(".gitconfig"),
        "[core]\n\tpager = /nonexistent/pager\n\thooksPath = /nonexistent/hooks\n\
         [filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\
         \tprocess = git-lfs filter-process\n\trequired = true\n\
         [diff \"spelled\"]\n\tcommand = /nonexistent/difft\n\ttextconv = /nonexistent/strings\n\
         [credential]\n\thelper = osxkeychain\n",
    )
    .unwrap();
    home
}

fn directory(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn git_read_routed_to_a_directory_without_a_repository_is_allowed() {
    let scratch = scratch("plain");
    let home = home(&scratch.root);
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let plain = directory(&scratch.root, "home/Code/scratch-notes");
    // A plain directory below the shared temporary root, where agents leave
    // scratch work: owned by the home owner and writable by no one else.
    let temporary = directory(&scratch.root, "probe-notes");
    for command in [
        format!("git -C {} status --short", fixture::shell_word(&plain)),
        format!("git -C {} status", fixture::shell_word(&plain)),
        format!("git -C {} log --oneline -3", fixture::shell_word(&plain)),
        format!("git -C {} status --short", fixture::shell_word(&temporary)),
        "git -C ~/Code/scratch-notes diff --stat".to_owned(),
    ] {
        assert_decision(&workspace, &home, &command, true);
    }
}

#[test]
fn git_read_routed_to_a_missing_directory_is_allowed() {
    let scratch = scratch("missing");
    let home = home(&scratch.root);
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let missing = scratch.root.join("home/Code/not-cloned-yet");
    for command in [
        format!("git -C {} log --oneline -3", fixture::shell_word(&missing)),
        "git -C ~/Code/not-cloned-yet status --short".to_owned(),
        "git -C ~/not-cloned-yet/web status --short".to_owned(),
    ] {
        assert_decision(&workspace, &home, &command, true);
    }
}

/// Discovery finds the repository above a plain subdirectory, so the route
/// keeps that repository's answer: a checkout below a home dot-directory is
/// still reviewed, and so is every directory inside it.
#[test]
fn git_read_routed_below_a_reviewed_repository_is_still_reviewed() {
    let scratch = scratch("below");
    let home = home(&scratch.root);
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let hidden = directory(&scratch.root, "home/.config-repo");
    repository(&hidden);
    let below = directory(&scratch.root, "home/.config-repo/notes");
    for command in [
        format!("git -C {} status --short", fixture::shell_word(&hidden)),
        format!("git -C {} log --oneline -1", fixture::shell_word(&below)),
    ] {
        assert_decision(&workspace, &home, &command, false);
    }
}

/// A directory that holds no repository is still only read where the read
/// screens reach: not through `..`, not outside home and the owned temporary
/// root, not under a hidden name, and not through a symlink.
#[test]
fn git_read_routed_outside_the_read_screens_stays_reviewed() {
    let scratch = scratch("screened");
    let home = home(&scratch.root);
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let hidden = directory(&scratch.root, "home/.scratch-notes");
    let plain = directory(&scratch.root, "home/Code/scratch-notes");
    let link = scratch.root.join("home/Code/linked-notes");
    std::os::unix::fs::symlink(&plain, &link).unwrap();
    for command in [
        "git -C .. status --short".to_owned(),
        "git -C ../scratch-notes log --oneline -1".to_owned(),
        format!("git -C {} status --short", fixture::shell_word(&hidden)),
        format!("git -C {} status --short", fixture::shell_word(&link)),
        "git -C /usr/share status --short".to_owned(),
        "git -C ~/.scratch-notes/draft status --short".to_owned(),
    ] {
        assert_decision(&workspace, &home, &command, false);
    }
}

/// Git discovers a bare repository implicitly: a directory holding `HEAD`,
/// `objects` and `refs` is a repository with no `.git` entry anywhere above
/// it. A route into one, or into any directory inside it, keeps the
/// repository route's proofs rather than passing as a plain directory.
#[test]
fn git_read_routed_into_a_bare_repository_is_still_reviewed() {
    let scratch = scratch("bare");
    let home = home(&scratch.root);
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let bare = scratch.root.join("home/Code/mirror.git");
    let status = std::process::Command::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(&bare)
        .status()
        .unwrap();
    assert!(status.success());
    for command in [
        format!("git -C {} log -p", fixture::shell_word(&bare)),
        "git -C ~/Code/mirror.git show HEAD".to_owned(),
        format!("git -C {}/refs log -1", fixture::shell_word(&bare)),
    ] {
        assert_decision(&workspace, &home, &command, false);
    }
}

/// A symlinked spelling clears the literal screen: `docs/.` names nothing
/// sensitive, but Git enters the directory the link points at.
#[test]
fn git_read_routed_through_a_link_to_a_sensitive_directory_is_reviewed() {
    let scratch = scratch("linked");
    let home = home(&scratch.root);
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let ssh = directory(&scratch.root, "home/.ssh");
    std::fs::write(ssh.join("config"), "Host fixture\n").unwrap();
    std::os::unix::fs::symlink(&ssh, workspace.join("docs")).unwrap();
    for command in [
        "git -C docs status --short",
        "git -C docs/. status --short",
        "git -C docs/. diff --no-index config /dev/null",
    ] {
        assert_decision(&workspace, &home, command, false);
    }
}

/// Outside a repository a few read subcommands still open files: `diff`
/// compares two paths, `grep` searches under `grep.fallbackToNoIndex`, and
/// `apply` and `hash-object` read their operands. Those operands resolve
/// against the `-C` directory, which no repository proof has screened.
#[test]
fn git_read_that_opens_files_without_a_repository_is_reviewed() {
    let scratch = scratch("reads");
    let home = home(&scratch.root);
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let plain = directory(&scratch.root, "home/Code/scratch-notes");
    std::fs::write(plain.join("notes.txt"), "fixture\n").unwrap();
    let route = fixture::shell_word(&plain);
    for command in [
        format!("git -C {route} diff notes.txt /dev/null"),
        format!("git -C {route} diff --no-index notes.txt /dev/null"),
        format!("git -C {route} diff --stat -- notes.txt /dev/null"),
        format!("git -C {route} grep -n fixture"),
        format!("git -C {route} hash-object notes.txt"),
        format!("git -C {route} apply --check notes.txt"),
    ] {
        assert_decision(&workspace, &home, &command, false);
    }
}

/// Git reads its global and system configuration before it looks for a
/// repository, so an inline `-c` can name a pager or an alias that runs
/// whatever the route. The route alone does not clear such a read.
#[test]
fn git_read_with_inline_configuration_without_a_repository_is_reviewed() {
    let scratch = scratch("inline-config");
    let home = home(&scratch.root);
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let plain = directory(&scratch.root, "home/Code/scratch-notes");
    let route = fixture::shell_word(&plain);
    for command in [
        format!("git -C {route} -c core.pager=./page.sh log --oneline -3"),
        format!("git -c core.pager=./page.sh -C {route} status --short"),
    ] {
        assert_decision(&workspace, &home, &command, false);
    }
}
