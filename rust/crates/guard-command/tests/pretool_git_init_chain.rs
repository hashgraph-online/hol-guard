#![cfg(unix)]

//! A scratch repository made, written and committed in one `&&` chain is
//! quiet when the new directory is fresh and below a temporary directory only
//! the user can write, and the chain only prints, stages and commits there
//! with no configured program or hook. A planted or shared location, another
//! step, a `-c` setting beyond the identity or a hidden file keeps the review.

use crate::git_helper_fixture::FixtureCleanup;
use crate::pretool_git_session_ops::{git, session, Session};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const CHAIN: &str = "native_exact_safe_git_init_chain";

fn unique(label: &str) -> String {
    format!(
        "guard-init-chain-{label}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    )
}

/// An owned 0700 directory directly in `/tmp`.
fn owned_parent() -> (PathBuf, FixtureCleanup) {
    let parent = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(unique("parent"));
    let cleanup = FixtureCleanup(parent.clone());
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    (parent, cleanup)
}

fn allowed(session: &Session, command: &str, cwd: &Path) -> Result<(), String> {
    let result = session.evaluate_at(command, cwd);
    (result.minimum_action == "allow" && result.reason_code == CHAIN)
        .then_some(())
        .ok_or(format!("{command}: {}", result.reason_code))
}

/// As [`allowed`], with the shell's HOME known to be (or not be) the session
/// home Git expands `~/` from.
fn allowed_home(session: &Session, command: &str, shell_home_matches: bool) -> Result<(), String> {
    let result = crate::git_helper_fixture::evaluate_with_shell_home(
        "codex",
        "PreToolUse",
        &serde_json::json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&crate::pretool_git_session_ops::default_controls()),
        None,
        session.home.to_str(),
        session.org.to_str(),
        shell_home_matches,
    );
    (result.minimum_action == "allow" && result.reason_code == CHAIN)
        .then_some(())
        .ok_or(format!("{command}: {}", result.reason_code))
}

#[test]
fn a_scratch_repository_made_and_committed_in_one_chain_is_quiet() {
    let session = session("init-chain");
    let (parent, _cleanup) = owned_parent();
    let scratch = parent.join("guard-scratch");
    let s = scratch.display();
    let init = format!("git init -q {s} && cd {s}");
    let commit = format!(
        "{init} && echo hi > a.txt && git add a.txt && git -c user.name=t -c user.email=t@t commit -qm test"
    );
    for cwd in [&session.org, &session.primary] {
        allowed(&session, &commit, cwd).unwrap();
    }
    for rest in [
        "printf 'x\\n' > notes.md && git add -A && git commit -m init",
        "git add . && git commit --author='A <a@example.test>' -m x",
    ] {
        allowed(&session, &format!("{init} && {rest}"), &session.org).unwrap();
    }

    let commit_tail = "git add a.txt && git commit -qm test";
    for command in [
        format!("{init} && echo hi > .gitattributes && git add . && git commit -qm test"),
        format!("{init} && echo hi > ../a.txt && {commit_tail}"),
        format!("{init} && echo hi > /tmp/a.txt && {commit_tail}"),
        format!("{init} && echo hi > a.txt && git add -f a.txt && git commit -qm test"),
        format!("{init} && echo hi > a.txt && git -c core.hooksPath=/tmp/h commit -qm test"),
        format!("{init} && echo hi > a.txt && git -c gpg.program=/tmp/g commit -qm test"),
        format!("{init} && echo hi > a.txt && git add a.txt && git commit -S -m test"),
        format!("{init} && echo hi > a.txt && {commit_tail} && git push origin main"),
        format!("{init} && echo hi > a.txt && {commit_tail} && rm -rf ~/x"),
        format!("{init}; echo hi > a.txt && {commit_tail}"),
        format!("git init -q {s}; cd {s} && {commit_tail}"),
        format!(
            "git init -q --template={parent} {s} && cd {s} && {commit_tail}",
            parent = parent.display()
        ),
        format!("git init --bare {s} && cd {s} && {commit_tail}"),
        format!(
            "git init -q {s} && cd {parent} && {commit_tail}",
            parent = parent.display()
        ),
        format!("{init} && echo $(id) > a.txt && {commit_tail}"),
    ] {
        assert!(
            allowed(&session, &command, &session.org).is_err(),
            "{command}"
        );
    }

    // Directly in the shared temporary root another user could create the
    // directory first.
    let shared = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(unique("shared"));
    let _shared = FixtureCleanup(shared.clone());
    let leaf = shared.display();
    let shared_commit =
        format!("git init -q {leaf} && cd {leaf} && echo hi > a.txt && {commit_tail}");
    assert!(allowed(&session, &shared_commit, &session.org).is_err());

    // A directory that already holds files, and settings that start a program
    // or configure the new repository.
    std::fs::create_dir(&scratch).unwrap();
    std::fs::write(scratch.join("planted"), "x\n").unwrap();
    assert!(allowed(&session, &commit, &session.org).is_err());
    std::fs::remove_dir_all(&scratch).unwrap();
    allowed(&session, &commit, &session.org).unwrap();
    let global = |arguments: &[&str]| {
        let mut full = vec!["config", "--global"];
        full.extend_from_slice(arguments);
        git(&session.home, &session.home, &full);
    };
    for (key, value) in [
        ("core.hooksPath", "/tmp/hooks"),
        ("init.templateDir", "/tmp/template"),
        ("hook.pre-commit.command", "id"),
        ("commit.gpgSign", "true"),
        ("core.fsmonitor", "id"),
    ] {
        global(&[key, value]);
        assert!(allowed(&session, &commit, &session.org).is_err(), "{key}");
        global(&["--unset-all", key]);
    }
    allowed(&session, &commit, &session.org).unwrap();

    // A developer's global hooks directory with no executable hook in it is
    // inert; an executable hook there, or a relative spelling, is not.
    let hooks = session.home.join(".config/git/hooks");
    for (value, ready) in [
        ("~/.config/git/hooks", false),
        ("~/.config/git/hooks", true),
    ] {
        if ready {
            std::fs::create_dir_all(&hooks).unwrap();
            std::fs::write(hooks.join("pre-commit.sample"), "#!/bin/sh\n").unwrap();
        }
        global(&["core.hooksPath", value]);
        allowed_home(&session, &commit, true).unwrap();
        // Git expands `~/` from the shell's HOME, which must be the home checked.
        assert!(allowed_home(&session, &commit, false).is_err());
    }
    std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\nid\n").unwrap();
    std::fs::set_permissions(
        hooks.join("pre-commit"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(allowed(&session, &commit, &session.org).is_err());
    std::fs::remove_file(hooks.join("pre-commit")).unwrap();
    global(&["core.hooksPath", "hooks"]);
    assert!(allowed(&session, &commit, &session.org).is_err());
    global(&["--unset-all", "core.hooksPath"]);
}

#[test]
fn a_bare_relative_target_is_reviewed_while_cdpath_could_redirect_its_cd() {
    let session = session("init-chain-cdpath");
    let (parent, _cleanup) = owned_parent();
    let tail =
        "echo hi > a.txt && git add a.txt && git -c user.name=t -c user.email=t@t commit -qm x";
    let bare = format!("git init -q guard-scratch && cd guard-scratch && {tail}");
    assert!(allowed(&session, &bare, &parent).is_err(), "{bare}");
}
