#![cfg(unix)]

//! In a linked worktree, `git rebase <upstream>`, `git rebase --continue`
//! after a resolved conflict and a commit the agent signs with `-S` are local
//! writes when no rebase state or configuration names a program and the
//! signing program is the user's installed one. An `exec` step, a saved
//! strategy or signing key, the apply backend, `--skip`, `--abort` and a
//! repository or untrusted signing program keep the review.

use crate::pretool_git_session_ops::{executable_hook, git, session, Session};
use std::path::Path;

const WRITE: &str = "native_exact_safe_git_local_write";

/// Runs Git like the shared helper, without requiring success: a rebase that
/// stops on a conflict exits nonzero.
fn git_may_fail(home: &Path, directory: &Path, arguments: &[&str]) {
    std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_EDITOR", "true")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .args(arguments)
        .output()
        .unwrap();
}

/// The worktree branch and `main` both change `tracked.txt`; the worktree
/// then starts `git rebase <options> main`, which stops on that conflict
/// with one more commit to replay. The conflict is resolved and staged.
fn stopped_rebase(session: &Session, options: &[&str]) {
    let (home, tree) = (&session.home, &session.worktree);
    git_may_fail(home, tree, &["rebase", "--abort"]);
    git(home, tree, &["reset", "--quiet", "--hard", "main"]);
    std::fs::write(tree.join("tracked.txt"), "worktree\n").unwrap();
    git(home, tree, &["commit", "--quiet", "-am", "worktree change"]);
    std::fs::write(tree.join("later.txt"), "later\n").unwrap();
    git(home, tree, &["add", "later.txt"]);
    git(home, tree, &["commit", "--quiet", "-m", "later change"]);
    let primary = &session.primary;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::fs::write(primary.join("tracked.txt"), format!("main {stamp}\n")).unwrap();
    git(home, primary, &["commit", "--quiet", "-am", "main change"]);
    let mut arguments = vec!["rebase"];
    arguments.extend_from_slice(options);
    arguments.push("main");
    git_may_fail(home, tree, &arguments);
    assert!(
        rebase_state(session).join("git-rebase-todo").is_file(),
        "{options:?}"
    );
    std::fs::write(tree.join("tracked.txt"), "resolved\n").unwrap();
    git(home, tree, &["add", "tracked.txt"]);
}

fn rebase_state(session: &Session) -> std::path::PathBuf {
    session
        .primary
        .join(".git/worktrees/app-portal-fix/rebase-merge")
}

fn allowed(session: &Session, command: &str) -> Result<(), String> {
    let result = session.evaluate_at(command, &session.worktree);
    (result.minimum_action == "allow" && result.reason_code == WRITE)
        .then_some(())
        .ok_or(format!("{command}: {}", result.reason_code))
}

#[test]
fn rebase_continue_is_quiet_only_with_replay_steps_and_no_programs() {
    let session = session("rebase-continue");
    let resume = "git rebase --continue 2>&1 | tail -2; git status | head -3";
    stopped_rebase(&session, &[]);
    allowed(&session, resume).unwrap();
    allowed(&session, "git add tracked.txt && git rebase --continue").unwrap();
    for command in [
        "git rebase --skip",
        "git rebase --abort",
        "git rebase --quit",
        "git rebase --edit-todo",
        "git rebase --continue -x id",
        "git -c core.hooksPath=/tmp/hooks rebase --continue",
        "git rebase --continue; rm -rf build",
    ] {
        assert!(allowed(&session, command).is_err(), "{command}");
    }
    for (key, value) in [
        ("merge.custom.driver", "sh -c id"),
        ("core.editor", "sh -c id"),
        ("commit.gpgSign", "true"),
        ("hook.post-rewrite.command", "id"),
    ] {
        session.config(&[key, value]);
        assert!(allowed(&session, resume).is_err(), "{key}");
        session.config(&["--unset-all", key]);
    }
    allowed(&session, resume).unwrap();
    executable_hook(&session.primary.join(".git/hooks/post-rewrite"));
    assert!(allowed(&session, resume).is_err());
    std::fs::remove_file(session.primary.join(".git/hooks/post-rewrite")).unwrap();

    // Saved state that starts a program: an `exec` step, a merge strategy
    // and a signing key.
    for options in [&["-x", "true"][..], &["-s", "ort"], &["-S"]] {
        stopped_rebase(&session, options);
        assert!(allowed(&session, resume).is_err(), "{options:?}");
    }
    // An `exec` line the user adds to the todo list.
    stopped_rebase(&session, &[]);
    let todo = rebase_state(&session).join("git-rebase-todo");
    let steps = std::fs::read_to_string(&todo).unwrap();
    std::fs::write(&todo, format!("{steps}exec id\n")).unwrap();
    assert!(allowed(&session, resume).is_err());
    // No rebase in progress.
    git_may_fail(&session.home, &session.worktree, &["rebase", "--abort"]);
    assert!(allowed(&session, resume).is_err());
}

#[test]
fn starting_a_rebase_onto_a_local_ref_is_a_local_write() {
    let session = session("rebase-start");
    for command in [
        "git rebase main",
        "git rebase -q main",
        "git rebase main 2>&1 | tail -2",
        "git add tracked.txt && git commit -m 'fix: x' && git rebase main",
    ] {
        allowed(&session, command).unwrap();
    }
    // Options that run a program, replay somewhere else or write over the
    // working tree, and a second operand that checks a branch out first.
    for command in [
        "git rebase -i main",
        "git rebase --interactive main",
        "git rebase -x id main",
        "git rebase --exec=id main",
        "git rebase --onto main topic",
        "git rebase --root",
        "git rebase -s ort main",
        "git rebase -X theirs main",
        "git rebase -S main",
        "git rebase --autostash main",
        "git rebase main fix/report-lane",
        "git -c core.hooksPath=/tmp/hooks rebase main",
        "git rebase main; rm -rf build",
    ] {
        assert!(allowed(&session, command).is_err(), "{command}");
    }
    // Configuration that replays with `git am` and its own hooks, or that
    // names a program the replayed commits would start.
    for (key, value) in [
        ("rebase.backend", "apply"),
        ("merge.custom.driver", "sh -c id"),
        ("commit.gpgSign", "true"),
        ("hook.post-rewrite.command", "id"),
    ] {
        session.config(&[key, value]);
        assert!(allowed(&session, "git rebase main").is_err(), "{key}");
        session.config(&["--unset-all", key]);
    }
    session.config(&["rebase.backend", "merge"]);
    allowed(&session, "git rebase main").unwrap();
    session.config(&["--unset-all", "rebase.backend"]);
    executable_hook(&session.primary.join(".git/hooks/post-rewrite"));
    assert!(allowed(&session, "git rebase main").is_err());
    std::fs::remove_file(session.primary.join(".git/hooks/post-rewrite")).unwrap();
    // A rebase already in progress carries a saved todo list this form does
    // not read.
    stopped_rebase(&session, &[]);
    assert!(allowed(&session, "git rebase main").is_err());
    git_may_fail(&session.home, &session.worktree, &["rebase", "--abort"]);
    allowed(&session, "git rebase main").unwrap();
}

#[test]
fn signed_commits_need_the_users_installed_signing_program() {
    let session = session("signed-commit");
    let home = &session.home;
    let global = |arguments: &[&str]| {
        let mut full = vec!["config", "--global"];
        full.extend_from_slice(arguments);
        git(home, home, &full);
    };
    // `ssh-keygen` is installed on every host these tests run on.
    global(&["gpg.format", "ssh"]);
    for command in [
        "git commit --amend --no-edit -S; git log -1",
        "git commit -S -m 'fix: x'",
        "git commit --gpg-sign -m x",
        "git commit --amend --no-edit --gpg-sign=ABCDEF",
    ] {
        allowed(&session, command).unwrap();
    }
    // The repository may not choose the program, its format or the key.
    for (key, value) in [
        ("gpg.ssh.program", "/usr/bin/ssh-keygen"),
        ("gpg.format", "openpgp"),
        ("gpg.program", "/tmp/gpg"),
    ] {
        session.config(&[key, value]);
        assert!(allowed(&session, "git commit -S -m x").is_err(), "{key}");
        session.config(&["--unset-all", key]);
    }
    // A key command runs a program, and a program below home is the
    // workspace's to change.
    let local = home.join("bin/ssh-keygen");
    executable_hook(&local);
    for (key, value) in [
        ("gpg.ssh.defaultKeyCommand", "ssh-add -L"),
        ("gpg.ssh.program", local.to_str().unwrap()),
        ("gpg.ssh.program", "~/bin/ssh-keygen"),
        ("gpg.format", "pkcs7"),
    ] {
        global(&[key, value]);
        assert!(allowed(&session, "git commit -S -m x").is_err(), "{key}");
        global(&["--unset-all", key]);
        global(&["gpg.format", "ssh"]);
    }
    allowed(&session, "git commit -S -m x").unwrap();
    assert!(allowed(&session, "git -c gpg.ssh.program=/tmp/x commit -S -m x").is_err());
}

#[test]
fn commit_signing_by_default_only_holds_writes_that_create_commits() {
    let session = session("gpgsign-default");
    let home = &session.home;
    let global = |arguments: &[&str]| {
        let mut full = vec!["config", "--global"];
        full.extend_from_slice(arguments);
        git(home, home, &full);
    };
    global(&["commit.gpgsign", "true"]);
    // Staging and starting a branch sign nothing, whatever the signing setup.
    session.config(&["gpg.program", "/tmp/gpg"]);
    for command in ["git add tracked.txt", "git switch -c gpgsign-probe"] {
        allowed(&session, command).unwrap();
    }
    // A commit signs as if asked with `-S`, so the repository may not pick
    // the program.
    assert!(allowed(&session, "git commit -m x").is_err());
    session.config(&["--unset-all", "gpg.program"]);
    global(&["gpg.format", "ssh"]);
    allowed(&session, "git commit -m x").unwrap();
    global(&["gpg.ssh.program", "/tmp/gpg"]);
    assert!(allowed(&session, "git commit -m x").is_err());
}
