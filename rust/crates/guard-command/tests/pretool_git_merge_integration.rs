#![cfg(unix)]

//! Bringing a checkout up to date: `git merge` of one revision, `git
//! cherry-pick` of named commits and `git pull origin <branch>` that may
//! write a merge commit, in a sibling repository behind `git -C` or after a
//! `sleep`. They stay quiet only while no hook, merge driver, configured
//! strategy, signing step or repository-chosen editor can run; every option
//! that picks a program or discards work keeps the review.

use crate::pretool_git_session_ops::{executable_hook, git, session, Session};
use std::path::PathBuf;

const LOCAL_WRITE: &str = "native_exact_safe_git_local_write";
const REFRESH: &str = "native_exact_safe_git_origin_refresh";

/// The session plus `org/service-api`, a sibling repository of the cwd.
fn sibling(label: &str) -> (Session, PathBuf) {
    let session = session(label);
    let service = session.org.join("service-api");
    std::fs::create_dir_all(&service).unwrap();
    let setup: [&[&str]; 3] = [
        &["init", "--quiet", "-b", "main"],
        &["config", "user.name", "Guard Fixture"],
        &["config", "user.email", "guard-fixture@example.invalid"],
    ];
    for arguments in setup {
        git(&session.home, &service, arguments);
    }
    std::fs::write(service.join("README.md"), "fixture\n").unwrap();
    git(&session.home, &service, &["add", "README.md"]);
    git(
        &session.home,
        &service,
        &["commit", "--quiet", "-m", "fixture"],
    );
    (session, service)
}

fn reason(session: &Session, command: &str, cwd: &std::path::Path) -> Option<String> {
    let result = session.evaluate_at(command, cwd);
    (result.minimum_action == "allow").then_some(result.reason_code)
}

fn assert_allowed(session: &Session, command: &str, cwd: &std::path::Path, expected: &str) {
    assert_eq!(
        reason(session, command, cwd).as_deref(),
        Some(expected),
        "{command}"
    );
}

fn assert_reviewed(session: &Session, command: &str, cwd: &std::path::Path) {
    assert_eq!(reason(session, command, cwd), None, "{command}");
}

fn configured(session: &Session, repository: &std::path::Path, key: &str, value: Option<&str>) {
    match value {
        Some(value) => git(&session.home, repository, &["config", key, value]),
        None => git(&session.home, repository, &["config", "--unset-all", key]),
    }
}

#[test]
fn sibling_merge_and_cherry_pick_behind_git_c_are_local_writes() {
    let (session, service) = sibling("merge-sibling");
    let cwd = session.primary.clone();
    let sib = service.display();
    for command in [
        format!("git -C {sib} merge origin/main --no-edit 2>&1 | tail -3"),
        format!("git -C {sib} merge FETCH_HEAD --no-edit"),
        format!("git -C {sib} merge origin/main"),
        format!("sleep 120; git -C {sib} merge origin/main --no-edit"),
        format!("sleep 300; git -C {sib} merge origin/main --no-edit 2>&1 | tail -4"),
        format!("git -C {sib} cherry-pick 36b51d1428 300395d837 64b5fdf03e 2>&1 | tail -4"),
        format!("sleep 420; git -C {sib} cherry-pick 36b51d1428 2>&1 | tail -2"),
        format!("git -C {sib} cherry-pick -x 36b51d1428"),
    ] {
        assert_allowed(&session, &command, &cwd, LOCAL_WRITE);
    }
    for command in [
        // A strategy runs `git-merge-<name>` from PATH; an option picks one.
        format!("git -C {sib} merge -s custom origin/main"),
        format!("git -C {sib} merge -X theirs origin/main"),
        format!("git -C {sib} merge origin/main feat/x"),
        format!("git -C {sib} merge --edit origin/main"),
        format!("git -C {sib} merge -S origin/main"),
        format!("git -C {sib} merge --abort"),
        format!("git -C {sib} cherry-pick -e 36b51d1428"),
        format!("git -C {sib} cherry-pick --continue"),
        format!("git -C {sib} cherry-pick --strategy=custom 36b51d1428"),
        format!("git -C {sib} -c merge.ff=false merge origin/main"),
        format!("GIT_EDITOR=/tmp/editor git -C {sib} merge origin/main"),
        // Neighbours that discard or rewrite work.
        format!("git -C {sib} reset --hard origin/main"),
        format!("git -C {sib} rebase origin/main"),
        format!("git -C {sib} checkout -- README.md"),
        // Steps other than Git run from the shell's directory.
        format!("git -C {sib} merge origin/main --no-edit && rm -rf build"),
        format!("sleep 120; git -C {sib} merge origin/main; bash run.sh"),
    ] {
        assert_reviewed(&session, &command, &cwd);
    }
}

#[test]
fn merge_stays_reviewed_when_configuration_or_hooks_can_start_a_program() {
    let (session, service) = sibling("merge-config");
    let cwd = session.primary.clone();
    let sib = service.display();
    let merge = format!("git -C {sib} merge origin/main --no-edit");
    let pick = format!("git -C {sib} cherry-pick 36b51d1428");
    assert_allowed(&session, &merge, &cwd, LOCAL_WRITE);
    for (key, value) in [
        ("merge.custom.driver", "sh -c id %O %A %B"),
        ("pull.twohead", "custom"),
        ("pull.octopus", "custom"),
        ("branch.main.mergeoptions", "-s custom"),
        ("merge.verifySignatures", "true"),
        ("gpg.program", "/tmp/gpg"),
        ("commit.gpgsign", "true"),
        ("core.editor", "/tmp/editor"),
        ("sequence.editor", "/tmp/editor"),
        ("filter.fixture.smudge", "id"),
        ("core.fsmonitor", "/tmp/monitor"),
        ("hook.post-merge.command", "id"),
    ] {
        configured(&session, &service, key, Some(value));
        assert_reviewed(&session, &merge, &cwd);
        assert_reviewed(&session, &pick, &cwd);
        configured(&session, &service, key, None);
    }
    assert_allowed(&session, &pick, &cwd, LOCAL_WRITE);
    for hook in [
        "pre-merge-commit",
        "prepare-commit-msg",
        "commit-msg",
        "post-commit",
        "post-merge",
        "post-rewrite",
        "reference-transaction",
    ] {
        let path = service.join(".git/hooks").join(hook);
        executable_hook(&path);
        assert_reviewed(&session, &merge, &cwd);
        assert_reviewed(&session, &pick, &cwd);
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn merge_pull_from_origin_is_a_proven_refresh_without_commit_programs() {
    let session = session("merge-pull");
    let cwd = session.org.clone();
    let primary = session.primary.display();
    let pull = format!("git -C {primary} pull origin main --no-edit");
    let fast_forward = format!("git -C {primary} pull --ff-only origin main");
    let last_no_ff = format!("git -C {primary} pull --ff-only --no-ff origin main");
    let last_ff_only = format!("git -C {primary} pull --no-ff --ff-only origin main");
    for command in [
        pull.clone(),
        format!("git -C {primary} pull origin main --no-edit 2>&1 | tail -3"),
        format!("sleep 300; git -C {primary} pull origin main --no-edit"),
        format!("git -C {primary} pull --no-rebase origin main"),
    ] {
        assert_allowed(&session, &command, &cwd, REFRESH);
    }
    for command in [
        format!("git -C {primary} pull --rebase origin main"),
        format!("git -C {primary} pull -s custom origin main"),
        format!("git -C {primary} pull -X theirs origin main"),
        format!("git -C {primary} pull --edit origin main"),
        format!("git -C {primary} pull origin main feat/x"),
        format!("git -C {primary} pull evil main --no-edit"),
    ] {
        assert_reviewed(&session, &command, &cwd);
    }
    for (key, value) in [
        ("merge.custom.driver", "sh -c id %O %A %B"),
        ("pull.twohead", "custom"),
        ("branch.main.mergeoptions", "-s custom"),
        ("commit.gpgsign", "true"),
        ("core.editor", "/tmp/editor"),
    ] {
        session.config(&[key, value]);
        assert_reviewed(&session, &pull, &cwd);
        session.config(&["--unset-all", key]);
    }
    // A fast-forward writes no commit, so a commit hook keeps only the merge
    // pull reviewed.
    for hook in ["pre-merge-commit", "prepare-commit-msg", "commit-msg"] {
        let path = session.primary.join(".git/hooks").join(hook);
        executable_hook(&path);
        assert_reviewed(&session, &pull, &cwd);
        assert_allowed(&session, &fast_forward, &cwd, REFRESH);
        assert_allowed(&session, &last_ff_only, &cwd, REFRESH);
        assert_reviewed(&session, &last_no_ff, &cwd);
        std::fs::remove_file(path).unwrap();
    }
    assert_allowed(&session, &pull, &cwd, REFRESH);
}

/// The user configuration a Git LFS install, a GPG setup and a shared hooks
/// directory leave behind.
const USER_CONFIG: &str = "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\
    \tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\
    \trequired = true\n[gpg]\n\tprogram = gpg\n[core]\n\thooksPath = ~/.config/git/hooks\n";

#[test]
fn pulls_stay_refreshes_under_the_users_own_gpg_program() {
    let session = session("merge-pull-user-gpg");
    let cwd = session.org.clone();
    let primary = session.primary.display();
    let pull = format!("git -C {primary} pull origin main --no-edit");
    let fast_forward = format!("git -C {primary} pull --ff-only origin main");
    let global = session.home.join(".gitconfig");
    std::fs::create_dir_all(session.home.join(".config/git/hooks")).unwrap();
    std::fs::write(&global, USER_CONFIG).unwrap();
    // The program runs only when Git signs or checks a signature.
    assert_allowed(&session, &pull, &cwd, REFRESH);
    assert_allowed(&session, &fast_forward, &cwd, REFRESH);
    // A program the repository picks keeps both reviewed.
    session.config(&["gpg.program", "/tmp/gpg"]);
    assert_reviewed(&session, &pull, &cwd);
    assert_reviewed(&session, &fast_forward, &cwd);
    session.config(&["--unset-all", "gpg.program"]);
    // Signing the merge commit keeps the merge pull reviewed; a fast-forward
    // writes no commit.
    std::fs::write(
        &global,
        format!("{USER_CONFIG}[commit]\n\tgpgsign = true\n"),
    )
    .unwrap();
    assert_reviewed(&session, &pull, &cwd);
    assert_allowed(&session, &fast_forward, &cwd, REFRESH);
    // A signature check runs the program on every pull.
    std::fs::write(
        &global,
        format!("{USER_CONFIG}[merge]\n\tverifySignatures = true\n"),
    )
    .unwrap();
    assert_reviewed(&session, &pull, &cwd);
    assert_reviewed(&session, &fast_forward, &cwd);
}
