#![cfg(unix)]

//! A linked worktree created beside the session's checkout and reached with
//! `../`: committing in it, removing the dependency link placed in it, and
//! removing it again. Only a provable linked worktree of the session's own
//! repository gets the relative proof; any other sibling stays reviewed.

use crate::pretool_git_session_ops::{git, session, Session};
use std::path::{Path, PathBuf};

const LOCAL_WRITE: &str = "native_exact_safe_git_local_write";
const MAINTENANCE: &str = "native_exact_safe_worktree_maintenance";
const EVALUATION_FAILED: &str = "native_command_extension_evaluation_failed";

/// The session plus `org/report-wt`, a linked worktree of the cwd's
/// repository beside it, holding `reports/weekly.md` and a `node_modules`
/// link to the checkout's own dependencies.
fn report_worktree(label: &str) -> (Session, PathBuf) {
    let session = session(label);
    let worktree = session.org.join("report-wt");
    git(
        &session.home,
        &session.primary,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "weekly-report",
            worktree.to_str().unwrap(),
        ],
    );
    std::fs::create_dir_all(worktree.join("reports")).unwrap();
    std::fs::write(worktree.join("reports/weekly.md"), "# Weekly\n").unwrap();
    std::os::unix::fs::symlink(
        session.primary.join("node_modules"),
        worktree.join("node_modules"),
    )
    .unwrap();
    (session, worktree)
}

fn repository(session: &Session, directory: &Path) {
    std::fs::create_dir_all(directory).unwrap();
    git(&session.home, directory, &["init", "--quiet", "-b", "main"]);
    git(
        &session.home,
        directory,
        &["config", "user.name", "Guard Fixture"],
    );
    git(
        &session.home,
        directory,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(directory.join("README.md"), "fixture\n").unwrap();
    git(&session.home, directory, &["add", "README.md"]);
    git(
        &session.home,
        directory,
        &["commit", "--quiet", "-m", "fixture"],
    );
}

fn verdict(session: &Session, command: &str) -> (String, String) {
    let result = session.evaluate_at(command, &session.primary);
    (result.minimum_action, result.reason_code)
}

fn assert_reviewed(session: &Session, command: &str) {
    let (action, reason) = verdict(session, command);
    assert!(
        !matches!(action.as_str(), "allow" | "warn"),
        "{command}: {action} {reason}"
    );
}

#[test]
fn committing_in_a_linked_worktree_beside_the_checkout_is_a_local_write() {
    let (session, _) = report_worktree("report-commit");
    let command = "cd ../report-wt && git add reports/weekly.md && git commit -m \"Add weekly report\" && git log --oneline -1 && git status --short";
    let (action, reason) = verdict(&session, command);
    assert!(
        (action == "allow" && reason == LOCAL_WRITE) || action == "sandbox-required",
        "{action} {reason}"
    );
    for command in [
        "cd ../report-wt && git add reports/weekly.md",
        "cd ../report-wt/ && git commit -m x",
    ] {
        let (action, reason) = verdict(&session, command);
        assert!(
            matches!(action.as_str(), "allow" | "sandbox-required"),
            "{command}: {action} {reason}"
        );
    }
    for command in [
        // Only a plain climb to the worktree root is proved.
        "cd ../report-wt/reports && git add weekly.md",
        "cd ../report-wt/../report-wt && git add reports/weekly.md",
        "cd .. && git status --short",
        // Other steps keep their own proofs.
        "cd ../report-wt && git add reports/weekly.md && rm -rf build",
        "cd ../report-wt && git commit -m x && git push origin weekly-report --force",
    ] {
        assert_reviewed(&session, command);
    }
}

#[test]
fn removing_the_dependency_link_before_committing_in_the_worktree_is_a_local_write() {
    let (session, worktree) = report_worktree("report-unlink-commit");
    for command in [
        "cd ../report-wt && rm node_modules && git add reports/weekly.md && git commit -m \"Add weekly report\" && git log --oneline -2",
        "cd ../report-wt/ && rm node_modules && git add reports/weekly.md && git commit -m x",
    ] {
        let (action, reason) = verdict(&session, command);
        assert!(
            (action == "allow" && reason == LOCAL_WRITE) || action == "sandbox-required",
            "{command}: {action} {reason}"
        );
    }
    std::fs::write(worktree.join("notes.txt"), "keep\n").unwrap();
    std::fs::write(worktree.join(".gitmodules"), "").unwrap();
    for name in [".gitattributes", ".hidden", "-f"] {
        std::os::unix::fs::symlink(session.primary.join("node_modules"), worktree.join(name))
            .unwrap();
    }
    let commit = "git add reports/weekly.md && git commit -m x";
    for command in [
        // Only a plain `rm` of one link in the worktree root, before any other step.
        format!("cd ../report-wt && rm -rf node_modules && {commit}"),
        format!("cd ../report-wt && rm -f node_modules && {commit}"),
        format!("cd ../report-wt && rm -- node_modules && {commit}"),
        format!("cd ../report-wt && rm node_modules notes.txt && {commit}"),
        format!("cd ../report-wt && rm notes.txt && {commit}"),
        format!("cd ../report-wt && rm reports && {commit}"),
        format!("cd ../report-wt && rm reports/weekly.md && {commit}"),
        format!("cd ../report-wt && rm missing && {commit}"),
        format!("cd ../report-wt && rm ./node_modules && {commit}"),
        format!("cd ../report-wt && rm -- -f && {commit}"),
        "cd ../report-wt && git add reports/weekly.md && rm node_modules && git commit -m x"
            .to_owned(),
        // Git's own names stay reviewed, links or not.
        format!("cd ../report-wt && rm .git && {commit}"),
        format!("cd ../report-wt && rm .git/config && {commit}"),
        format!("cd ../report-wt && rm .gitmodules && {commit}"),
        format!("cd ../report-wt && rm .gitattributes && {commit}"),
        format!("cd ../report-wt && rm .hidden && {commit}"),
        // Each step must run only after the one before it succeeded.
        format!("cd ../report-wt; rm node_modules && {commit}"),
        format!("cd ../report-wt && rm node_modules; {commit}"),
        format!("cd ../report-wt && rm node_modules || {commit}"),
        // The `cd` must enter the worktree root itself.
        format!("cd ../report-wt/reports && rm ../node_modules && {commit}"),
        format!("rm node_modules && cd ../report-wt && {commit}"),
    ] {
        assert_reviewed(&session, &command);
    }
}

#[test]
fn siblings_that_are_not_linked_worktrees_of_the_session_stay_reviewed() {
    let (session, worktree) = report_worktree("report-siblings");
    // A sibling repository with its own `.git` directory.
    repository(&session, &session.org.join("other"));
    // A worktree of that other repository.
    let foreign = session.org.join("other-wt");
    git(
        &session.home,
        &session.org.join("other"),
        &["worktree", "add", "--quiet", foreign.to_str().unwrap()],
    );
    std::os::unix::fs::symlink(
        session.primary.join("node_modules"),
        foreign.join("node_modules"),
    )
    .unwrap();
    // A directory whose `.git` is a symlink to the real worktree's gitfile.
    let linked_git = session.org.join("linked-git");
    std::fs::create_dir_all(&linked_git).unwrap();
    std::os::unix::fs::symlink(worktree.join(".git"), linked_git.join(".git")).unwrap();
    std::os::unix::fs::symlink(
        session.primary.join("node_modules"),
        linked_git.join("node_modules"),
    )
    .unwrap();
    // A symlinked spelling of the real worktree.
    std::os::unix::fs::symlink(&worktree, session.org.join("alias-wt")).unwrap();
    for name in ["other", "other-wt", "linked-git", "alias-wt"] {
        for command in [
            format!("cd ../{name} && git add README.md && git commit -m x"),
            format!("cd ../{name} && git status --short"),
            format!("rm ../{name}/node_modules"),
            format!("rm ../{name}/node_modules && git worktree remove ../report-wt"),
            format!("cd ../{name} && rm node_modules && git add README.md && git commit -m x"),
        ] {
            assert_reviewed(&session, &command);
        }
    }
    assert_reviewed(&session, "git worktree remove ../other-wt");
}

#[test]
fn removing_the_dependency_link_and_the_worktree_is_quiet() {
    let (session, _) = report_worktree("report-remove");
    let mut failures = Vec::new();
    for (command, reason) in [
        ("rm ../report-wt/node_modules", None),
        ("git worktree remove ../report-wt", Some(MAINTENANCE)),
        (
            "git worktree remove ../report-wt && git worktree list",
            Some(MAINTENANCE),
        ),
        (
            "git worktree remove ../report-wt && git branch -v",
            Some(MAINTENANCE),
        ),
        (
            "rm -f ../report-wt/node_modules && git worktree remove ../report-wt",
            Some(MAINTENANCE),
        ),
        (
            "rm ../report-wt/node_modules && git worktree remove ../report-wt && git worktree list && git branch -v",
            Some(MAINTENANCE),
        ),
    ] {
        let (action, code) = verdict(&session, command);
        if action != "allow" || reason.is_some_and(|reason| code != reason) {
            failures.push(format!("{command}: {action} {code}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    std::fs::write(session.org.join("report-wt/notes.txt"), "keep\n").unwrap();
    std::os::unix::fs::symlink(
        session.primary.join("node_modules"),
        session.org.join("report-wt/.hidden"),
    )
    .unwrap();
    for command in [
        // Only links are removed, never a file, a directory or a hidden name.
        "rm ../report-wt/notes.txt",
        "rm ../report-wt/reports",
        "rm -r ../report-wt/node_modules",
        "rm ../report-wt/.hidden",
        "rm -- -f ../report-wt/node_modules",
        "rm ../report-wt/node_modules -- -f",
        "rm ../report-wt/reports/../node_modules",
        // Every step runs only after the one before it succeeded.
        "rm ../report-wt/node_modules; git worktree remove ../report-wt",
        "rm ../report-wt/node_modules || git worktree remove ../report-wt",
        "git worktree remove --force ../report-wt && git worktree list",
        "git worktree remove ../report-wt && git worktree list | sh",
        "git worktree remove ../report-wt && git push origin main",
        "git worktree remove ../report-wt && npm test",
        "git worktree remove ../report-wt && cd .. && git branch -v",
    ] {
        assert_reviewed(&session, command);
    }
}

#[test]
fn creating_and_entering_a_worktree_through_pwd_is_judged_not_failed() {
    let session = session("report-create");
    let command = "git worktree add ../weekly-wt -b weekly && ln -s \"$(pwd)/node_modules\" ../weekly-wt/node_modules && cd ../weekly-wt && npm run report && cat reports/weekly.md && git status --short";
    let (action, reason) = verdict(&session, command);
    assert_ne!(action, "allow", "{reason}");
    assert_ne!(reason, EVALUATION_FAILED);
}

#[test]
fn listing_the_linked_worktree_beside_the_checkout_is_quiet() {
    let (session, _) = report_worktree("report-read");
    let listing = |path: &str| {
        guard_command::pretool::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name": "read", "tool_input": {"path": path}}),
            None,
            None,
            session.home.to_str(),
            session.primary.to_str(),
        )
    };
    for path in ["../report-wt", "../report-wt/"] {
        let result = listing(path);
        assert_eq!(
            result.minimum_action, "allow",
            "{path}: {}",
            result.reason_code
        );
    }
    repository(&session, &session.org.join("other"));
    std::os::unix::fs::symlink(session.org.join("report-wt"), session.org.join("alias-wt"))
        .unwrap();
    for path in [
        "..",
        "../other",
        "../alias-wt",
        "../report-wt/reports",
        "../report-wt/../other",
        "../../org/other",
    ] {
        let result = listing(path);
        assert_ne!(
            result.minimum_action, "allow",
            "{path}: {}",
            result.reason_code
        );
    }
}
