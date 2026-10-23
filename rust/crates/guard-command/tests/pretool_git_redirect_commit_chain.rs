#![cfg(unix)]

use crate::pretool_git_session_ops::{executable_hook, session};

const WRITE: &str = "native_exact_safe_git_local_write";

#[test]
fn a_workspace_file_written_then_committed_in_a_linked_worktree_is_quiet() {
    let session = session("redirect-commit");
    std::fs::create_dir_all(session.worktree.join("docs")).unwrap();
    // The workspace sandbox may run the chain in the worktree instead of
    // Git's write proof allowing it; either way it raises no review.
    let quiet = |command: &str| session.quiet_at(command, &session.worktree, WRITE);
    for command in [
        "echo x > notes.txt && git add -A && git commit -m init",
        "printf 'draft notes' > docs/notes.md && git add docs/notes.md && git commit -m 'docs: add notes'",
        "echo x >> notes.txt && git add notes.txt && git commit -q -m update",
    ] {
        quiet(command).unwrap();
    }
}

#[test]
fn hook_and_config_targets_publishing_and_outside_writes_stay_reviewed() {
    let session = session("redirect-commit-refused");
    let at_tree = |command: &str| session.evaluate_at(command, &session.worktree);
    let reviewed = |command: &str| {
        let result = at_tree(command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    };
    std::fs::create_dir_all(session.worktree.join(".husky")).unwrap();
    let outside = session.home.join("outside.txt");
    for target in [
        ".git/hooks/pre-commit",
        ".husky/pre-commit",
        ".git/config",
        ".gitattributes",
        ".envrc",
        "../outside.txt",
        "~/notes.txt",
        outside.to_str().unwrap(),
    ] {
        reviewed(&format!(
            "echo '* filter=strip' > {target} && git add -A && git commit -m init"
        ));
    }
    // An attribute that names a configured filter runs it on `git add`.
    session.config(&["filter.strip.clean", "sed -e s/x//"]);
    reviewed("echo '* filter=strip' > .gitattributes && git add -A && git commit -m init");
    session.config(&["--unset-all", "filter.strip.clean"]);
    for command in [
        "echo x > notes.txt && git add -A && git commit -m init && git push origin fix/report-lane",
        "echo x > notes.txt && git add -A && git -c core.hooksPath=hooks commit -m init",
        "echo x > notes.txt && git -C ../org/app-portal add -A && git commit -m init",
        "cat ~/.ssh/id_rsa > notes.txt && git add -A && git commit -m init",
        "cd docs && echo x > notes.txt && git add -A && git commit -m init",
        "echo x > notes.txt && git checkout main && git commit -am init",
    ] {
        reviewed(command);
    }
}

#[test]
fn writes_into_the_hooks_directory_or_an_included_file_stay_reviewed() {
    let session = session("redirect-commit-hooks");
    let at_tree = |command: &str| session.evaluate_at(command, &session.worktree);
    let allow_reason = |command: &str| {
        let result = at_tree(command);
        (result.minimum_action == "allow").then_some(result.reason_code)
    };
    let quiet = |command: &str| session.quiet_at(command, &session.worktree, WRITE);
    let chain = |target: &str| format!("echo x > {target} && git add -A && git commit -m init");
    std::fs::create_dir_all(session.worktree.join("hooks")).unwrap();
    session.config(&["core.hooksPath", "hooks"]);
    // Whether Git's proof allows the chain or the sandbox runs it in the
    // worktree, a write outside the hooks directory raises no review.
    quiet(&chain("notes.txt")).unwrap();
    for target in [
        "hooks/pre-commit",
        "Hooks/pre-commit",
        "./hooks/post-commit",
    ] {
        assert_eq!(allow_reason(&chain(target)), None, "{target}");
    }
    session.config(&["--unset-all", "core.hooksPath"]);
    // A program already installed as a hook keeps the commit reviewed.
    let hook = session.primary.join(".git/hooks/pre-commit");
    executable_hook(&hook);
    assert_eq!(allow_reason(&chain("notes.txt")), None);
    std::fs::remove_file(hook).unwrap();
    // The written file could be the configuration an include loads.
    session.config(&["include.path", "extra.inc"]);
    assert_eq!(allow_reason(&chain("extra.inc")), None);
    assert_eq!(allow_reason(&chain("notes.txt")), None);
    session.config(&["--unset-all", "include.path"]);
    quiet(&chain("notes.txt")).unwrap();
}
