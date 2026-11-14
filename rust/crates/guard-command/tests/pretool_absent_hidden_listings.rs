#![cfg(unix)]

//! Listing a hidden directory that is not there.
//!
//! Agents probe for optional tool directories (`ls -la ~/.toolcfg`) before
//! they read anything out of one. The path does not exist, so the listing
//! prints `No such file or directory` and reads nothing at all, but the
//! absent-path proof refused every missing name that began with a dot --
//! `.git` and `.github` aside -- and sent the probe to review. Inside a
//! pipeline it took the whole command with it. What the probe may spell is
//! now what a listing of the same path would print if it did exist: one
//! hidden directory of the home directory, nothing hidden below it, and the
//! shared roots named only together with the tool directory under them. A
//! credential store stays refused, because the answer to a probe for one is
//! itself the account it keeps, and a dot-leaf anywhere else in the tree
//! keeps the review it always had.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_probe_for_a_hidden_directory_reads_nothing() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/absent-listing-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".config/toolcfg")).unwrap();
    std::fs::create_dir_all(root.join("work/src")).unwrap();
    let root = std::fs::canonicalize(&root).unwrap();
    std::fs::write(root.join(".config/toolcfg/config.yml"), "setting: 1\n").unwrap();
    std::fs::write(root.join("work/src/one.txt"), "ordinary fixture\n").unwrap();
    let home = root.to_str().unwrap();
    let cwd = root.join("work");
    let cwd = cwd.to_str().unwrap();
    for harness in ["omp", "zcode"] {
        for (command, allowed) in [
            ("ls -la ~/.config/toolcfg", true),
            ("ls -la ~/.toolcfg", true),
            ("ls ~/.toolcfg", true),
            ("ls -la ~/.codex", true),
            ("ls -la ~/plain-name", true),
            (
                "ls -la ~/.config/toolcfg | head; ls -la ~/.toolcfg | head",
                true,
            ),
            ("ls -la ~/.aws", false),
            ("ls -la ~/.ssh", false),
            ("ls -la ~/.gnupg", false),
            ("ls -la ~/.config/gh", false),
            ("ls -la ~/.config/1password", false),
            ("ls -la ~/.env.local", false),
            // Below the one hidden component the probe may spell, the tool
            // owns its own private state rather than the layout a listing
            // prints.
            ("ls -la ~/.config/toolcfg/.secrets", false),
            // A dot-leaf that is not a directory of the home directory keeps
            // the review it always had, whatever the name says.
            ("test -f ~/work/src/.aws-session", false),
            // `~/.local/share` is a root several tools keep directories
            // under, not one tool's own.
            ("ls -la ~/.local/share", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                Some(home),
                Some(cwd),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command} => {} / {}",
                result.minimum_action,
                result.reason_code
            );
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Agents check a worktree for an in-flight Git operation before they touch
/// it: `ls <worktree>/.git/index.lock`, `test -f .../MERGE_HEAD`. In a linked
/// worktree `.git` is a file, so the probe fails with `Not a directory`, and
/// the per-worktree state lives in `<main>/.git/worktrees/<name>/`. Both
/// print an error and nothing else; a probe through a credential file still
/// keeps its review.
#[test]
fn a_probe_for_git_operation_state_in_a_linked_worktree_reads_nothing() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/absent-listing-fixtures")
        .join(format!("gitfile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("work/.git/worktrees/wt")).unwrap();
    std::fs::create_dir_all(root.join("wt/src")).unwrap();
    std::fs::create_dir_all(root.join(".ssh")).unwrap();
    let root = std::fs::canonicalize(&root).unwrap();
    std::fs::write(root.join("work/.git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(
        root.join("work/.git/worktrees/wt/HEAD"),
        "ref: refs/heads/x\n",
    )
    .unwrap();
    std::fs::write(root.join("work/.env"), "TOKEN=synthetic\n").unwrap();
    std::fs::write(root.join(".ssh/id_ed25519"), "synthetic\n").unwrap();
    std::fs::write(root.join(".git-credentials"), "synthetic\n").unwrap();
    // A sibling checkout's package store is hidden too, but it is not a Git
    // directory, so an absent name below it keeps its review.
    std::fs::create_dir_all(root.join("other/.git")).unwrap();
    std::fs::write(root.join("other/.git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::create_dir_all(root.join("other/node_modules/.pnpm")).unwrap();
    std::fs::create_dir_all(root.join("probe")).unwrap();
    // A lexical `.git` symlink to a package store must not give Git-directory privileges.
    std::os::unix::fs::symlink(
        root.join("other/node_modules/.pnpm"),
        root.join("probe/.git"),
    )
    .unwrap();
    let gitdir = root.join("work/.git/worktrees/wt");
    std::fs::write(
        root.join("wt/.git"),
        format!("gitdir: {}\n", gitdir.display()),
    )
    .unwrap();
    let home = root.to_str().unwrap();
    let cwd = root.join("work");
    let cwd = cwd.to_str().unwrap();
    let state = gitdir.to_str().unwrap();
    for (command, allowed) in [
        (format!("ls {home}/wt/.git/index.lock 2>&1"), true),
        ("ls ~/wt/.git/MERGE_HEAD 2>&1".to_string(), true),
        (format!("ls {state}/index.lock"), true),
        (
            format!("test -f {home}/wt/.git/MERGE_HEAD && echo M || echo N"),
            true,
        ),
        (
            format!("test -f {state}/MERGE_HEAD && echo M || echo N"),
            true,
        ),
        (
            format!("ls {home}/wt/.git 2>&1; ls {home}/wt/.git/index.lock 2>&1"),
            true,
        ),
        ("ls ~/.ssh/id_ed25519/x".to_string(), false),
        ("ls ~/.git-credentials/x".to_string(), false),
        (format!("ls {cwd}/.env/x"), false),
        ("test -f ~/.ssh/id_ed25519/x && echo M".to_string(), false),
        (
            format!("ls {home}/other/node_modules/.pnpm/registry.npmjs.org"),
            false,
        ),
        (format!("ls {home}/probe/.git/missing-package"), false),
        (
            format!("test -f {home}/probe/.git/missing-package && echo M"),
            false,
        ),
    ] {
        let result = evaluate_pre_tool_envelope_with_context(
            "claude-code",
            "PreToolUse",
            &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
            None,
            None,
            Some(home),
            Some(cwd),
        );
        assert_eq!(
            result.minimum_action == "allow",
            allowed,
            "{command} => {} / {}",
            result.minimum_action,
            result.reason_code
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}
