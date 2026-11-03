//! On macOS the per-user temporary directory lives below `/private/var`, which
//! is otherwise system state. Routine work in a workspace created there must
//! stay quiet, while the temporary directory itself and system paths do not.
#![cfg(target_os = "macos")]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn decision(home: &std::path::Path, cwd: &std::path::Path, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

#[test]
fn routine_work_in_a_private_temporary_workspace_is_quiet() {
    let temporary = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(
        temporary.starts_with("/private/var/folders"),
        "expected the per-user temporary directory, got {}",
        temporary.display()
    );
    let nonce = crate::unique_nanos::unique_nanos();
    let workspace = temporary.join(format!(
        "guard-temp-workspace-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&workspace).unwrap();
    let _cleanup = Cleanup(workspace.clone());
    std::fs::write(workspace.join("notes.md"), "fixture\n").unwrap();
    let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
    // The workspace may be named through the /var alias, as $TMPDIR spells it.
    let alias = std::path::Path::new("/var").join(workspace.strip_prefix("/private/var").unwrap());
    for cwd in [&workspace, &alias] {
        for command in [
            "mkdir -p build/out",
            "touch build/out/report.txt",
            "cat notes.md",
        ] {
            assert_eq!(
                decision(&home, cwd, command),
                "allow",
                "{command} in {}",
                cwd.display()
            );
        }
    }
    // The shared temporary directory is not a workspace, and system paths stay guarded.
    assert_ne!(decision(&home, &temporary, "mkdir -p build/out"), "allow");
    assert_ne!(
        decision(&home, &workspace, "mkdir -p /private/var/db/guard-fixture"),
        "allow"
    );
}

/// `git worktree add "$TMPDIR/<name>"` places a checkout of the repository in
/// the per-user temporary directory. Sharing the main checkout's dependency
/// directory into it, at its root or in one of its folders, is the same
/// routine link as into a sibling worktree. A plain temporary folder that is
/// no checkout of the repository still takes no link.
#[test]
fn a_dependency_link_into_a_temporary_worktree_is_quiet() {
    let session = crate::pretool_git_session_ops::session("temp-worktree-link");
    let temporary = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(temporary.starts_with("/private/var/folders"));
    let nonce = crate::unique_nanos::unique_nanos();
    let scratch = temporary.join(format!("guard-temp-wt-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&scratch).unwrap();
    let _cleanup = Cleanup(scratch.clone());
    let checkout = scratch.join("workspace");
    crate::pretool_git_session_ops::git(
        &session.home,
        &session.primary,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "temp-feature",
            checkout.to_str().unwrap(),
        ],
    );
    std::fs::create_dir(checkout.join("src")).unwrap();
    std::fs::create_dir(scratch.join("plain")).unwrap();
    let primary = session.primary.display();
    let checkout = checkout.display();
    for command in [
        format!("ln -s {primary}/node_modules {checkout}/node_modules"),
        format!("ln -s {primary}/node_modules {checkout}/node_modules && echo linked"),
        format!("ln -s {primary}/node_modules {checkout}/src/node_modules && echo linked"),
    ] {
        assert_eq!(
            session
                .evaluate_at(&command, &session.primary)
                .minimum_action,
            "allow",
            "{command}"
        );
    }
    let plain = scratch.join("plain");
    let plain = plain.display();
    for command in [
        format!("ln -s {primary}/node_modules {plain}/node_modules"),
        format!("ln -s {primary}/node_modules {plain}/node_modules && echo linked"),
    ] {
        assert_ne!(
            session
                .evaluate_at(&command, &session.primary)
                .minimum_action,
            "allow",
            "{command}"
        );
    }
}

/// `$TMPDIR` ends in `/` on macOS, so `git worktree add "$TMPDIR/<name>"`
/// reaches Guard as `/var/folders/<a>/<b>/T//<name>`. The repeated separator
/// names the same destination as a single one, so the checkout and the reads
/// in it stay as quiet as they are with one separator. A leading `//` is no
/// spelling of the temporary directory and keeps its review.
#[test]
fn a_worktree_add_into_the_expanded_temporary_directory_is_quiet() {
    let session = crate::pretool_git_session_ops::session("temp-worktree-separator");
    let temporary = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(temporary.starts_with("/private/var/folders"));
    let alias = std::path::Path::new("/var").join(temporary.strip_prefix("/private/var").unwrap());
    let alias = alias.display();
    let name = format!(
        "guard-temp-add-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let _cleanup = Cleanup(temporary.join(&name));
    for destination in [format!("{alias}//{name}"), format!("{alias}/{name}")] {
        for command in [
            format!("git worktree add --detach {destination} HEAD"),
            format!(
                "git worktree add --detach {destination} HEAD && cd {destination} && git status --short"
            ),
        ] {
            let result = session.evaluate_at(&command, &session.primary);
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
    }
    for command in [
        format!("git worktree add --detach /{alias}/{name} HEAD"),
        format!("git worktree add --detach {alias}//{name}/ HEAD"),
    ] {
        assert_ne!(
            session
                .evaluate_at(&command, &session.primary)
                .minimum_action,
            "allow",
            "{command}"
        );
    }
}

struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
