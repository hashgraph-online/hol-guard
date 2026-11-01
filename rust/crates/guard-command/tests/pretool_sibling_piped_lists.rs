#![cfg(unix)]
//! Agents step into a linked worktree beside the checkout and run several
//! package scripts there, trimming each one's output:
//! `cd <worktree> && bun run test 2>&1 | tail -4 && bun run build | tail -4`.
//! The sink peels the `cd` and runs the rest whole from the worktree root, the
//! filters included, so the list is contained there just as the same list
//! without the filters is. Any other pipe keeps its review.

use crate::pretool_git_session_ops::{session, Session};
use std::path::Path;

/// Scripts the worktree's package runs, and the local entrypoint its build
/// names.
fn package(directory: &Path) {
    let scripts =
        r#"{"scripts":{"build":"vite build","test":"node --test","smoke":"node smoke.js"}}"#;
    std::fs::write(directory.join("package.json"), scripts).unwrap();
    let entry = directory.join("node_modules/vite/bin/vite.js");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(entry, "").unwrap();
}

fn outcome(session: &Session, command: &str) -> (String, String) {
    let result = session.evaluate_at(command, &session.primary);
    (result.minimum_action, result.reason_code)
}

#[test]
fn a_list_of_bounded_runs_in_a_sibling_worktree_runs_contained() {
    let session = session("sibling-piped-list");
    package(&session.worktree);
    let wt = session.worktree.display();
    for command in [
        format!("cd {wt} && bun run test 2>&1 | tail -4 && bun run smoke 2>&1 | tail -4"),
        format!("cd {wt} && bun run test | head -n 20 && bun run build"),
        format!("cd {wt} && bun run build && bun run test 2>&1 | tail -12"),
        format!("cd {wt}; bun run test 2>&1 | tail -4 && bun run smoke | tail -4"),
        format!("cd {wt} && bun run test && bun run smoke"),
    ] {
        let (action, reason) = outcome(&session, &command);
        assert_eq!(
            (action.as_str(), reason.as_str()),
            ("sandbox-required", "native_workspace_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn other_pipes_in_a_sibling_worktree_list_keep_their_review() {
    let session = session("sibling-piped-other");
    package(&session.worktree);
    let wt = session.worktree.display();
    for command in [
        format!("cd {wt} && bun run test | grep fail && bun run smoke"),
        format!("cd {wt} && bun run test | tail -4 | head -2 && bun run smoke"),
        format!("cd {wt} && bun run test | tail -f && bun run smoke"),
        format!("cd {wt} && bun run test | tail -4 notes.txt && bun run smoke"),
        format!("cd {wt} && bun run test 2>&1 && bun run smoke | sh"),
        format!("cd {wt} && bun run test | tail -4 || bun run smoke"),
    ] {
        let (action, reason) = outcome(&session, &command);
        assert!(
            !matches!(action.as_str(), "allow" | "sandbox-required"),
            "{command}: {action} {reason}"
        );
    }
}
