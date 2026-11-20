//! A `cd` whose transition cannot be proven, beside the user's Git Allow.
//!
//! `cd . && git worktree prune; git worktree list | grep -c app` is how a
//! session tidies its worktrees and counts what is left. The `;` is the point:
//! if the `cd` failed, the shell would run the rest in the directory the
//! command started in, so Guard cannot read a later relative operand against
//! either directory and refuses to prove any step alone. That withdrew the
//! user's Allow from the whole command, including the `grep` reading the pipe,
//! which names no path at all and reads the same either way.
//!
//! Only steps that name nothing regain their proof. A step that touches the
//! working directory -- a bare `ls`, a `cat` of a relative file, a Git read --
//! still loses one.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

/// `root/project` on `main`, one commit deep, with a GitHub `origin` so the
/// Git reads beside the `cd` have something to report.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-cd-sequence-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    fixture::git(&root, &project, &["init", "--quiet", "-b", "main"]);
    fixture::git(&root, &project, &["config", "user.name", "Guard Fixture"]);
    fixture::git(
        &root,
        &project,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    fixture::git(
        &root,
        &project,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example-org/app-portal.git",
        ],
    );
    std::fs::write(project.join("src/index.ts"), "export const a = 1;\n").unwrap();
    fixture::git(&root, &project, &["add", "-A"]);
    fixture::git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

fn decide(
    root: &Path,
    harness: &str,
    command: &str,
    controls: &guard_command::native_command_controls::CompiledNativeCommandControls,
) -> guard_contracts::PreToolResultV1 {
    fixture::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(controls),
        None,
        root.to_str(),
        root.join("project").to_str(),
    )
}

const HARNESSES: &[&str] = &["omp", "zcode", "codex", "claude-code"];

/// The steps that name no path keep their proof, so the user's Allow still
/// covers the command the `;` appears in.
#[test]
fn a_path_free_step_keeps_its_proof_after_an_unproven_cd() {
    let (root, _cleanup) = checkout("allow");
    let controls = fixture::every_permission_enabled();
    for command in [
        "cd . && git worktree prune; git worktree list | grep -c app",
        "cd . && git worktree remove ../review --force; git worktree list | grep -c app",
        "cd . && git worktree remove ../review --force && git worktree remove ../other --force 2>/dev/null; git worktree list | grep -c app",
        "cd . && git worktree prune; echo done",
        "cd . && git worktree prune; true",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

/// A step whose answer the working directory decides is still unproven after a
/// `cd` the separator leaves in doubt.
#[test]
fn a_step_that_reads_the_working_directory_stays_unproven() {
    let (root, _cleanup) = checkout("floor");
    let controls = fixture::every_permission_enabled();
    for command in [
        "cd . && git worktree prune; ls",
        "cd . && git worktree prune; cat README.md",
        "cd . && git worktree prune; git status --short",
        "cd nowhere && git worktree prune; cat .env",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}
