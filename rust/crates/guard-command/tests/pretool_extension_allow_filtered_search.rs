//! A filtered search under the user's Git Allow.
//!
//! `grep --include=*.tsx` and `rg --glob=*.rs` name the files a search should
//! look at. Guard's fixed floor asks of a glob whether some longer string it
//! matches could name a private file, and it read the whole `--include=*.tsx`
//! token as one name -- which `private-key.tsx` matches. One ordinary filtered
//! search anywhere in a command therefore set a floor no extension permission
//! can settle, withdrawing the user's Allow from every other step, including
//! the worktree commands beside it.
//!
//! The value still faces every screen a bare operand faces: a filter whose own
//! glob reaches a credential keeps its floor.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

/// `root/project` on `main`, one commit deep, with a source directory for the
/// search to filter.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-filtered-search-{label}-{}",
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
    std::fs::write(project.join("src/index.tsx"), "export const a = 1;\n").unwrap();
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

/// A step the user's Allow settles, beside a filtered search, keeps that Allow.
/// The floor is read over the whole command, so a filter the floor refused
/// withdrew the Allow from the worktree step as well.
#[test]
fn an_allowed_step_keeps_its_allow_beside_a_filtered_search() {
    let (root, _cleanup) = checkout("allow");
    let controls = fixture::every_permission_enabled();
    for command in [
        "git worktree remove ../review --force; grep -rn needle src --include=*.tsx -l",
        "git worktree remove ../review --force && grep -rn needle src --include=*.tsx -l",
        "git worktree remove ../review --force && rg needle src --glob=*.rs",
        "git worktree remove ../review --force && rg --glob=*.rs needle src",
        "git worktree remove ../review --force && grep -rn needle src --include=*.ts --include=*.tsx -l",
        "git worktree prune && grep -rn needle src --include=*.tsx -l",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

/// The value after the `=` is screened the way a bare operand is, so a filter
/// whose own glob reaches a credential keeps the floor the user's Allow cannot
/// settle.
#[test]
fn a_filter_that_reaches_a_credential_keeps_its_floor() {
    let (root, _cleanup) = checkout("floor");
    let controls = fixture::every_permission_enabled();
    for command in [
        "git worktree remove ../review --force && grep -rn needle src --include=.env* -l",
        "git worktree remove ../review --force && grep -rn needle src --include=*.env -l",
        "git worktree remove ../review --force && rg needle src --glob=.env*",
        "git worktree remove ../review --force && grep -rn needle src --exclude=*.log -l",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

// Even after `--`, Git accepts a filename that resembles an option.
// With Git Allow, discarding the `--include=` prefix would quietly allow a
// pathspec that can select a synthetic credential-named file.
#[test]
fn a_pathspec_after_double_dash_must_not_be_an_option() {
    let (root, _cleanup) = checkout("pathspec");
    let project = root.join("project");
    let filename = "--include=private-key.tsx";
    let path = project.join(filename);
    std::fs::write(&path, "public test marker\n").unwrap();
    fixture::git(&root, &project, &["add", "--", filename]);
    fixture::git(
        &root,
        &project,
        &["commit", "--quiet", "-m", "pathspec fixture"],
    );
    std::fs::write(&path, "changed public test marker\n").unwrap();

    let controls = fixture::every_permission_enabled();
    for command in [
        "git diff --name-only -- '--include=*.tsx'",
        "git diff -m --name-only -- '--include=*.tsx'",
        "git diff-tree -m --name-only HEAD^ HEAD -- '--include=*.tsx'",
        "git diff-index -m --name-only HEAD -- '--include=*.tsx'",
        "git diff-files -m --name-only -- '--include=*.tsx'",
        "git whatchanged -m --name-only -1 -- '--include=*.tsx'",
        "git checkout -m -- '--include=*.tsx'",
        "git restore -m -- '--include=*.tsx'",
        "git worktree remove ../review --force && git diff --name-only -- '--include=*.tsx'",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}
