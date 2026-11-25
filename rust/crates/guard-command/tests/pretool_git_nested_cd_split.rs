//! Git reads after a second `cd` in `cd <dir> && <read>; cd .. && git diff`.
//!
//! The Git floor splits `cd <dir> && <head>; <tail>` and `cd <dir>; <rest>`
//! into the parts the shell can run, each in its own directory, and judges
//! every part again. It refused the split whenever a later step changed
//! directory, so stepping into a subfolder for a read and back out for
//! `git diff` fell to the blanket "Git after a later `cd`" review, even with
//! every Git permission enabled.
//!
//! The split now accepts the later `cd`, because each part goes back through
//! the same directory-aware floor and helper probe: the second `cd` splits
//! its part in turn, so every Git read is inspected in each directory it can
//! run in. A helper configured where a failed first `cd` would leave the read
//! still keeps the review, and so does a configuration write before the read.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

fn git(home: &Path, directory: &Path, arguments: &[&str]) {
    let mut command = std::process::Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_NAMESPACE",
    ] {
        command.env_remove(name);
    }
    let status = command
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Guard Fixture")
        .env("GIT_AUTHOR_EMAIL", "guard-fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Guard Fixture")
        .env("GIT_COMMITTER_EMAIL", "guard-fixture@example.invalid")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// `root/<parent>/project` on `main` with a committed `src/index.ts` and one
/// uncommitted edit. `parent` is a plain folder unless `parent_helper` makes
/// it a checkout whose configuration names a helper program.
fn checkout(label: &str, parent_helper: bool) -> (PathBuf, PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-git-nested-cd-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let parent = root.join("parent");
    std::fs::create_dir_all(&parent).unwrap();
    if parent_helper {
        git(&root, &parent, &["init", "--quiet", "-b", "main"]);
        git(
            &root,
            &parent,
            &["config", "core.fsmonitor", "./synthetic-never-execute"],
        );
    }
    let project = parent.join("project");
    git(
        &root,
        &parent,
        &["init", "--quiet", "-b", "main", project.to_str().unwrap()],
    );
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/index.ts"), "export const a = 1;\n").unwrap();
    git(&root, &project, &["add", "-A"]);
    git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    std::fs::write(project.join("src/index.ts"), "export const a = 2;\n").unwrap();
    let root = fixture::canonical_spelling(&root);
    let project = root.join("parent/project");
    (root.clone(), project, FixtureCleanup(root))
}

/// Every permission the Git extension declares, enabled, as the Extensions
/// page writes it when the user allows Git outright.
fn git_allow() -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls: Vec<_> = program
        .extensions
        .iter()
        .filter(|extension| extension.extension_id == "command.git")
        .flat_map(|extension| extension.permissions.iter())
        .map(|permission| {
            json!({"target_kind":"permission", "target_id":permission.permission_id, "state":"enabled"})
        })
        .collect();
    let value = json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":controls
        }]
    });
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(value).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

fn decide(
    root: &Path,
    project: &Path,
    harness: &str,
    command: &str,
    controls: Option<&guard_command::native_command_controls::CompiledNativeCommandControls>,
) -> guard_contracts::PreToolResultV1 {
    fixture::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        controls,
        None,
        root.to_str(),
        project.to_str(),
    )
}

const HARNESSES: [&str; 3] = ["claude-code", "codex", "omp"];

const STEP_IN_AND_OUT: [&str; 4] = [
    "cd src && ls; cd .. && git diff --stat",
    "cd src && wc -l index.ts; cd .. && git log --oneline -3",
    "cd src && ls; cd .. && git diff --stat; git diff | grep -c export",
    "cd src; ls; cd ..; git status --short",
];

#[test]
fn a_read_in_a_subfolder_then_git_back_out_runs_under_the_allow() {
    let (root, project, _cleanup) = checkout("allowed", false);
    let allow = git_allow();
    for command in STEP_IN_AND_OUT {
        for harness in HARNESSES {
            let result = decide(&root, &project, harness, command, Some(&allow));
            assert_eq!(
                result.minimum_action, "allow",
                "{harness}: {command}: {} {}",
                result.reason_code, result.reason
            );
        }
    }
}

/// When `cd src` fails, `cd ..` leaves the read in the folder above the
/// project. A helper configured there runs for `git status`, so the review
/// stays even though the user allowed every Git step.
#[test]
fn a_helper_where_a_failed_cd_leaves_the_read_keeps_the_review() {
    let (root, project, _cleanup) = checkout("parent-helper", true);
    let allow = git_allow();
    for command in [
        "cd src && ls; cd .. && git status --short",
        "cd src; ls; cd ..; git status --short",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, &project, harness, command, Some(&allow));
            assert_ne!(
                result.minimum_action, "allow",
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
    }
}

#[test]
fn a_configuration_write_before_the_read_still_reviews() {
    let (root, project, _cleanup) = checkout("config", false);
    let allow = git_allow();
    for command in [
        "cd src && ls; cd .. && git config core.pager cat; git log -1",
        "cd src && ls; cd .. && git config core.fsmonitor ./synthetic-never-execute && git status",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, &project, harness, command, Some(&allow));
            assert_ne!(
                result.minimum_action, "allow",
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
    }
}
