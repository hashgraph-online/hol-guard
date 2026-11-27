//! Git reads after `cd <dir> && <step>; <read>` under a Git Allow.
//!
//! The Git floor judges `cd <dir> && <head>; <tail>` in parts: the remainder
//! after the `cd` in `<dir>`, and the tail in the original directory, where it
//! runs alone when the `cd` fails. A fetch before a log in the first part is
//! an earlier step the floor cannot prove leaves the log's configuration
//! alone, so it asked the user's Allow to settle it. That answer was indexed
//! into the part, not the command, so it was dropped and the review stood:
//! `cd <dir> && git fetch origin main; git log origin/main` asked while
//! `git -C <dir> fetch origin main && git -C <dir> log origin/main` ran.
//!
//! The Allow now settles each part in the directory it runs in. A step that
//! writes configuration the read obeys still settles nothing, and without
//! the Allow the review stands.
//!
//! The same commands also carry two read shapes Guard proves on its own: a
//! plain exclusion pathspec after `--` and a later `grep` whose pattern holds
//! a quoted `*`.

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

/// `root/project` on `main` with an `origin` it has fetched from once.
fn checkout(label: &str) -> (PathBuf, PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-git-allow-cd-fork-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let upstream = root.join("upstream.git");
    let project = root.join("project");
    git(
        &root,
        &root,
        &[
            "init",
            "--quiet",
            "--bare",
            "-b",
            "main",
            upstream.to_str().unwrap(),
        ],
    );
    git(
        &root,
        &root,
        &["init", "--quiet", "-b", "main", project.to_str().unwrap()],
    );
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/index.ts"), "export const a = 1;\n").unwrap();
    std::fs::write(project.join("bun.lock"), "{}\n").unwrap();
    git(&root, &project, &["add", "-A"]);
    git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &root,
        &project,
        &["remote", "add", "origin", upstream.to_str().unwrap()],
    );
    git(&root, &project, &["push", "--quiet", "origin", "main"]);
    git(&root, &project, &["fetch", "--quiet", "origin"]);
    let root = fixture::canonical_spelling(&root);
    let project = root.join("project");
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

const HARNESSES: [&str; 2] = ["claude-code", "codex"];

#[test]
fn allowed_fetch_then_reads_after_a_cd_run() {
    let (root, project, _cleanup) = checkout("allowed");
    let p = fixture::shell_word(&project);
    let allow = git_allow();
    for command in [
        format!(
            r#"cd {p} && git fetch origin main 2>&1 | tail -5; echo "--- remote"; git log --oneline -3 origin/main; echo "--- ahead"; git rev-list --left-right --count main...origin/main"#
        ),
        format!("cd {p} && git fetch origin main; git log --oneline -3 origin/main"),
        format!("cd {p} && git pull --ff-only; git log --oneline -3"),
        format!("cd {p} && git fetch origin main; git log --oneline -3 origin/main; git rev-list --count main"),
    ] {
        for harness in HARNESSES {
            let result = decide(&root, &project, harness, &command, Some(&allow));
            assert_eq!(
                result.minimum_action, "allow",
                "{harness}: {command}: {} {}",
                result.reason_code, result.reason
            );
        }
    }
}

#[test]
fn the_same_compound_still_reviews_without_the_allow() {
    let (root, project, _cleanup) = checkout("default");
    let p = fixture::shell_word(&project);
    let command = format!("cd {p} && git fetch origin main; git log --oneline -3 origin/main");
    for harness in HARNESSES {
        let result = decide(&root, &project, harness, &command, None);
        assert_ne!(
            result.minimum_action, "allow",
            "{harness}: {command}: {}",
            result.reason_code
        );
    }
}

#[test]
fn a_configuration_write_before_the_read_still_reviews_under_the_allow() {
    let (root, project, _cleanup) = checkout("config");
    let p = fixture::shell_word(&project);
    let allow = git_allow();
    for command in [
        format!("cd {p} && git config core.pager cat; git log -1"),
        format!(
            "cd {p} && git fetch origin main; git log -1; git config core.pager cat; git rev-list --count main"
        ),
        format!("cd {p} && git fetch origin main; echo x; git config core.pager cat; git log -1"),
    ] {
        for harness in HARNESSES {
            let result = decide(&root, &project, harness, &command, Some(&allow));
            assert_ne!(
                result.minimum_action, "allow",
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
    }
}

#[test]
fn exclusion_pathspecs_and_quoted_filter_globs_are_proven_reads() {
    let (root, project, _cleanup) = checkout("reads");
    let p = fixture::shell_word(&project);
    for command in [
        format!("cd {p} && git diff HEAD --unified=0 -- . ':!bun.lock'"),
        format!("git -C {p} diff --cached -U0 -- . ':(exclude)bun.lock' ':^dist'"),
        format!(
            r#"cd {p} && git diff HEAD --unified=0 | grep -E "^\+.*process\.env" | grep -vE "^\+\+\+""#
        ),
    ] {
        for harness in HARNESSES {
            let result = decide(&root, &project, harness, &command, None);
            assert_eq!(
                result.minimum_action, "allow",
                "{harness}: {command}: {} {}",
                result.reason_code, result.reason
            );
        }
    }
}

#[test]
fn magic_pathspecs_and_unquoted_filter_syntax_keep_their_review() {
    let (root, project, _cleanup) = checkout("refused");
    let p = fixture::shell_word(&project);
    for command in [
        // An exclusion before `--` can name an index object.
        format!("git -C {p} diff ':!bun.lock'"),
        // Further magic after the exclusion.
        format!("git -C {p} diff -- . ':!/bun.lock'"),
        format!("git -C {p} diff -- . ':(exclude,glob)**/bun.lock'"),
        // An unquoted glob expands into the file it names.
        format!("git -C {p} diff --cached | grep -v .env*"),
    ] {
        for harness in HARNESSES {
            let result = decide(&root, &project, harness, &command, None);
            assert_ne!(
                result.minimum_action, "allow",
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
    }
}

/// The tail after `cd <dir> && <head>;` runs alone where the command started
/// when the `cd` fails, so a helper configured there keeps the review even
/// though the user allowed every Git step.
#[test]
fn a_helper_where_the_command_started_keeps_the_review_under_the_allow() {
    let (root, project, _cleanup) = checkout("start-helper");
    let start = root.join("start");
    git(
        &root,
        &root,
        &["init", "--quiet", "-b", "main", start.to_str().unwrap()],
    );
    git(
        &root,
        &start,
        &["config", "core.fsmonitor", "./synthetic-never-execute"],
    );
    let p = fixture::shell_word(&project);
    let allow = git_allow();
    let command = format!("cd {p} && git fetch origin main; git status --short");
    for harness in HARNESSES {
        let result = fixture::evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
            Some(&allow),
            None,
            root.to_str(),
            start.to_str(),
        );
        assert_ne!(
            result.minimum_action, "allow",
            "{harness}: {command}: {}",
            result.reason_code
        );
    }
}
