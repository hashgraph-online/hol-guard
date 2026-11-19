//! `git stage` is Git's own second name for `git add`. `git-stage(1)`
//! documents it as a synonym of `git-add(1)`: the same builtin, the same
//! options, the same effect on the index. Guard's local-write proofs read the
//! subcommand word, so they recognised `git add -A` and not `git stage -A`,
//! and the second spelling asked the user for the work the first one ran.

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
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// `root/project` on `main`, one commit deep, with an edit waiting to stage.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!("guard-git-stage-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    git(&root, &project, &["init", "--quiet", "-b", "main"]);
    git(&root, &project, &["config", "user.name", "Guard Fixture"]);
    git(
        &root,
        &project,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    git(
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
    std::fs::write(project.join("README.md"), "fixture\n").unwrap();
    git(&root, &project, &["add", "-A"]);
    git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    std::fs::write(project.join("src/index.ts"), "export const a = 2;\n").unwrap();
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

/// Every permission the Git extension declares, set to `enabled`, as the
/// Extensions page writes it when the user allows Git outright.
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
    assert!(
        controls.len() > 1,
        "the Git extension declares too few permissions to allow"
    );
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

fn decide(root: &Path, harness: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    let controls = git_allow();
    fixture::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls),
        None,
        root.to_str(),
        root.join("project").to_str(),
    )
}

const HARNESSES: &[&str] = &["omp", "zcode", "codex", "claude-code"];

/// Each pair is the same work spelled both ways. The `add` spelling already
/// ran; the `stage` spelling has to reach the same answer.
const PAIRS: &[(&str, &str)] = &[
    ("git add -A", "git stage -A"),
    ("git add --all", "git stage --all"),
    ("git add -u", "git stage -u"),
    ("git add src/index.ts", "git stage src/index.ts"),
    ("git add -- src/index.ts", "git stage -- src/index.ts"),
    (
        "git add -A && git commit -m 'fix: handle retry'",
        "git stage -A && git commit -m 'fix: handle retry'",
    ),
    (
        "git status --short && git add -A",
        "git status --short && git stage -A",
    ),
    (
        "git add -A && git log -1 --oneline",
        "git stage -A && git log -1 --oneline",
    ),
];

#[test]
fn staging_reaches_the_answer_adding_already_had() {
    let (root, _cleanup) = checkout("pairs");
    let mut failures = Vec::new();
    for harness in HARNESSES {
        for (adds, stages) in PAIRS {
            let added = decide(&root, harness, adds);
            if added.decision != "allow" {
                failures.push(format!(
                    "{harness}: {adds}: the add spelling did not allow: {} {}",
                    added.decision, added.reason_code
                ));
                continue;
            }
            let staged = decide(&root, harness, stages);
            if staged.decision != "allow" {
                failures.push(format!(
                    "{harness}: {stages}: {} {} {}",
                    staged.decision, staged.reason_code, staged.reason
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The synonym carries no more than the name it stands for. `git add -f`
/// stages an ignored file, which is how a secret the project ignores reaches
/// a commit, and `git stage -f` has to keep the same review.
#[test]
fn the_synonym_stops_where_adding_stops() {
    let (root, _cleanup) = checkout("forced");
    for command in [
        "git add -f ignored.env",
        "git stage -f ignored.env",
        "git add --force ignored.env",
        "git stage --force ignored.env",
    ] {
        let result = decide(&root, "omp", command);
        assert_ne!(
            result.decision, "allow",
            "{command}: {} {}",
            result.reason_code, result.reason
        );
    }
}
