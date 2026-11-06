//! A user who allows every Git permission has allowed Git, not the list of
//! spellings Guard happens to model. Most Git verbs carry a rule, so the Allow
//! reaches them and they run. The ones with no rule -- `ls-remote`, `archive`,
//! `for-each-ref`, a verb a later Git release adds -- produce no observation
//! at all, so nothing could record them as covered and the generic review
//! stood. The Allow then held for `git status` and stopped at
//! `git ls-remote`, which is the shape users report as allowing Git and still
//! being asked.
//!
//! An Allow that does not reach the variations is not an Allow, so a watched
//! program now counts as covered when the user enabled every permission its
//! extension declares. The scope stays theirs: a partial Allow covers exactly
//! its own rules, and every floor Guard raises around that coverage keeps its
//! answer.

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

/// `root/project` on `main`, one commit deep, with a GitHub `origin`.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-unmodelled-git-{label}-{}",
        std::process::id()
    ));
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
    // Git for Windows reads no global configuration from a `\\?\` home, so the
    // fixture spells the root the way a user's home is spelled.
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

/// Every permission the Git extension declares, set to `enabled`, as the
/// Extensions page writes it when the user allows Git outright. `withheld`
/// names one permission to leave at its default, which is how a user who
/// allowed only part of Git looks.
fn git_allow(
    withheld: Option<&str>,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls: Vec<_> = program
        .extensions
        .iter()
        .filter(|extension| extension.extension_id == "command.git")
        .flat_map(|extension| extension.permissions.iter())
        .filter(|permission| Some(permission.permission_id.as_str()) != withheld)
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

/// A permission the Git extension certainly declares, used as the one a
/// partial Allow leaves off.
const WITHHELD: &str = "command.git.permission.status";

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

/// Git work the packaged catalog carries no rule for. Each one is the whole
/// command, so no earlier allowed step can carry it, and each is a plain read
/// a developer runs while the Allow is in force.
const UNMODELLED: &[&str] = &[
    "git ls-remote --heads origin",
    "git ls-remote --tags origin",
    "git ls-remote origin",
    "git archive --format=tar HEAD",
    "git for-each-ref --format='%(refname:short)' refs/heads",
    "git show-ref --verify refs/heads/main",
    "git cat-file -p HEAD",
    "git shortlog -sn HEAD",
    "git count-objects -v",
    "git ls-remote --heads origin && git log --oneline -3",
    // A read leaves the next step running what Guard read, so the Allow
    // carries the whole chain, and packaging a tree into a file the
    // workspace names is Git's own work.
    "git ls-remote --heads origin && git archive --format=tar -o snapshot.tar HEAD",
    "git format-patch -o patches HEAD~1",
    "git status --short --branch && git log --oneline -5 && git remote -v",
];

const HARNESSES: &[&str] = &["omp", "zcode", "codex", "claude-code"];

#[test]
fn an_allowed_git_extension_reaches_the_shapes_it_has_no_rule_for() {
    let (root, _cleanup) = checkout("allow");
    let controls = git_allow(None);
    let mut failures = Vec::new();
    for harness in HARNESSES {
        for command in UNMODELLED {
            let result = decide(&root, harness, command, &controls);
            if result.decision != "allow" {
                failures.push(format!(
                    "{harness}: {command}: {} {} {}",
                    result.decision, result.reason_code, result.reason
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The shapes above that Guard does not prove on its own. Most unmodelled Git
/// reads already carry a native benign proof, so they allow whatever the user
/// answered; the rest are the ones the Allow has to reach, and they are what
/// the scope tests below measure.
fn shapes_that_need_the_allow(root: &Path) -> Vec<&'static str> {
    let defaults = fixture::github_controls("default");
    UNMODELLED
        .iter()
        .copied()
        .filter(|command| decide(root, "omp", command, &defaults).decision != "allow")
        .collect()
}

/// Without the Allow these shapes are not proven read-only on their own, so
/// they wait for the user exactly as they did before. At least one must, or
/// the test above proves nothing.
#[test]
fn the_same_shapes_wait_without_an_allow() {
    let (root, _cleanup) = checkout("default");
    assert!(
        !shapes_that_need_the_allow(&root).is_empty(),
        "no unmodelled shape waits without an Allow"
    );
}

/// Allowing part of Git is not allowing Git. A user who left one permission
/// off has not answered for the shapes no rule models, so those keep their
/// review and the rules they did allow keep working.
#[test]
fn a_partial_allow_does_not_reach_the_unmodelled_shapes() {
    let (root, _cleanup) = checkout("partial");
    let partial = git_allow(Some(WITHHELD));
    let full = git_allow(None);
    let mut measured = 0;
    let mut reached = Vec::new();
    for command in shapes_that_need_the_allow(&root) {
        if decide(&root, "omp", command, &full).decision != "allow" {
            continue;
        }
        measured += 1;
        let result = decide(&root, "omp", command, &partial);
        if result.decision == "allow" {
            reached.push(format!("{command}: {}", result.reason_code));
        }
    }
    assert!(reached.is_empty(), "{reached:#?}");
    assert!(measured > 0, "the full Allow reaches no shape to scope");
}

/// Git shapes an extension-wide Allow must never reach. Each one either runs
/// a program the user configured rather than Git itself, or is a verb this
/// release does not model, so no answer about Git's own reads covers it.
const OUTSIDE_THE_ALLOW: &[&str] = &[
    "git credential fill",
    "git filter-branch --force --tree-filter 'rm -f secret.txt' HEAD",
    "git -c alias.sneak='!printf hi' sneak",
    "git -c core.pager='printf hi' log --oneline -3",
    // `--output` reaches every verb that shows a diff, so this read writes
    // the configuration the `git status` after it reads.
    "git log -1 --output=.git/config && git status",
    // The same option on a verb that packages a tree, pointed at the hook
    // the next step would run and at a path outside the workspace.
    "git archive --format=tar -o .git/hooks/pre-commit HEAD && git status",
    "git archive --format=tar -o ../snapshot.tar HEAD && git status",
];

/// Allowing Git in full answers for Git's own work, not for whatever program
/// a setting, an alias or an unmodelled verb makes Git start. Coverage runs
/// through the same per-program contract the uncertainty path uses, so these
/// keep the answer they had before the Allow.
#[test]
fn an_allowed_git_extension_does_not_reach_a_configured_program() {
    let (root, _cleanup) = checkout("configured");
    let controls = git_allow(None);
    let mut reached = Vec::new();
    for command in OUTSIDE_THE_ALLOW {
        let result = decide(&root, "omp", command, &controls);
        if result.decision == "allow" {
            reached.push(format!("{command}: {}", result.reason_code));
        }
    }
    assert!(reached.is_empty(), "{reached:#?}");
}
