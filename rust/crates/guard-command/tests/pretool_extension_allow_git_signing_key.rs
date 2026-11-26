//! A Git step that names its OpenPGP signing key under the user's Git Allow.
//!
//! `git -c user.signingkey=<key id> commit -S` picks which key in the user's
//! keyring signs the commit. A key ID or fingerprint is a public identifier,
//! yet the literal-secret screen read `signingkey=<hex>` as a credential
//! written into the command and withdrew the Allow.
//!
//! A random value under the same name still reads as a secret.

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

/// `root/project` on `main`, one commit deep.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    // Below the target directory: `$TMPDIR` on macOS resolves under
    // `/private/var`, which the sensitive-root screen rejects for reads.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "guard-extension-allow-git-signing-key-{label}-{}",
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
    git(&root, &project, &["add", "-A"]);
    git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

/// Every permission in the packaged catalog set to `state`, as the Extensions
/// page writes it when the user allows each pattern.
fn every_permission(
    state: &str,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls: Vec<_> = program
        .extensions
        .iter()
        .flat_map(|extension| extension.permissions.iter())
        .map(|permission| {
            json!({"target_kind":"permission", "target_id":permission.permission_id, "state":state})
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
    harness: &str,
    command: &str,
    controls: &guard_command::native_command_controls::CompiledNativeCommandControls,
) -> guard_contracts::PreToolResultV1 {
    decide_with(root, harness, command, Some(controls))
}

fn decide_with(
    root: &Path,
    harness: &str,
    command: &str,
    controls: Option<&guard_command::native_command_controls::CompiledNativeCommandControls>,
) -> guard_contracts::PreToolResultV1 {
    fixture::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        controls,
        None,
        root.to_str(),
        root.join("project").to_str(),
    )
}

const HARNESSES: &[&str] = &["omp", "zcode", "codex", "claude-code"];

#[test]
fn a_step_naming_its_signing_key_id_keeps_its_allow() {
    let (root, _cleanup) = checkout("allow");
    let controls = every_permission("enabled");
    for command in [
        "git -c user.signingkey=3AA5C34371567BD2 commit -m \"fix: handle retry\"",
        "git -c user.name=\"Guard Agent\" -c user.email=agent@example.invalid -c user.signingkey=3AA5C34371567BD2 -c commit.gpgsign=true commit -S -m \"fix(report): handle retry\" -m \"The window now closes on retry.\"",
        "git -c user.signingkey=0x3AA5C34371567BD2! commit -S -m \"fix: handle retry\"",
        "git -c user.signingKey=4F3A9B2C1D0E8F7A6B5C4D3E2F1A0B9C8D7E6F5A commit -S -m \"fix: handle retry\"",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_eq!(
                (result.decision.as_str(), result.reason_code.as_str()),
                ("allow", "native_command_explicit_permission_allow"),
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_random_value_under_the_signing_key_name_keeps_its_review() {
    let (root, _cleanup) = checkout("review");
    let controls = every_permission("enabled");
    for command in [
        "git -c user.signingkey=Xq7vR2mK9pL4wT8nB3cZ6hJ1 commit -m \"fix: handle retry\"",
        "git -c user.signingkey=3AA5C34371567BD24F3A9B2C1D0E8F7A6B5C4D3E2F1A0B9C commit -m \"fix: handle retry\"",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

/// An agent that passes its identity on every Git command keeps its reads with
/// no permission set: the identity names no program and a read signs nothing.
#[test]
fn a_read_naming_its_identity_on_the_command_line_stays_a_read() {
    let (root, _cleanup) = checkout("read");
    for command in [
        "git -c user.signingkey=3AA5C34371567BD2 status --short",
        "git -c user.signingkey=3AA5C34371567BD2 -c core.pager=cat log --oneline -3",
        "git -c user.name=\"Guard Agent\" -c user.email=agent@example.invalid -c user.signingkey=3AA5C34371567BD2 diff --stat",
    ] {
        for harness in HARNESSES {
            let result = decide_with(&root, harness, command, None);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
    // A setting that names a program, or a value the shell would run, still
    // holds the read.
    for command in [
        "git -c user.signingkey=3AA5C34371567BD2 -c gpg.program=./sign log --show-signature -1",
        "git -c user.name=\"Guard Agent\" -c core.pager=./page log --oneline -3",
        "git -c user.name=\"$(id)\" status --short",
    ] {
        for harness in HARNESSES {
            let result = decide_with(&root, harness, command, None);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}
