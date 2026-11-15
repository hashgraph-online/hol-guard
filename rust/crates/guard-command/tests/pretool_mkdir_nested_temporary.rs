#![cfg(unix)]
//! `mkdir -p` of a nested path below a private temporary directory.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct Fixture {
    home: PathBuf,
    workspace: PathBuf,
    scratch: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

/// Home and workspace stay outside the temporary roots. The scratch directory
/// is a user-owned directory directly under `/tmp` that holds a private
/// directory, a directory anyone may write to, and a link out to home.
fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-mkdir-nested-temporary")
        .join(format!("{name}-{}", std::process::id()));
    let home = root.join("home");
    let workspace = home.join("project");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let scratch = PathBuf::from(format!(
        "/tmp/hg-mkdir-nested-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::create_dir(scratch.join("private")).unwrap();
    std::fs::set_permissions(
        scratch.join("private"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::create_dir(scratch.join("shared")).unwrap();
    std::fs::set_permissions(
        scratch.join("shared"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    std::os::unix::fs::symlink(home.join(".ssh"), scratch.join("keys")).unwrap();
    Fixture {
        home: std::fs::canonicalize(home).unwrap(),
        workspace: std::fs::canonicalize(workspace).unwrap(),
        scratch,
    }
}

fn action(fixture: &Fixture, harness: &str, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        fixture.home.to_str(),
        fixture.workspace.to_str(),
    )
    .minimum_action
}

#[test]
fn a_nested_directory_below_a_private_temporary_directory_is_bounded() {
    let fixture = fixture("allowed");
    let scratch = fixture.scratch.display();
    let fresh = format!("/tmp/hg-mkdir-nested-fresh-{}", std::process::id());
    for harness in ["claude-code", "codex", "cursor", "zcode"] {
        for command in [
            // The single-level form was already admitted.
            format!("mkdir -p {fresh}"),
            format!("mkdir -p {fresh}/a"),
            format!("mkdir -p {fresh}/a/b/c"),
            format!("mkdir --parents {fresh}/logs/run"),
            format!("mkdir -p {scratch}/build/out"),
            format!("mkdir -p {scratch}/private/a/b"),
        ] {
            assert_eq!(
                action(&fixture, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_nested_directory_outside_a_private_temporary_parent_keeps_its_review() {
    let fixture = fixture("refused");
    let scratch = fixture.scratch.display();
    let home = fixture.home.display();
    for command in [
        // Anyone may write to the existing parent, so it could be swapped.
        format!("mkdir -p {scratch}/shared/a/b"),
        // A link at the existing parent resolves into home.
        format!("mkdir -p {scratch}/keys/a/b"),
        // A parent component is never read lexically.
        format!("mkdir -p {scratch}/a/../b/c"),
        // Outside the temporary roots nothing changes.
        "mkdir -p /etc/hg-mkdir-nested/a".to_owned(),
        format!("mkdir -p {home}/.ssh/a/b"),
        // A hidden component deeper down keeps the review the single-level
        // form gives it.
        format!("mkdir -p {scratch}/a/.ssh/b"),
    ] {
        for harness in ["claude-code", "codex", "cursor", "zcode"] {
            assert_ne!(
                action(&fixture, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
