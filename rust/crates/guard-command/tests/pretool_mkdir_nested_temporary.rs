#![cfg(unix)]
//! `mkdir -p` of a nested path below a private temporary directory, and
//! `mkdir` with several targets.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    scratch: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
        let _ = std::fs::remove_dir_all(&self.root);
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
    let scratch = PathBuf::from(format!(
        "/tmp/hg-mkdir-nested-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&scratch);
    // Owns both trees from here on, so a failed setup step cleans up too.
    let mut fixture = Fixture {
        root: root.clone(),
        home: PathBuf::new(),
        workspace: PathBuf::new(),
        scratch: scratch.clone(),
    };
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
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
    fixture.home = std::fs::canonicalize(home).unwrap();
    fixture.workspace = std::fs::canonicalize(workspace).unwrap();
    fixture
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

#[test]
fn several_targets_pass_when_each_passes_alone() {
    let fixture = fixture("several");
    let scratch = fixture.scratch.display();
    let fresh = format!("/tmp/hg-mkdir-several-fresh-{}", std::process::id());
    for harness in ["claude-code", "codex", "cursor", "zcode"] {
        for command in [
            format!("mkdir -p {fresh}/a {fresh}/b"),
            format!("mkdir --parents {scratch}/build/out {scratch}/private/logs"),
            format!("mkdir -p -- {fresh}/x {fresh}/y/z"),
            format!("mkdir {scratch}/one {scratch}/two"),
            "mkdir -p src/notes docs/notes".to_owned(),
            format!("mkdir -p notes/a {fresh}/c"),
            format!("mkdir -p src/x && mkdir -p {fresh}/d {fresh}/e"),
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
fn one_failing_target_keeps_several_in_review() {
    let fixture = fixture("several-refused");
    let scratch = fixture.scratch.display();
    let home = fixture.home.display();
    let fresh = format!("/tmp/hg-mkdir-several-refused-{}", std::process::id());
    let many = (0..17)
        .map(|index| format!("{fresh}/n{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    for command in [
        format!("mkdir -p {fresh}/a {home}/.ssh/b"),
        format!("mkdir -p {fresh}/a /etc/hg-mkdir-several"),
        format!("mkdir -p {fresh}/a {scratch}/shared/b/c"),
        format!("mkdir -p {fresh}/a {scratch}/keys/b"),
        // An option after a target is refused, wherever it sits.
        format!("mkdir {fresh}/a -p {fresh}/b/c"),
        format!("mkdir -p {fresh}/a --mode=777 {fresh}/b"),
        // Only `-p` admits a nested new temporary path.
        format!("mkdir -- {fresh}/a/b {fresh}/c"),
        // A hard cap on how many targets one command may name.
        format!("mkdir -p {many}"),
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
