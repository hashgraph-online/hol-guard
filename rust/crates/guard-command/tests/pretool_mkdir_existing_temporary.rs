#![cfg(unix)]
//! `mkdir -p` of a temporary directory that already exists.
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

fn private_directory(path: &Path, mode: u32) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Home and workspace stay outside the temporary roots. The scratch directory
/// is a user-owned directory directly under `/tmp` that holds a private
/// directory, a directory anyone may write to, a file and a link out to home.
fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-mkdir-existing-temporary")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("project");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let scratch = PathBuf::from(format!(
        "/tmp/hg-mkdir-existing-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    private_directory(&scratch, 0o755);
    private_directory(&scratch.join("private"), 0o700);
    private_directory(&scratch.join("shared"), 0o777);
    std::fs::write(scratch.join("notes.txt"), "notes\n").unwrap();
    std::os::unix::fs::symlink(home.join(".ssh"), scratch.join("keys")).unwrap();
    Fixture {
        root,
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
fn mkdir_of_an_existing_private_temporary_directory_is_bounded() {
    let fixture = fixture("allowed");
    let scratch = fixture.scratch.display();
    for harness in ["claude-code", "codex", "cursor", "zcode"] {
        for command in [
            format!("mkdir -p {scratch}"),
            format!("mkdir --parents {scratch}"),
            format!("mkdir -p {scratch}/private"),
            format!("mkdir -p {scratch}/private/run"),
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
fn mkdir_of_an_existing_temporary_path_that_is_not_private_keeps_its_review() {
    let fixture = fixture("refused");
    let scratch = fixture.scratch.display();
    for command in [
        // Anyone may write to it, so it could be swapped.
        format!("mkdir -p {scratch}/shared"),
        // A link at the leaf resolves into home.
        format!("mkdir -p {scratch}/keys"),
        // A file is not a directory.
        format!("mkdir -p {scratch}/notes.txt"),
        // The temporary root itself is not the user's.
        "mkdir -p /tmp".to_owned(),
        // `touch` still needs a file it owns.
        format!("touch {scratch}/private"),
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
