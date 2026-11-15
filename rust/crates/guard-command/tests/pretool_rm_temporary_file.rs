#![cfg(unix)]
//! `rm` of the user's own scratch files in a private temporary directory.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    scratch: PathBuf,
    loose: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_file(&self.loose);
    }
}

fn directory(path: &Path, mode: u32) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Home and workspace stay outside the temporary roots. The scratch directory
/// under `/tmp` belongs to the user and holds files, a folder, a folder
/// anyone may write to and a hard-linked file; a loose file sits directly in
/// `/tmp`.
fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-rm-temporary-file")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("project");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(home.join("notes.txt"), "home notes\n").unwrap();
    let scratch = PathBuf::from(format!(
        "/tmp/hg-rm-temporary-{name}-{}",
        std::process::id()
    ));
    let loose = PathBuf::from(format!(
        "/tmp/hg-rm-loose-{name}-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    directory(&scratch, 0o755);
    directory(&scratch.join("out"), 0o700);
    directory(&scratch.join("shared"), 0o777);
    for file in ["probe.txt", "probe.patch", "shared/left.txt"] {
        std::fs::write(scratch.join(file), "x\n").unwrap();
    }
    std::fs::hard_link(home.join("notes.txt"), scratch.join("alias.txt")).unwrap();
    std::fs::write(&loose, "x\n").unwrap();
    Fixture {
        root,
        home: std::fs::canonicalize(home).unwrap(),
        workspace: std::fs::canonicalize(workspace).unwrap(),
        scratch,
        loose,
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
fn rm_of_the_users_own_temporary_files_is_bounded() {
    let fixture = fixture("allowed");
    let scratch = fixture.scratch.display();
    let loose = fixture.loose.display();
    let absent = format!("/tmp/hg-rm-absent-{}.txt", std::process::id());
    for harness in ["claude-code", "codex", "cursor", "zcode"] {
        for command in [
            format!("rm {scratch}/probe.txt"),
            format!("rm -f {scratch}/probe.txt {scratch}/probe.patch"),
            format!("rm {loose}"),
            format!("rm -f {absent}"),
            format!("rm {scratch}/probe.patch {absent} 2>/dev/null"),
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
fn rm_of_a_temporary_path_the_user_does_not_solely_own_keeps_its_review() {
    let fixture = fixture("refused");
    let scratch = fixture.scratch.display();
    for command in [
        // Anyone may write to the folder holding it.
        format!("rm {scratch}/shared/left.txt"),
        // A second name for a home file.
        format!("rm {scratch}/alias.txt"),
        // A folder, and a recursive removal.
        format!("rm {scratch}/out"),
        format!("rm -r {scratch}/out"),
        format!("rm -rf {scratch}"),
        // Outside the temporary roots nothing changes.
        "rm /etc/hosts".to_owned(),
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
