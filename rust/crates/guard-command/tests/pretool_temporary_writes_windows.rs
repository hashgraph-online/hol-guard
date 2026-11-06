#![cfg(windows)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::{PreToolActionTypeV1, PreToolResultV1};
use serde_json::json;
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: String,
    workspace: String,
    temp: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A profile with its own `AppData\Local\Temp`, spelled as agents see it:
/// the ordinary drive path rather than the verbatim canonical form.
fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-temporary-writes-windows")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("home/project")).unwrap();
    std::fs::create_dir_all(root.join(r"home\AppData\Local\Temp\tmp.abc123")).unwrap();
    let canonical = std::fs::canonicalize(&root).unwrap();
    let drive = PathBuf::from(canonical.to_str().unwrap().trim_start_matches(r"\\?\"));
    let home = drive.join("home");
    Fixture {
        root: canonical,
        workspace: home.join("project").to_str().unwrap().to_owned(),
        temp: home.join(r"AppData\Local\Temp"),
        home: home.to_str().unwrap().to_owned(),
    }
}

fn write(fixture: &Fixture, target: &str) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &json!({
            "toolName": "Write", "tool_name": "Write",
            "toolInput": {"file_path": target, "content": "first draft"},
            "tool_input": {"file_path": target, "content": "first draft"}
        }),
        None,
        None,
        Some(fixture.home.as_str()),
        Some(fixture.workspace.as_str()),
    )
}

fn shell(fixture: &Fixture, command: &str) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &json!({
            "toolName": "Bash", "tool_name": "Bash",
            "toolInput": {"command": command},
            "tool_input": {"command": command}
        }),
        None,
        None,
        Some(fixture.home.as_str()),
        Some(fixture.workspace.as_str()),
    )
}

#[test]
fn write_into_profile_temporary_directory_is_bounded() {
    let fixture = fixture("owned");
    let target = fixture.temp.join(r"tmp.abc123\scratch-notes.txt");
    let result = write(&fixture, target.to_str().unwrap());
    assert_eq!(result.action.action_type, PreToolActionTypeV1::FileWrite);
    assert_eq!(result.minimum_action, "allow");
    assert_eq!(result.reason_code, "native_exact_safe_file_write");

    std::fs::write(&target, "first draft").unwrap();
    let overwrite = write(&fixture, target.to_str().unwrap());
    assert_eq!(overwrite.reason_code, "native_exact_safe_file_write");

    // Git Bash writes `/tmp/notes.txt` directly into the folder itself.
    let direct = write(&fixture, fixture.temp.join("notes.txt").to_str().unwrap());
    assert_eq!(direct.reason_code, "native_exact_safe_file_write");
}

#[test]
fn profile_temporary_write_keeps_spelling_link_and_leaf_boundaries() {
    let fixture = fixture("bounded");
    let scratch = fixture.temp.join("tmp.abc123");
    let outside = Path::new(&fixture.workspace).join("target.txt");
    std::fs::write(&outside, "x").unwrap();
    let hard = scratch.join("hard.txt");
    std::fs::hard_link(&outside, &hard).unwrap();
    // A junction into the workspace is an ordinary workspace write, so point
    // it at a directory outside both the workspace and home.
    let elsewhere = Path::new(&fixture.home).parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let junction = scratch.join("junction");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&elsewhere)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::create_dir_all(scratch.join(r"repo\.git\hooks")).unwrap();

    let scratch_text = scratch.to_str().unwrap();
    let mut targets = vec![
        fixture.temp.join("helper.dll").to_str().unwrap().to_owned(),
        hard.to_str().unwrap().to_owned(),
        junction.join("notes.txt").to_str().unwrap().to_owned(),
        scratch.join("helper.dll").to_str().unwrap().to_owned(),
        scratch
            .join(r"repo\.git\hooks\pre-commit")
            .to_str()
            .unwrap()
            .to_owned(),
        scratch
            .join(r"missing\notes.txt")
            .to_str()
            .unwrap()
            .to_owned(),
        format!(r"{scratch_text}\..\notes.txt"),
        format!(r"{scratch_text}\notes.txt:hidden"),
        format!(r"{}\notes.txt", scratch_text.to_uppercase()),
    ];
    // A short-name spelling of the temporary directory names the same place
    // through a different path.
    if let Some(short) = scratch_text
        .rfind('\\')
        .map(|at| format!(r"{}\TMPABC~1", &scratch_text[..at]))
    {
        targets.push(format!(r"{short}\notes.txt"));
    }
    for target in targets {
        let result = write(&fixture, &target);
        assert_ne!(result.minimum_action, "allow", "{target}");
    }
    std::fs::remove_dir(&junction).unwrap();
}

#[test]
fn copy_into_profile_temporary_directory_needs_a_quoted_drive_path() {
    let fixture = fixture("copy");
    std::fs::write(Path::new(&fixture.workspace).join("notes.txt"), "x").unwrap();
    let destination = fixture.temp.join(r"tmp.abc123\notes.txt");
    let destination = destination.to_str().unwrap();
    let quoted = shell(&fixture, &format!("cp notes.txt '{destination}'"));
    assert_eq!(quoted.minimum_action, "allow", "{}", quoted.reason_code);
    // Bash drops unquoted backslashes, so the copy would land elsewhere.
    let unquoted = shell(&fixture, &format!("cp notes.txt {destination}"));
    assert_ne!(unquoted.minimum_action, "allow");
}
