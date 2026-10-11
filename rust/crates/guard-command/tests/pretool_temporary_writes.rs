#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::{PreToolActionTypeV1, PreToolResultV1};
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
/// is a private, user-owned directory directly under `/tmp`.
fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-temporary-writes")
        .join(format!("{name}-{}", std::process::id()));
    let home = root.join("home");
    let workspace = home.join("project");
    std::fs::create_dir_all(&workspace).unwrap();
    let scratch = PathBuf::from(format!(
        "/tmp/hg-temporary-write-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
    Fixture {
        home: std::fs::canonicalize(home).unwrap(),
        workspace: std::fs::canonicalize(workspace).unwrap(),
        scratch,
    }
}

fn write(fixture: &Fixture, target: &Path) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &json!({
            "toolName": "Write", "tool_name": "Write",
            "toolInput": {"file_path": target.to_string_lossy(), "content": "query"},
            "tool_input": {"file_path": target.to_string_lossy(), "content": "query"}
        }),
        None,
        None,
        fixture.home.to_str(),
        fixture.workspace.to_str(),
    )
}

#[test]
fn write_into_owned_temporary_directory_is_bounded() {
    let fixture = fixture("owned");
    let result = write(&fixture, &fixture.scratch.join("threads-query.txt"));
    assert_eq!(result.action.action_type, PreToolActionTypeV1::FileWrite);
    assert_eq!(result.minimum_action, "allow");
    assert_eq!(result.reason_code, "native_exact_safe_file_write");

    std::fs::write(fixture.scratch.join("existing.mjs"), "x").unwrap();
    let overwrite = write(&fixture, &fixture.scratch.join("existing.mjs"));
    assert_eq!(overwrite.reason_code, "native_exact_safe_file_write");
}

#[test]
fn temporary_write_keeps_link_permission_and_hidden_boundaries() {
    let fixture = fixture("bounded");
    let outside = fixture.workspace.join("target.txt");
    std::fs::write(&outside, "x").unwrap();

    let link = fixture.scratch.join("link.txt");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    let hard = fixture.scratch.join("hard.txt");
    std::fs::hard_link(&outside, &hard).unwrap();

    let shared = fixture.scratch.join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();

    let hooks = fixture.scratch.join("repo/.git/hooks");
    std::fs::create_dir_all(&hooks).unwrap();

    for target in [
        link,
        hard,
        shared.join("notes.txt"),
        hooks.join("pre-commit"),
        fixture.scratch.join("missing/notes.txt"),
        fixture.scratch.join("../notes.txt"),
    ] {
        let result = write(&fixture, &target);
        assert_ne!(result.minimum_action, "allow", "{}", target.display());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn configured_darwin_temp_root_keeps_owned_leaf_and_overwrite_proofs() {
    let mut fixture = fixture("darwin");
    std::fs::remove_dir(&fixture.scratch).unwrap();
    fixture.scratch = std::env::temp_dir().join(format!("hg-darwin-write-{}", std::process::id()));
    std::fs::create_dir(&fixture.scratch).unwrap();
    std::fs::set_permissions(&fixture.scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = fixture.scratch.join("scratch-notes.txt");
    assert_eq!(write(&fixture, &target).minimum_action, "allow");
    std::fs::write(&target, "first draft").unwrap();
    assert_eq!(write(&fixture, &target).minimum_action, "allow");
    let hard = fixture.scratch.join("hard.txt");
    std::fs::hard_link(&target, &hard).unwrap();
    assert_ne!(write(&fixture, &hard).minimum_action, "allow");
    let link = fixture.scratch.join("linked.txt");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_ne!(write(&fixture, &link).minimum_action, "allow");
    std::fs::set_permissions(&fixture.scratch, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_ne!(
        write(&fixture, &fixture.scratch.join("public.txt")).minimum_action,
        "allow"
    );
}
