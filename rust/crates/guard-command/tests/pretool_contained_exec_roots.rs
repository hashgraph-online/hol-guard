#![cfg(unix)]

use crate::git_helper_fixture::git_github_controls;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const OUTSIDE_ROOTS: &str = "native_workspace_containment_executable_outside_roots";

fn fixture() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/contained-exec-root-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project/tools")).unwrap();
    std::fs::create_dir_all(root.join("installed")).unwrap();
    std::fs::canonicalize(root).unwrap()
}

fn tool(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn decide(root: &Path, search_path: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    let project = root.join("project");
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: search_path.to_owned(),
        environment_names: Vec::new(),
        environment_digest: "0".repeat(64),
        home: root.to_str().map(str::to_owned),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    // Containment only converts a review when the device's controls are present.
    let controls = git_github_controls("default", "default");
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        Some(&controls),
        None,
        guard_command::pretool::PathContext {
            home_dir: root.to_str(),
            cwd: project.to_str(),
            cdpath_unset: true,
            ..guard_command::pretool::PathContext::default()
        },
        Some(&environment),
    )
}

#[test]
fn a_cli_installed_outside_the_sandbox_roots_stays_a_setup_review() {
    let root = fixture();
    tool(&root.join("installed/lanectl"), "#!/bin/sh\necho up\n");
    let search_path = format!("{}:/usr/bin:/bin", root.join("installed").display());

    let result = decide(&root, &search_path, "lanectl status");

    assert_ne!(result.minimum_action, "sandbox-required");
    assert_eq!(result.minimum_action, "review");
    if cfg!(target_os = "macos") {
        assert_eq!(result.reason_code, OUTSIDE_ROOTS);
        assert!(!result.reason.contains("http"));
    }
}

#[test]
fn a_workspace_script_with_an_outside_interpreter_stays_a_review() {
    let root = fixture();
    let interpreter = root.join("installed/lanectl-python");
    tool(&interpreter, "");
    tool(
        &root.join("project/tools/lanectl"),
        &format!("#!{}\n", interpreter.display()),
    );

    let result = decide(&root, "/usr/bin:/bin", "./tools/lanectl status");

    assert_ne!(result.minimum_action, "sandbox-required");
}

#[test]
fn a_workspace_program_the_sandbox_can_run_is_still_contained() {
    let root = fixture();
    tool(&root.join("project/tools/lanectl"), "#!/bin/sh\necho up\n");

    let result = decide(&root, "/usr/bin:/bin", "./tools/lanectl status");

    if cfg!(target_os = "macos") {
        assert_eq!(result.minimum_action, "sandbox-required");
        assert_eq!(result.reason_code, "native_workspace_containment_required");
    }
}

#[test]
fn a_relative_program_after_a_cd_is_judged_from_that_directory() {
    let root = fixture();
    let interpreter = root.join("installed/lanectl-python");
    tool(&interpreter, "");
    tool(
        &root.join("project/tools/lanectl"),
        &format!("#!{}\n", interpreter.display()),
    );
    tool(&root.join("project/tools/ready"), "#!/bin/sh\necho up\n");

    let outside = decide(&root, "/usr/bin:/bin", "cd tools && ./lanectl status");
    let inside = decide(&root, "/usr/bin:/bin", "cd tools && ./ready status");

    assert_ne!(outside.minimum_action, "sandbox-required");
    if cfg!(target_os = "macos") {
        assert_eq!(inside.minimum_action, "sandbox-required");
    }
}
