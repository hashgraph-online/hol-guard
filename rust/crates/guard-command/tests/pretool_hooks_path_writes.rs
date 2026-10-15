#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(home: &Path, directory: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(directory)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// `home/project`, a repository with a visible `hooks` directory that holds
/// a `pre-commit` file, configured as the hooks directory when `configured`.
fn project(name: &str, configured: bool) -> (PathBuf, PathBuf) {
    // Avoid macOS's protected /private/var temporary root.
    let home = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-hooks-path")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let project = home.join("project");
    std::fs::create_dir_all(project.join("hooks")).unwrap();
    let home = home.canonicalize().unwrap();
    let project = project.canonicalize().unwrap();
    git(&home, &project, &["init", "--quiet"]);
    if configured {
        git(&home, &project, &["config", "core.hooksPath", "hooks"]);
    }
    for file in ["notes.txt", "hooks/pre-commit"] {
        std::fs::write(project.join(file), "synthetic fixture\n").unwrap();
    }
    (home, project)
}

fn action(harness: &str, input: Value, home: &Path, workspace: &Path) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &input,
        None,
        None,
        home.to_str(),
        workspace.to_str(),
    )
    .minimum_action
}

fn shell_allowed(command: &str, home: &Path, workspace: &Path) -> bool {
    let input = json!({"toolName": "Bash", "toolInput": {"command": command}});
    let zcode = action("zcode", input.clone(), home, workspace);
    assert_eq!(
        zcode,
        action("omp", input, home, workspace),
        "host policy drift: {command}"
    );
    zcode == "allow"
}

fn write_allowed(path: &Path, home: &Path, workspace: &Path) -> bool {
    let input = json!({
        "toolName": "Write",
        "toolInput": {"file_path": path, "content": "#!/bin/sh\necho hook\n"}
    });
    action("claude-code", input, home, workspace) == "allow"
}

const HOOK_WRITES: &[&str] = &[
    "echo x > hooks/pre-commit",
    "printf 'x\\n' >> hooks/post-checkout",
    "cp notes.txt hooks/pre-commit",
    "mv notes.txt hooks/pre-push",
];

#[test]
fn writes_into_the_configured_hooks_directory_are_not_allowed() {
    let (home, project) = project("configured", true);
    for command in HOOK_WRITES.iter().chain(&[
        "echo x | tee hooks/pre-commit",
        "tee hooks/commit-msg < notes.txt",
        "ln -s ../notes.txt hooks/post-merge",
    ]) {
        assert!(!shell_allowed(command, &home, &project), "{command}");
    }
    assert!(!write_allowed(
        &project.join("hooks/pre-commit"),
        &home,
        &project
    ));
    assert!(!write_allowed(
        &project.join("hooks/post-merge"),
        &home,
        &project
    ));
    for command in ["ls hooks", "ls -la hooks", "cat hooks/pre-commit"] {
        assert!(shell_allowed(command, &home, &project), "{command}");
    }
    assert!(shell_allowed("echo x > notes.txt", &home, &project));
    assert!(write_allowed(&project.join("src/app.ts"), &home, &project));
}

#[test]
fn an_ordinary_hooks_directory_stays_writable() {
    let (home, project) = project("ordinary", false);
    for command in HOOK_WRITES {
        assert!(shell_allowed(command, &home, &project), "{command}");
    }
    assert!(write_allowed(
        &project.join("hooks/pre-commit"),
        &home,
        &project
    ));
    assert!(shell_allowed("ls hooks", &home, &project));
}
