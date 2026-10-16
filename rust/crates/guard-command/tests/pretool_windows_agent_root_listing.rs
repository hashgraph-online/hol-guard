#![cfg(windows)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

use crate::git_helper_fixture as fixture;

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn windows_agent_root_listings_accept_backslash_home_spellings() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/windows-agent-root-listing")
        .join(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let _cleanup = fixture::FixtureCleanup(root.clone());
    std::fs::create_dir_all(&root).unwrap();
    let canonical_root = std::fs::canonicalize(&root).unwrap();
    let spelling = canonical_root.to_str().unwrap();
    let root = PathBuf::from(spelling.strip_prefix(r"\\?\").unwrap_or(spelling));
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    write(home.join(".agent/skills/demo/SKILL.md"), "inert skill\n");
    write(home.join(".agent/artifacts/report.md"), "Inert report\n");
    write(home.join(".ssh/id_rsa"), "synthetic sensitive fixture\n");
    let home_spelling = home.display().to_string();
    let allowed = |command: String| {
        evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash","tool_input":{"command":command}}),
            None,
            None,
            home.to_str(),
            project.to_str(),
        )
        .minimum_action
            == "allow"
    };
    for command in [
        format!("ls '{home_spelling}'/.agent"),
        format!("ls -R '{home_spelling}'/.agent"),
        format!("ls -R '{home_spelling}\\.agent'"),
    ] {
        assert!(allowed(command.clone()), "{command}");
    }
    for command in [
        format!("grep -r Inert '{home_spelling}\\.agent'"),
        format!("ls -R '{home_spelling}\\.ssh'"),
        format!("ls -R '{home_spelling}\\.agent\\skills\\..'"),
    ] {
        assert!(!allowed(command.clone()), "{command}");
    }
    let hidden = home.join(".agent/artifacts/.hidden/report.md");
    write(hidden, "synthetic sensitive fixture\n");
    assert!(!allowed(format!("ls -R '{home_spelling}\\.agent'")));
    assert!(!allowed(format!(
        "ls -rec -Force '{home_spelling}\\.agent'"
    )));
}

#[test]
fn windows_missing_git_marker_probe_accepts_backslash_home_spellings() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/windows-missing-git-marker")
        .join(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let _cleanup = fixture::FixtureCleanup(root.clone());
    std::fs::create_dir_all(&root).unwrap();
    let canonical_root = std::fs::canonicalize(&root).unwrap();
    let spelling = canonical_root.to_str().unwrap();
    let root = PathBuf::from(spelling.strip_prefix(r"\\?\").unwrap_or(spelling));
    let home = root.join("home");
    let project = home.join("project");
    write(home.join("plain/README.md"), "plain directory\n");
    write(project.join("README.md"), "project\n");
    let home_spelling = home.display().to_string();
    let allowed = |command: String| {
        evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash","tool_input":{"command":command}}),
            None,
            None,
            home.to_str(),
            project.to_str(),
        )
        .minimum_action
            == "allow"
    };
    for command in [
        format!("ls -d '{home_spelling}'/plain/.git; ls '{home_spelling}'/plain"),
        format!("ls -d '{home_spelling}\\plain\\.git'"),
    ] {
        assert!(allowed(command.clone()), "{command}");
    }
    for command in [
        format!("ls -d '{home_spelling}\\plain\\.ssh'"),
        format!("ls -d '{home_spelling}\\plain\\.git\\config'"),
        format!("ls -d '{home_spelling}\\plain\\..\\.ssh'"),
        format!("ls -d '{home_spelling}\\missing\\.aws'"),
    ] {
        assert!(!allowed(command.clone()), "{command}");
    }
    // A Windows host may run this text in PowerShell or cmd, where
    // `2>/dev/null` opens `\dev\null` on the current drive. That writes
    // nothing while no drive has a `\dev` directory, and is reviewed once one
    // does.
    let dev_directory =
        (b'A'..=b'Z').any(|drive| Path::new(&format!("{}:\\dev", drive as char)).exists());
    assert_eq!(
        allowed("ls README.md 2>/dev/null".to_owned()),
        !dev_directory
    );
}
