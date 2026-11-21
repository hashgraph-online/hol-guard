#![cfg(unix)]

use super::names_secret_alias;
use crate::pretool::workspace_contained_tests::controls;
use crate::pretool::{evaluate_pre_tool_with_context, PathContext};
use crate::{parse_command, CommandModelRequestV1};
use guard_contracts::PreToolResultV1;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

const SENSITIVE: &str = "native_sensitive_access_review";
const CONTAINED: &str = "native_workspace_containment_required";
/// Hosts whose agents read files through a shell tool.
const HARNESSES: &[&str] = &["codex", "claude-code"];

/// A home with an SSH key and a project holding `.env`, `.aws/credentials`
/// and ordinary notes, plus links to each under ordinary names.
struct Fixture {
    home: PathBuf,
    project: PathBuf,
}

fn fixture(name: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!("guard-alias-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(project.join("aliases")).unwrap();
    std::fs::create_dir_all(project.join(".aws")).unwrap();
    std::fs::write(home.join(".ssh/id_ed25519"), "synthetic key\n").unwrap();
    std::fs::write(project.join(".env"), "TOKEN=synthetic\n").unwrap();
    std::fs::write(project.join(".aws/credentials"), "[default]\n").unwrap();
    std::fs::write(project.join("notes.md"), "notes\n").unwrap();
    let aliases = project.join("aliases");
    symlink(project.join(".env"), aliases.join("ordinary.txt")).unwrap();
    symlink(aliases.join("ordinary.txt"), aliases.join("hop.txt")).unwrap();
    symlink(home.join(".ssh/id_ed25519"), aliases.join("key.txt")).unwrap();
    symlink(project.join(".aws"), project.join("cfg")).unwrap();
    symlink(project.join("notes.md"), aliases.join("readme.txt")).unwrap();
    symlink(project.join("aliases"), project.join("docs")).unwrap();
    Fixture {
        home: home.canonicalize().unwrap(),
        project: project.canonicalize().unwrap(),
    }
}

fn shell(harness: &str, command: &str, fixture: &Fixture) -> PreToolResultV1 {
    let controls = controls();
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        fixture.home.to_str(),
        fixture.project.to_str(),
    )
}

fn aliased(command: &str, fixture: &Fixture) -> bool {
    let model = parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "pre-tool-generic".to_owned(),
    })
    .unwrap();
    names_secret_alias(
        &model,
        PathContext {
            home_dir: fixture.home.to_str(),
            cwd: fixture.project.to_str(),
            ..PathContext::default()
        },
    )
}

const SECRET_ALIAS_READS: &[&str] = &[
    "cat aliases/ordinary.txt",
    "head -n 5 aliases/ordinary.txt",
    "tail aliases/ordinary.txt",
    "sed -n 1,5p aliases/ordinary.txt",
    "wc -l aliases/ordinary.txt",
    // A link to a link, a linked directory, and a link leaving the project.
    "cat aliases/hop.txt",
    "cat docs/ordinary.txt",
    "cat cfg/credentials",
    "cat aliases/key.txt",
    "cat notes.md aliases/ordinary.txt",
];

#[test]
fn a_link_to_a_secret_is_read_like_the_secret() {
    let fixture = fixture("secret");
    for harness in HARNESSES {
        let direct = shell(harness, "cat .env", &fixture);
        assert_eq!(direct.reason_code, SENSITIVE, "{harness}");
        for command in SECRET_ALIAS_READS {
            assert!(aliased(command, &fixture), "{command}");
            let result = shell(harness, command, &fixture);
            assert_eq!(
                (result.reason_code.as_str(), result.minimum_action.as_str()),
                (direct.reason_code.as_str(), direct.minimum_action.as_str()),
                "{harness} {command}"
            );
            assert!(result.action.sensitive_target, "{harness} {command}");
            assert_ne!(result.reason_code, CONTAINED, "{harness} {command}");
        }
    }
}

#[test]
fn the_command_authority_reviews_a_link_to_a_secret() {
    let fixture = fixture("authority");
    for command in SECRET_ALIAS_READS {
        let decision = evaluate_pre_tool_with_context(
            &CommandModelRequestV1 {
                command: (*command).to_owned(),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "pre-tool-generic".to_owned(),
            },
            fixture.home.to_str(),
            fixture.project.to_str(),
        )
        .unwrap();
        assert_eq!(decision.minimum_action, "review", "{command}");
        assert_eq!(decision.reason_code, SENSITIVE, "{command}");
    }
}

#[test]
fn links_to_ordinary_files_keep_their_verdict() {
    let fixture = fixture("ordinary");
    for command in [
        "cat aliases/readme.txt",
        "head -n 5 docs/readme.txt",
        "ls -la aliases",
        "cat notes.md",
    ] {
        assert!(!aliased(command, &fixture), "{command}");
        for harness in HARNESSES {
            let result = shell(harness, command, &fixture);
            assert_ne!(result.reason_code, SENSITIVE, "{harness} {command}");
            assert!(!result.action.sensitive_target, "{harness} {command}");
        }
    }
}

#[test]
fn spelled_secrets_and_missing_paths_are_left_to_the_text_screens() {
    let fixture = fixture("spelled");
    for command in [
        "cat .env",
        "cat missing.txt",
        "grep --file=aliases/missing.txt x notes.md",
        "echo aliases",
    ] {
        assert!(!aliased(command, &fixture), "{command}");
    }
    assert!(aliased(
        "grep --file=aliases/ordinary.txt x notes.md",
        &fixture
    ));
}
