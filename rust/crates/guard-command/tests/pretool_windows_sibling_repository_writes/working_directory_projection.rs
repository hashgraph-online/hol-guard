#![cfg(windows)]
//! A shell command that names its own working directory — `$(pwd)`, `$PWD`,
//! `$(dirname "$PWD")` — is judged on the path that use prints, not on the
//! opaque expansion. The projection behind that read accepted only a POSIX
//! absolute directory, so on Windows it never ran and ordinary reads blocked
//! with `native_command_review_required`. The same shapes the POSIX spelling
//! already proves must hold for a drive path, whichever separator the
//! harness spells it with, and the narrow set of uses the projection
//! recognizes must stay narrow.

// Compiled into the `pretool_windows_sibling_repository_writes` binary, which
// owns the shared fixture module, so the Windows lane links one executable.
use super::git_helper_fixture::{self, FixtureCleanup};
use serde_json::json;
use std::path::{Path, PathBuf};

/// The drive path an agent spells, with forward slashes.
fn forward(path: &Path) -> String {
    path.to_str()
        .unwrap()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}

/// The same drive path spelled with the separator Windows itself prints.
fn backward(path: &Path) -> String {
    forward(path).replace('/', "\\")
}

struct Session {
    _cleanup: FixtureCleanup,
    home: PathBuf,
    project: PathBuf,
}

fn session(name: &str) -> Session {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&parent).unwrap();
    let home = parent.canonicalize().unwrap().join(format!(
        "guard-pwd-projection-{name}-{}",
        std::process::id()
    ));
    let cleanup = FixtureCleanup(home.clone());
    let project = home.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/report.ts"), "export const a = 1;\n").unwrap();
    Session {
        _cleanup: cleanup,
        home,
        project,
    }
}

fn action(session: &Session, command: &str, spell: fn(&Path) -> String) -> String {
    let home = spell(&session.home);
    let cwd = spell(&session.project);
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: ["HOME", "PATH"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.clone()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    let controls = git_helper_fixture::github_controls("enabled");
    let result = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls),
        None,
        guard_command::pretool::PathContext {
            home_dir: Some(&home),
            cwd: Some(&cwd),
            cdpath_unset: false,
            rustup_override_absent: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
        },
        Some(&environment),
    );
    format!("{} {}", result.minimum_action, result.reason_code)
}

fn allowed(session: &Session, command: &str, spell: fn(&Path) -> String) -> bool {
    action(session, command, spell).starts_with("allow ")
}

#[test]
fn a_command_naming_its_working_directory_is_read_as_the_path_it_prints() {
    let session = session("uses");
    // `$(dirname "$PWD")` is left out on purpose: its producer is still not
    // recognized on this host, so the parent substitution reaches review for a
    // reason this projection does not own.
    let command = r#"echo "$(pwd)""#;
    assert!(
        allowed(&session, command, forward),
        "{command}: {}",
        action(&session, command, forward)
    );
}

#[test]
fn the_separator_the_harness_spells_the_directory_with_does_not_change_the_reading() {
    let session = session("separator");
    for command in [r#"echo "$(pwd)""#, r#"echo "$(dirname "$PWD")""#] {
        assert_eq!(
            action(&session, command, backward),
            action(&session, command, forward),
            "{command}"
        );
    }
}

#[test]
fn projecting_the_directory_does_not_admit_what_a_use_is_passed_to() {
    let session = session("narrow");
    for command in [
        r#"echo "$(curl "$PWD")""#,
        r#"echo "$(rm -rf "$PWD")""#,
        r#"echo "$(cat "$HOME/.env")""#,
    ] {
        assert!(
            !allowed(&session, command, forward),
            "{command}: {}",
            action(&session, command, forward)
        );
    }
}
