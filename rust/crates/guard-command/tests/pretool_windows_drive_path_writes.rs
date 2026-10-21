#![cfg(windows)]
//! Agents on Windows spell absolute paths as `C:/...` drive paths: a scratch
//! copy saved into the profile's temporary folder, a patch checked from
//! there, and a worktree added beside the session's repository. Each is the
//! same bounded action the POSIX spelling already proves.

#[allow(dead_code)]
#[path = "support/git_helper_fixture.rs"]
mod git_helper_fixture;

use git_helper_fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

fn git(repository: &Path, arguments: &[&str]) -> Vec<u8> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{arguments:?}");
    output.stdout
}

/// The drive path an agent spells, with forward slashes.
fn spelled(path: &Path) -> String {
    path.to_str()
        .unwrap()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}

struct Session {
    _cleanup: FixtureCleanup,
    home: PathBuf,
    temporary: PathBuf,
    project: PathBuf,
    sibling: PathBuf,
}

/// A home holding the session's repository, a sibling repository and the
/// profile's own `AppData\Local\Temp`.
fn session(name: &str) -> Session {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&parent).unwrap();
    let home = parent
        .canonicalize()
        .unwrap()
        .join(format!("guard-drive-writes-{name}-{}", std::process::id()));
    let cleanup = FixtureCleanup(home.clone());
    let temporary = home.join("AppData").join("Local").join("Temp");
    std::fs::create_dir_all(&temporary).unwrap();
    let project = home.join("project");
    let sibling = home.join("other-project");
    for repository in [&project, &sibling] {
        std::fs::create_dir_all(repository.join("src")).unwrap();
        git(repository, &["init", "--quiet"]);
        git(repository, &["config", "user.name", "Guard Fixture"]);
        git(
            repository,
            &["config", "user.email", "guard-fixture@example.invalid"],
        );
        std::fs::write(repository.join("src/report.ts"), "export const a = 1;\n").unwrap();
        git(repository, &["add", "src/report.ts"]);
        git(repository, &["commit", "--quiet", "-m", "fixture"]);
    }
    git(&project, &["branch", "fix/report-export"]);
    Session {
        _cleanup: cleanup,
        home,
        temporary,
        project,
        sibling,
    }
}

fn action(session: &Session, command: &str) -> String {
    let home = spelled(&session.home);
    let cwd = spelled(&session.project);
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: ["GIT_CONFIG_NOSYSTEM", "HOME", "PATH"]
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

fn allowed(session: &Session, command: &str) -> bool {
    action(session, command).starts_with("allow ")
}

#[test]
fn committed_copy_saved_into_the_profile_temporary_folder_is_proved() {
    let session = session("copy");
    let sibling = spelled(&session.sibling);
    let copy = spelled(&session.temporary.join("hg-scratch-report-main.ts"));
    let save = format!("git -C {sibling} show HEAD:src/report.ts > {copy}");
    for command in [save.clone(), format!("{save} && wc -l {copy}")] {
        assert!(
            allowed(&session, &command),
            "{command}: {}",
            action(&session, &command)
        );
    }
    for target in [
        // Hidden, library and stream names, and another spelling of the folder.
        spelled(&session.temporary.join(".report-main.ts")),
        spelled(&session.temporary.join("helper.dll")),
        format!("{copy}:stream"),
        copy.to_lowercase(),
        // Home outside the temporary folder and outside a repository.
        spelled(&session.home.join("report-main.ts")),
    ] {
        let command = format!("git -C {sibling} show HEAD:src/report.ts > {target}");
        assert!(!allowed(&session, &command), "{command}");
    }
}

#[test]
fn patch_checked_from_the_profile_temporary_folder_is_proved() {
    let session = session("patch");
    let sibling = spelled(&session.sibling);
    let patch = session.temporary.join("hg-scratch-fix.patch");
    std::fs::write(&patch, git(&session.sibling, &["show", "HEAD"])).unwrap();
    let patch = spelled(&patch);
    for command in [
        format!("git -C {sibling} apply --check {patch}"),
        format!("git -C {sibling} apply --numstat {patch}"),
    ] {
        assert!(
            allowed(&session, &command),
            "{command}: {}",
            action(&session, &command)
        );
    }
    for command in [
        format!("git -C {sibling} apply --check {patch}:stream"),
        format!(
            "git -C {sibling} apply --check C:{}",
            &patch[2..].replacen('/', "", 1)
        ),
    ] {
        assert!(!allowed(&session, &command), "{command}");
    }
}

#[test]
fn worktree_added_beside_the_session_repository_is_proved() {
    let session = session("worktree");
    let project = spelled(&session.project);
    let destination = spelled(&session.home.join("project-report-fix"));
    let command = format!("git -C {project} worktree add {destination} fix/report-export");
    assert!(
        allowed(&session, &command),
        "{command}: {}",
        action(&session, &command)
    );
    // A protected destination stays reviewed.
    let workflows = spelled(&session.project.join(".github").join("workflows").join("x"));
    let command = format!("git -C {project} worktree add {workflows} fix/report-export");
    assert!(!allowed(&session, &command), "{command}");
}

#[test]
fn existing_program_in_the_profile_temporary_folder_stays_reviewed() {
    let session = session("program");
    let sibling = spelled(&session.sibling);
    for name in ["tool.exe", "setup.CMD", "run.ps1"] {
        std::fs::write(session.temporary.join(name), "program").unwrap();
        let program = spelled(&session.temporary.join(name));
        // Windows opens `tool.exe.` as `tool.exe`.
        for target in [program.clone(), format!("{program}.")] {
            let command = format!("git -C {sibling} show HEAD:src/report.ts > {target}");
            assert!(!allowed(&session, &command), "{command}");
        }
    }
    // An existing ordinary file there is still a scratch copy.
    std::fs::write(session.temporary.join("report.ts"), "old").unwrap();
    let copy = spelled(&session.temporary.join("report.ts"));
    let command = format!("git -C {sibling} show HEAD:src/report.ts > {copy}");
    assert!(
        allowed(&session, &command),
        "{command}: {}",
        action(&session, &command)
    );
}

#[test]
fn drive_path_redirect_names_no_stream_and_no_drive_relative_path() {
    let session = session("stream");
    let sibling = spelled(&session.sibling);
    let project = spelled(&session.project);
    let inside = format!("{project}/report-main.ts");
    let command = format!("git -C {sibling} show HEAD:src/report.ts > {inside}");
    assert!(
        allowed(&session, &command),
        "{command}: {}",
        action(&session, &command)
    );
    std::fs::write(session.project.join("credentials"), "secret").unwrap();
    for target in [
        format!("{inside}:stream"),
        format!("{project}/credentials:stream"),
        format!("{project}/credentials:stream:$DATA"),
        "report-main.ts:stream".to_owned(),
        format!("{}report-main.ts", &project[..2]),
    ] {
        let command = format!("git -C {sibling} show HEAD:src/report.ts > {target}");
        assert!(!allowed(&session, &command), "{command}");
    }
}

#[test]
fn existing_source_file_in_the_profile_temporary_folder_is_still_a_scratch_copy() {
    let session = session("source");
    let sibling = spelled(&session.sibling);
    // `.js` is a program extension to Windows Script Host, but a workspace
    // loads it as source the way POSIX hosts treat it.
    std::fs::write(session.temporary.join("bundle.js"), "old").unwrap();
    let copy = spelled(&session.temporary.join("bundle.js"));
    let command = format!("git -C {sibling} show HEAD:src/report.ts > {copy}");
    assert!(
        allowed(&session, &command),
        "{command}: {}",
        action(&session, &command)
    );
}
