#![cfg(windows)]
//! Agents on Windows add a scratch checkout under the profile's temporary
//! directory and read it straight away, naming both with drive paths. The
//! crate's unit tests need Unix, so this proof runs as its own test binary.

#[allow(dead_code)]
#[path = "support/git_helper_fixture.rs"]
mod git_helper_fixture;

use git_helper_fixture::FixtureCleanup;
use serde_json::json;
use std::path::Path;

fn git(repository: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "{arguments:?}");
}

/// The drive path an agent spells, with forward slashes.
fn spelled(path: &Path) -> String {
    path.to_str()
        .unwrap()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}

#[test]
fn worktree_add_then_cd_into_it_is_proved_on_windows() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&parent).unwrap();
    let home = parent
        .canonicalize()
        .unwrap()
        .join(format!("guard-worktree-cd-{}", std::process::id()));
    let _cleanup = FixtureCleanup(home.clone());
    let repository = home.join("other-project");
    let temporary = home.join("AppData").join("Local").join("Temp");
    std::fs::create_dir_all(&repository).unwrap();
    std::fs::create_dir_all(&temporary).unwrap();
    std::fs::create_dir_all(home.join("project")).unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["config", "user.name", "Guard Fixture"]);
    git(
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(repository.join("tracked.txt"), "fixture\n").unwrap();
    git(&repository, &["add", "tracked.txt"]);
    git(&repository, &["commit", "--quiet", "-m", "fixture"]);
    let home_text = spelled(&home);
    let cwd = spelled(&home.join("project"));
    let source = spelled(&repository);
    let fresh = spelled(&temporary.join("scratch-leaf"));
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: ["GIT_CONFIG_NOSYSTEM", "HOME", "PATH"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        environment_digest: "0".repeat(64),
        home: Some(home_text.clone()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    let controls = git_helper_fixture::github_controls("enabled");
    let action = |command: &str| {
        guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            Some(&controls),
            None,
            guard_command::pretool::PathContext {
                home_dir: Some(&home_text),
                cwd: Some(&cwd),
                cdpath_unset: false,
                rustup_override_absent: false,
                npm_config_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
                psql_environment: Default::default(),
            },
            Some(&environment),
        )
        .minimum_action
    };
    let add = format!("git -C {source} worktree add -q --detach {fresh} HEAD");
    assert_eq!(
        action(&format!(
            "{add} && cd {fresh} && git log -1 --format='%H %s'"
        )),
        "allow"
    );
    for command in [
        // Another directory than the one Git creates.
        format!("{add} && cd {source} && git log -1"),
        // A different spelling of the parent stays unproved.
        format!("{add} && cd {} && git log -1", fresh.to_lowercase()),
        format!("{add} && cd {} && git log -1", fresh.replace('/', "\\")),
        format!("{add} && cd {fresh}:stream && git log -1"),
        // Git Bash resolves a root-relative path against its own root.
        format!("{add} && cd /scratch-leaf && git log -1"),
    ] {
        assert_ne!(action(&command), "allow", "{command}");
    }
}
