#![cfg(windows)]
//! A session started beside its checkouts steps into one and reads it:
//! `cd C:/Users/me/other-project && git log -1`. Unix has admitted that for
//! as long as the contained route has existed, because the directory is the
//! nearest `.git` ancestor under the agent's own profile and the sink rebases
//! its approved root to it. Windows had no way to ask who owns a directory,
//! so `sibling_project_root` was a stub returning `None` and every sibling
//! shape arrived as a review prompt — a false positive on the platform, not a
//! different policy. The crate's unit tests need Unix, so this proof runs as
//! its own test binary.

#[allow(dead_code)]
#[path = "support/git_helper_fixture.rs"]
mod git_helper_fixture;

use git_helper_fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

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

/// A committed repository at `root`.
fn repository(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    git(root, &["init", "--quiet"]);
    git(root, &["config", "user.name", "Guard Fixture"]);
    git(
        root,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(root.join("tracked.txt"), "fixture\n").unwrap();
    git(root, &["add", "tracked.txt"]);
    git(root, &["commit", "--quiet", "-m", "fixture"]);
}

/// The drive path an agent spells, with forward slashes.
fn spelled(path: &Path) -> String {
    path.to_str()
        .unwrap()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}

/// A profile holding the session and its sibling checkouts, plus one
/// repository outside the profile entirely.
fn layout(name: &str) -> (PathBuf, PathBuf) {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&parent).unwrap();
    let root = parent
        .canonicalize()
        .unwrap()
        .join(format!("{name}-{}", std::process::id()));
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    (root, home)
}

/// A junction at `link` pointing at `target`, which a standard user may make.
fn junction(link: &Path, target: &Path) -> bool {
    std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn reading_a_sibling_checkout_under_the_profile_is_proved_on_windows() {
    let (root, home) = layout("guard-win-sibling");
    let _cleanup = FixtureCleanup(root.clone());
    let session = home.join("project");
    repository(&session);
    let sibling = home.join("other-project");
    repository(&sibling);
    // A directory under the profile that is not a checkout at all.
    std::fs::create_dir_all(home.join("Documents")).unwrap();
    // A checkout the profile does not contain.
    let outside = root.join("outside-project");
    repository(&outside);

    let home_text = spelled(&home);
    let cwd = spelled(&session);
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
                pip_config_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
                psql_environment: Default::default(),
            },
            Some(&environment),
        )
        .minimum_action
    };

    assert_eq!(
        action(&format!(
            "cd {} && git log -1 --format='%H %s'",
            spelled(&sibling)
        )),
        "allow"
    );
    for command in [
        // Not a checkout, so there is no root for the sink to rebase to.
        format!("cd {} && git log -1", spelled(&home.join("Documents"))),
        // Outside the profile the agent's ownership says nothing.
        format!("cd {} && git log -1", spelled(&outside)),
        // The profile itself is not a sibling of the session.
        format!("cd {home_text} && git log -1"),
    ] {
        assert_ne!(action(&command), "allow", "{command}");
    }

    // A junction outside the profile pointing into it: the target resolves
    // inside home, so containment holds, but its spelled ancestors never
    // equal the profile. The nearest `.git` above it is `outside-project`'s,
    // which the agent owns, so a walk that stopped only at the profile would
    // hand back a root outside it.
    let escape = outside.join("link");
    if junction(&escape, &home.join("Documents")) {
        assert_ne!(
            action(&format!("cd {} && git log -1", spelled(&escape))),
            "allow",
            "a junction must not walk out of the profile"
        );
    }
}
