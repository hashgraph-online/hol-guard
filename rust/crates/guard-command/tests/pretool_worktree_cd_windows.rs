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
    let host = std::env::var("PATH").unwrap();
    let environment_on = |path: String| guard_contracts::GuardExecutionEnvironmentV1 {
        path,
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
        ..Default::default()
    };
    let controls = git_helper_fixture::github_controls("enabled");
    let action_on = |command: &str, path: String| {
        let environment = environment_on(path);
        guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            Some(&controls),
            None,
            guard_command::pretool::PathContext {
                literal_words: &[],
                guard_home: None,
                home_dir: Some(&home_text),
                cwd: Some(&cwd),
                cdpath_unset: false,
                rustup_override_absent: false,
                go_toolchain_inert: false,
                cargo_config_inert: false,
                cargo_compiler_inert: false,
                npm_config_inert: false,
                pip_config_inert: false,
                python_environment_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
                gem_config_absent: false,
                http_config_absent: false,
                openssl_config_absent: false,
                psql_environment: Default::default(),
                creates_nothing: false,
            },
            Some(&environment),
        )
        .minimum_action
    };
    let action = |command: &str| action_on(command, host.clone());
    let add = format!("git -C {source} worktree add -q --detach {fresh} HEAD");
    assert_eq!(
        action(&format!(
            "{add} && cd {fresh} && git log -1 --format='%H %s'"
        )),
        "allow"
    );
    // Windows installers often leave an empty entry in the search path. Git
    // Bash drops it and Git skips it, so it never names the new checkout and
    // the proof stands. A `.` entry does name it once the `cd` has run.
    let read = format!("{add} && cd {fresh} && git log -1 --format='%H %s'");
    assert_eq!(action_on(&read, format!("{host};;{host}")), "allow");
    assert_ne!(action_on(&read, format!(".;{host}")), "allow");
    for command in [
        // The chain proof covers reads in the checkout Git creates. A `cd`
        // anywhere else, even the agent's own source checkout, leaves the
        // read floor in place: Windows has no workspace sandbox to lift it.
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

/// The pre-tool action for an Oh My Pi shell command run from `cwd`.
fn action_in(command: &str, home: &str, cwd: &str) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: ["GIT_CONFIG_NOSYSTEM", "HOME", "PATH"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_owned()),
        git_config_no_system: true,
        ..Default::default()
    };
    let controls = git_helper_fixture::github_controls("enabled");
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls),
        None,
        guard_command::pretool::PathContext {
            home_dir: Some(home),
            cwd: Some(cwd),
            ..Default::default()
        },
        Some(&environment),
    )
    .minimum_action
}

#[test]
fn worktree_add_beside_the_checkout_then_cd_up_into_it_is_proved_on_windows() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&parent).unwrap();
    let home = parent
        .canonicalize()
        .unwrap()
        .join(format!("guard-worktree-relative-cd-{}", std::process::id()));
    let _cleanup = FixtureCleanup(home.clone());
    // Agents work in a clone, so the checkout has an `origin` to branch
    // from. A repository with a remote is what keeps Git's read floor on.
    let upstream = home.join("upstream");
    std::fs::create_dir_all(&upstream).unwrap();
    git(&upstream, &["init", "--quiet", "-b", "main"]);
    git(&upstream, &["config", "user.name", "Guard Fixture"]);
    git(
        &upstream,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(upstream.join("tracked.txt"), "fixture\n").unwrap();
    git(&upstream, &["add", "tracked.txt"]);
    git(&upstream, &["commit", "--quiet", "-m", "fixture"]);
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["clone", "--quiet", &spelled(&upstream), "project"]);
    let repository = work.join("project");
    let home_text = spelled(&home);
    let cwd = spelled(&repository);
    let add = "git worktree add -b review ../review-wt HEAD";
    let action = |command: &str| action_in(command, &home_text, &cwd);
    for command in [
        format!(
            "{add} && cd ../review-wt && git status --short && git rev-parse --abbrev-ref HEAD"
        ),
        "git worktree add -b review ../review-wt origin/main && cd ../review-wt && git status --short"
            .to_owned(),
    ] {
        assert_eq!(action(&command), "allow", "{command}");
    }
    // The checkout a relative `cd` enters is the one the add creates only
    // when the shell's directory is spelled as its real path.
    let backslashed = cwd.replace('/', "\\");
    assert_eq!(
        action_in(
            &format!("{add} && cd ../review-wt && git status --short"),
            &home_text,
            &backslashed
        ),
        "allow"
    );
    assert_ne!(
        action_in(
            &format!("{add} && cd ../review-wt && git status --short"),
            &home_text,
            &cwd.to_uppercase()
        ),
        "allow"
    );
    for command in [
        // A bare name goes through the CDPATH search.
        format!("{add} && cd review-wt && git status --short"),
        // A `.` part stays reviewed here as on every platform.
        format!("{add} && cd ./../review-wt && git status --short"),
        // A backslash reads differently in Git Bash and PowerShell.
        format!("{add} && cd ..\\review-wt && git status --short"),
        // Other directories, and other spellings of this one.
        format!("{add} && cd ../Review-WT && git status --short"),
        format!("{add} && cd ../review-wt/.. && git status --short"),
        format!("{add} && cd ../../review-wt && git status --short"),
        format!("{add} && cd .. && git status --short"),
        format!("{add} && cd ../review-wt:stream && git status --short"),
        format!("{add} && cd ../review-wt. && git status --short"),
        // Climbing past the drive.
        format!(
            "{add} && cd ../../../../../../../../../../../../../../../review-wt && git status --short"
        ),
    ] {
        assert_ne!(action(&command), "allow", "{command}");
    }
}
