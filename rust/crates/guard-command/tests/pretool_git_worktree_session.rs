#![cfg(unix)]

//! The worktree proof judges the configuration the agent's own Git reads:
//! sessions that keep the system file or set `XDG_CONFIG_HOME` are proven
//! against those files rather than turned away, and the usual sibling layout
//! `../name` is accepted while the destination stays under home.

// This session test builds its own execution environment. The shared helper
// `evaluate_pre_tool_envelope_with_context` stays for the other Git fixtures.
#[allow(dead_code)]
#[path = "support/git_helper_fixture.rs"]
mod fixture;

use fixture::FixtureCleanup;
use serde_json::json;
use std::path::Path;

fn evaluate(
    repository: &Path,
    command: &str,
    xdg_config_home: Option<&Path>,
    no_system: bool,
) -> guard_contracts::PreToolResultV1 {
    use sha2::{Digest, Sha256};

    let home = repository.parent().unwrap();
    let path = std::env::var("PATH").unwrap();
    let mut environment = std::collections::BTreeMap::from([
        ("PATH", path.clone()),
        ("HOME", home.to_str().unwrap().to_owned()),
    ]);
    if no_system {
        environment.insert("GIT_CONFIG_NOSYSTEM", "1".to_owned());
    }
    if let Some(directory) = xdg_config_home {
        environment.insert("XDG_CONFIG_HOME", directory.to_str().unwrap().to_owned());
    }
    let context = guard_contracts::GuardExecutionEnvironmentV1 {
        path,
        environment_names: environment.keys().map(|key| (*key).to_owned()).collect(),
        environment_digest: hex::encode(Sha256::digest(serde_json::to_vec(&environment).unwrap())),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: xdg_config_home.map(|directory| directory.to_str().unwrap().to_owned()),
        git_config_no_system: no_system,
        library_search_paths: Default::default(),
    };
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
        None,
        guard_command::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: repository.to_str(),
            cdpath_unset: false,
            rustup_override_absent: false,
            npm_config_inert: false,
            shell_home_matches: false,
        },
        Some(&context),
    )
}

fn git(repository: &Path, arguments: &[&str]) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", repository.parent().unwrap())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_AUTHOR_NAME")
        .env_remove("GIT_AUTHOR_EMAIL")
        .env_remove("GIT_COMMITTER_NAME")
        .env_remove("GIT_COMMITTER_EMAIL")
        .args(arguments)
        .status()
        .unwrap()
        .success()
}

/// Whether the host's system Git configuration has settings the proof turns
/// away, such as the `filter.lfs` section `git lfs install --system` writes.
fn system_config_is_plain() -> bool {
    let output = std::process::Command::new("git")
        .args(["config", "--system", "--name-only", "--list"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).lines().all(|key| {
        let key = key.to_ascii_lowercase();
        ![
            "filter.",
            "hook.",
            "pager.",
            "include",
            "extensions.",
            "submodule.",
            "core.bare",
            "core.hookspath",
            "core.worktree",
            "core.fsmonitor",
            "core.sshcommand",
            "core.gitproxy",
            "core.askpass",
            "core.pager",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
    })
}

#[test]
fn worktree_proof_follows_the_session_git_configuration() {
    let root_directory = if cfg!(target_os = "macos") {
        std::path::PathBuf::from("/tmp")
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
    };
    let root = std::fs::canonicalize(root_directory).unwrap().join(format!(
        "guard-git-worktree-session-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let repository = root.join("repository");
    let _cleanup = FixtureCleanup(root.clone());
    std::fs::create_dir_all(&repository).unwrap();
    assert!(git(&repository, &["init", "--quiet"]));
    assert!(git(&repository, &["config", "user.name", "Guard Fixture"]));
    assert!(git(
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"]
    ));
    std::fs::write(repository.join("tracked.txt"), "fixture\n").unwrap();
    assert!(git(&repository, &["add", "tracked.txt"]));
    assert!(git(&repository, &["commit", "--quiet", "-m", "fixture"]));

    let sibling = "git worktree add ../weekly-report -b weekly-report";
    let admitted = evaluate(&repository, sibling, None, true);
    assert_eq!(admitted.minimum_action, "allow", "{}", admitted.reason_code);
    assert_eq!(admitted.reason_code, "native_exact_safe_worktree_add");
    assert!(git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "../weekly-report",
            "-b",
            "weekly-report"
        ]
    ));
    assert!(root.join("weekly-report/tracked.txt").is_file());

    // Leaving home, or climbing anywhere but the start, keeps review.
    for command in [
        "git worktree add ../../outside-home -b outside-home",
        "git worktree add sub/../escape -b escape",
        "git worktree add ./here -b here",
        "git worktree add .. -b parent",
        "git worktree add ../.hidden -b hidden",
    ] {
        let result = evaluate(&repository, command, None, true);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }

    let xdg = root.join("xdg");
    std::fs::create_dir_all(xdg.join("git")).unwrap();
    std::fs::write(
        xdg.join("git/config"),
        "[user]\n\tname = Guard Fixture\n[credential]\n\thelper = cache\n",
    )
    .unwrap();
    let with_xdg = evaluate(
        &repository,
        "git worktree add ../xdg-report -b xdg-report",
        Some(&xdg),
        true,
    );
    assert_eq!(with_xdg.minimum_action, "allow", "{}", with_xdg.reason_code);

    // The XDG file is read, so a hook directory set there is seen.
    std::fs::write(
        xdg.join("git/config"),
        format!("[core]\n\thooksPath = {}\n", root.join("hooks").display()),
    )
    .unwrap();
    let hooked = evaluate(
        &repository,
        "git worktree add ../hooked-report -b hooked-report",
        Some(&xdg),
        true,
    );
    assert_ne!(hooked.minimum_action, "allow");

    // Without GIT_CONFIG_NOSYSTEM the system file is read too and judged
    // like the others.
    let with_system = evaluate(
        &repository,
        "git worktree add ../system-report -b system-report",
        None,
        false,
    );
    if system_config_is_plain() {
        assert_eq!(
            with_system.minimum_action, "allow",
            "{}",
            with_system.reason_code
        );
    } else {
        assert_ne!(with_system.minimum_action, "allow");
    }
}
