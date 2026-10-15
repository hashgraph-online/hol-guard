use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

fn git(directory: &std::path::Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("HOME", std::env::temp_dir())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

struct Workspace {
    root: std::path::PathBuf,
    home: std::path::PathBuf,
    repository: std::path::PathBuf,
}

fn workspace(label: &str) -> (Workspace, FixtureCleanup) {
    let base = if cfg!(unix) {
        std::path::PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    let root = base.join(format!("guard-cd-reads-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(repository.join("app")).unwrap();
    git(&root, &["init", "--quiet", repository.to_str().unwrap()]);
    std::fs::write(repository.join("README.md"), "# fixture\n").unwrap();
    git(&repository, &["add", "-A"]);
    git(&repository, &["commit", "--quiet", "-m", "base"]);
    (
        Workspace {
            root: root.clone(),
            home,
            repository,
        },
        FixtureCleanup(root),
    )
}

fn decide(
    workspace: &Workspace,
    cwd: &std::path::Path,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        None,
        None,
        workspace.home.to_str(),
        cwd.to_str(),
    )
}

#[test]
fn verified_cd_then_git_history_reads_are_allowed_without_configured_helpers() {
    let (space, _cleanup) = workspace("allow");
    let repository = space.repository.to_str().unwrap();
    for command in [
        format!("cd {repository} && git log -5 --oneline"),
        format!("cd {repository} && git diff --check"),
        format!("cd {repository} && git show --stat --oneline HEAD"),
        format!("cd {repository} && git log -1 --format=%h | head -1"),
        format!("git -C {repository} log -1"),
        format!("git -C {repository} diff --stat"),
    ] {
        let result = decide(&space, &space.repository, &command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
        assert_eq!(result.reason_code, "native_exact_safe_command", "{command}");
    }
    let result = decide(&space, &space.repository, "cd app && git log -1");
    assert_eq!(
        result.decision, "allow",
        "relative cd: {}",
        result.reason_code
    );
}

#[test]
fn verified_cd_does_not_hide_configured_git_helpers() {
    let (space, _cleanup) = workspace("helper");
    let repository = space.repository.to_str().unwrap();
    git(
        &space.repository,
        &["config", "diff.external", "./synthetic-never-execute"],
    );
    for command in [
        format!("cd {repository} && git log -1"),
        format!("cd {repository} && git diff --stat"),
        format!("git -C {repository} show HEAD"),
    ] {
        let result = decide(&space, &space.repository, &command);
        assert_ne!(result.decision, "allow", "{command}");
        assert!(!result.explicitly_benign, "{command}");
    }
}

#[test]
fn cd_helper_config_is_judged_in_the_destination_not_the_reported_cwd() {
    let (space, _cleanup) = workspace("destination");
    // The reported cwd is a clean repository; the cd target carries the helper.
    let clean = space.root.join("clean");
    std::fs::create_dir_all(&clean).unwrap();
    git(&space.root, &["init", "--quiet", clean.to_str().unwrap()]);
    git(
        &space.repository,
        &["config", "core.fsmonitor", "./synthetic-never-execute"],
    );
    let workspace_root = space.root.clone();
    let command = format!("cd {} && git status", space.repository.display());
    let result = decide(&space, &workspace_root, &command);
    assert_ne!(result.decision, "allow", "{command}");
}

#[test]
fn cd_outside_the_workspace_or_into_secret_locations_is_not_allowed() {
    let (space, _cleanup) = workspace("outside");
    let outside = std::path::PathBuf::from("/tmp");
    for command in [
        "cd /etc && git log -1".to_owned(),
        format!("cd {}/.ssh && git log -1", space.home.display()),
        format!(
            "cd {} && git log -1 && curl https://example.invalid",
            space.repository.display()
        ),
        format!(
            "cd {} && git log -1 > /etc/synthetic-out",
            space.repository.display()
        ),
        format!("cd {} && git log -1 $(id)", space.repository.display()),
    ] {
        let result = decide(&space, &space.repository, &command);
        assert!(
            result.decision != "allow"
                || !result.explicitly_benign
                || result.minimum_action != "allow",
            "{command}"
        );
        assert_ne!(result.reason_code, "native_exact_safe_command", "{command}");
    }
    let _ = outside;
}

#[test]
fn cd_history_read_helper_config_is_judged_in_the_destination() {
    let (space, _cleanup) = workspace("destination-log");
    // A clean reported cwd must not stand in for the helper-configured target.
    let clean = space.root.join("clean");
    std::fs::create_dir_all(&clean).unwrap();
    git(&space.root, &["init", "--quiet", clean.to_str().unwrap()]);
    git(
        &space.repository,
        &["config", "diff.external", "./synthetic-never-execute"],
    );
    for read in ["log -1", "diff --stat", "show HEAD"] {
        let command = format!("cd {} && git {read}", space.repository.display());
        let result = decide(&space, &clean, &command);
        assert_ne!(result.decision, "allow", "{command}");
        assert!(!result.explicitly_benign, "{command}");
    }
}

#[test]
fn relative_dash_c_after_cd_resolves_against_the_destination() {
    let (space, _cleanup) = workspace("nested-dash-c");
    // `child` exists only beneath the cd destination, not the reported cwd.
    let child = space.repository.join("child");
    git(
        &space.repository,
        &["init", "--quiet", child.to_str().unwrap()],
    );
    std::fs::write(child.join("notes.txt"), "child\n").unwrap();
    git(&child, &["add", "-A"]);
    git(&child, &["commit", "--quiet", "-m", "child"]);
    let command = format!("cd {} && git -C child log -1", space.repository.display());
    let result = decide(&space, &space.root, &command);
    assert_eq!(
        result.decision, "allow",
        "{command}: {}",
        result.reason_code
    );
    git(
        &child,
        &["config", "diff.external", "./synthetic-never-execute"],
    );
    let result = decide(&space, &space.root, &command);
    assert_ne!(result.decision, "allow", "{command}");
}

#[test]
fn read_prefix_before_a_verified_cd_keeps_the_cd_compound_decision() {
    let (space, _cleanup) = workspace("prefix");
    let root = space.root.to_str().unwrap();
    let repository = space.repository.to_str().unwrap();
    for command in [
        format!("ls {root} && cd {repository} && git status"),
        format!("ls {root} && cd {repository} && git remote -v"),
        format!(
            "ls {root} && echo \"---\" && cd {repository} && git status && echo \"---\" \
             && git remote -v && echo \"---\" && git log --oneline -5"
        ),
        format!("pwd && cd {repository} && git log -1 --format=%h | head -1"),
    ] {
        let result = decide(&space, &space.root, &command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

#[test]
fn only_a_proven_read_prefix_before_a_single_cd_is_set_aside() {
    let (space, _cleanup) = workspace("prefix-deny");
    let root = space.root.to_str().unwrap();
    let home = space.home.to_str().unwrap();
    let repository = space.repository.to_str().unwrap();
    std::fs::create_dir_all(space.home.join(".ssh")).unwrap();
    std::fs::write(space.home.join(".ssh/id_ed25519"), "fixture\n").unwrap();
    for command in [
        format!("cat {home}/.ssh/id_ed25519 && cd {repository} && git status"),
        format!("touch {root}/marker && cd {repository} && git status"),
        format!("ls {root} && cd {repository} && rm -rf app"),
        format!("ls {root} && cd {repository} && git status && cd {root} && ls"),
        format!("ls {root}; cd {repository} && git status"),
        format!("ls {root} || cd {repository} && git status"),
    ] {
        let result = decide(&space, &space.root, &command);
        assert_ne!(
            result.reason_code, "native_exact_safe_command",
            "{command}: {}",
            result.decision
        );
    }
}

/// Local Git reads before the `cd` write nothing the reads after it could
/// pick up, so the floor judges the command from the `cd` onward.
#[test]
fn proven_git_reads_before_a_cd_into_a_sibling_repository_are_allowed() {
    let (space, _cleanup) = workspace("git-prefix");
    let other = space.root.join("other");
    git(&space.root, &["init", "--quiet", other.to_str().unwrap()]);
    std::fs::write(other.join("notes.txt"), "other\n").unwrap();
    git(&other, &["add", "-A"]);
    git(&other, &["commit", "--quiet", "-m", "other"]);
    let other = other.to_str().unwrap();
    for command in [
        format!(
            "git log --oneline -5 && git status --short | head -20 && echo \"=== other ===\" \
             && cd {other} && git log --oneline -5 && git status --short | head"
        ),
        format!("git status && cd {other} && git log -1"),
    ] {
        let result = decide(&space, &space.repository, &command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    for command in [
        format!("git checkout -b scratch && cd {other} && git log -1"),
        format!("git config core.hooksPath hooks && cd {other} && git log -1"),
        format!("git commit --allow-empty -m wip && cd {other} && git log -1"),
        format!("git -c core.pager=less log -1 && cd {other} && git log -1"),
        format!("git status; cd {other} && git log -1"),
        format!("git status && cd {other} && git config core.fsmonitor true && git status"),
    ] {
        let result = decide(&space, &space.repository, &command);
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn remote_url_reads_are_read_only() {
    let (space, _cleanup) = workspace("remote-url");
    let repository = space.repository.to_str().unwrap();
    git(
        &space.repository,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/fixture.git",
        ],
    );
    for command in [
        "git remote get-url origin".to_owned(),
        "git remote get-url --push origin".to_owned(),
        "git remote get-url --all origin".to_owned(),
        format!(
            "pwd && git -C {repository} status --short --branch \
             && git -C {repository} remote get-url origin \
             && git -C {repository} remote get-url --push origin"
        ),
    ] {
        let result = decide(&space, &space.repository, &command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    for command in [
        "git remote get-url",
        "git remote get-url --push",
        "git remote get-url --delete origin",
        "git remote set-url origin https://example.invalid/other.git",
        "git remote add other https://example.invalid/other.git",
        "git remote prune origin",
        "git remote update",
        "git remote show origin",
    ] {
        let result = decide(&space, &space.repository, command);
        assert_ne!(result.decision, "allow", "{command}");
    }
}
