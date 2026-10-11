//! Agents commonly work from a directory that holds several repositories
//! below home (`~/Code/org/app-portal`, `~/Code/org/service-api`). Read-only
//! searches and Git inspection that name a child or sibling repository by its
//! absolute or `~` path are ordinary work and must not ask for review, while
//! hidden, linked-away, sensitive and helper-configured targets still do.
use serde_json::json;
use std::path::{Path, PathBuf};

#[path = "support/git_helper_fixture.rs"]
pub mod fixture;

fn git(directory: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn decide(cwd: &Path, home: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    fixture::evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

fn repository(path: &Path) {
    std::fs::create_dir_all(path.join(".github/workflows")).unwrap();
    std::fs::create_dir_all(path.join("src")).unwrap();
    std::fs::write(path.join(".github/workflows/ci.yml"), "name: ci\n").unwrap();
    std::fs::write(path.join("src/main.rs"), "fn main() {} // fixture\n").unwrap();
    git(path, &["init", "--quiet"]);
    git(path, &["add", "."]);
    git(path, &["commit", "--quiet", "-m", "fixture"]);
}

struct Layout {
    _cleanup: fixture::FixtureCleanup,
    home: PathBuf,
    org: PathBuf,
}

/// `CARGO_TARGET_TMPDIR` keeps the fixture outside `/var` and dot
/// directories on macOS, which the read screens would otherwise refuse for
/// reasons unrelated to the layout under test.
fn layout(name: &str) -> Layout {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "home-layout-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let cleanup = fixture::FixtureCleanup(root.clone());
    let home = root.join("home");
    let org = home.join("Code").join("org");
    std::fs::create_dir_all(&org).unwrap();
    let home = std::fs::canonicalize(home).unwrap();
    let org = std::fs::canonicalize(org).unwrap();
    repository(&org.join("app-portal"));
    repository(&org.join("service-api"));
    Layout {
        _cleanup: cleanup,
        home,
        org,
    }
}

fn assert_decision(cwd: &Path, home: &Path, command: &str, allowed: bool) {
    let result = decide(cwd, home, command);
    assert_eq!(
        result.decision == "allow",
        allowed,
        "{command}: {} {}",
        result.decision,
        result.reason_code
    );
}

#[test]
fn search_of_child_repository_by_absolute_or_home_path_is_allowed() {
    let layout = layout("rg");
    let child = layout.org.join("app-portal");
    for command in [
        format!("rg -n fixture {}", child.display()),
        format!("rg -n fixture {}/src", child.display()),
        "rg -n fixture ~/Code/org/app-portal".to_owned(),
        "rg -n fixture app-portal".to_owned(),
    ] {
        assert_decision(&layout.org, &layout.home, &command, true);
    }
}

#[test]
fn search_root_that_is_hidden_linked_away_or_sensitive_is_reviewed() {
    let layout = layout("rg-negative");
    let hidden = layout.org.join(".private-notes");
    std::fs::create_dir_all(&hidden).unwrap();
    std::fs::write(hidden.join("notes.md"), "fixture\n").unwrap();
    std::fs::create_dir_all(layout.home.join(".ssh")).unwrap();
    let mut commands = vec![
        format!("rg -n fixture {}", hidden.display()),
        format!("rg -n fixture {}", layout.home.join(".ssh").display()),
        "rg -n fixture ~/.ssh".to_owned(),
        format!("rg -n fixture {}/../org", layout.org.display()),
    ];
    #[cfg(unix)]
    {
        let link = layout.org.join("notes-link");
        std::os::unix::fs::symlink(&hidden, &link).unwrap();
        commands.push(format!("rg -n fixture {}", link.display()));
    }
    for command in commands {
        assert_decision(&layout.org, &layout.home, &command, false);
    }
}

#[test]
fn git_inspection_of_sibling_repository_below_home_is_allowed() {
    let layout = layout("git-sibling");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api");
    for command in [
        "git -C ../service-api log --oneline -3".to_owned(),
        format!("git -C {} status --short", sibling.display()),
        "git -C ~/Code/org/service-api diff --stat".to_owned(),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
    assert_decision(
        &layout.org,
        &layout.home,
        "git -C app-portal log --oneline -1",
        true,
    );
}

#[test]
fn git_route_to_hidden_home_or_helper_configured_repository_is_reviewed() {
    let layout = layout("git-negative");
    let cwd = layout.org.join("app-portal");
    let hidden = layout.home.join(".config-repo");
    repository(&hidden);
    let helper = layout.org.join("helper-repo");
    repository(&helper);
    git(&helper, &["config", "core.fsmonitor", "./monitor.sh"]);
    let plain = layout.org.join("plain-directory");
    std::fs::create_dir_all(&plain).unwrap();
    for command in [
        format!("git -C {} log --oneline -1", hidden.display()),
        "git -C ~ status --short".to_owned(),
        "git -C ../helper-repo status --short".to_owned(),
        format!("git -C {} status --short", plain.display()),
    ] {
        assert_decision(&cwd, &layout.home, &command, false);
    }
}

#[test]
fn git_inspection_of_linked_worktree_below_home_is_allowed_unless_forged() {
    let layout = layout("git-worktree");
    let repository = layout.org.join("app-portal");
    let linked = layout.org.join("app-portal-feature");
    git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "feature",
            linked.to_str().unwrap(),
        ],
    );
    let cwd = layout.org.join("service-api");
    for command in [
        "git -C ../app-portal-feature diff --stat".to_owned(),
        format!("git -C {} log --oneline -1", linked.display()),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
    // A copied `.git` file names the registry entry, but the entry's
    // backlink still names the real worktree.
    let forged = layout.org.join("forged-checkout");
    std::fs::create_dir_all(&forged).unwrap();
    std::fs::copy(linked.join(".git"), forged.join(".git")).unwrap();
    assert_decision(
        &cwd,
        &layout.home,
        "git -C ../forged-checkout status --short",
        false,
    );
}

#[test]
fn quoted_home_or_variable_roots_are_reviewed_and_rootless_fd_matches_dot() {
    let layout = layout("quoted-roots");
    let cwd = layout.org.join("app-portal");
    let literal_home = [
        "rg -n fixture '~/Code/org/app-portal'",
        "rg -n fixture \\~/Code/org/app-portal",
        "fd -e rs main '~/Code/org/app-portal'",
    ];
    // With no `~` entry in the cwd the literal path names nothing.
    for command in literal_home {
        assert_decision(&cwd, &layout.home, command, true);
    }
    for command in [
        "fd -e rs main --search-path=~/Code/org/app-portal",
        "fd . \"$HOME\"",
        "fd . $HOME/Code/org",
        "git -C '~/Code/org/service-api' status --short",
        "git -C \"~/Code/org/service-api\" diff --stat",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
    // A rootless fd lists the cwd, exactly like an explicit `.` root.
    for directory in [&layout.home, &cwd] {
        assert_eq!(
            decide(directory, &layout.home, "fd -e rs main").decision,
            decide(directory, &layout.home, "fd -e rs main .").decision,
        );
    }
    for command in [
        "fd -e rs main",
        "fd -e rs main ~/Code/org/app-portal",
        "fd -e rs main --search-path ~/Code/org",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
    // Once the cwd holds a `~` entry, the literal path reads something else.
    std::fs::create_dir(cwd.join("~")).unwrap();
    for command in literal_home {
        assert_decision(&cwd, &layout.home, command, false);
        // The same cwd spelled from home still sees its `~` entry.
        let spelled = Path::new("~/Code/org/app-portal");
        assert_ne!(
            decide(spelled, &layout.home, command).decision,
            "allow",
            "{command}"
        );
    }
}
