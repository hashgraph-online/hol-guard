//! Read-only Homebrew and `pg_ctl` status queries run without review;
//! installs, upgrades, taps, service and server changes keep it.
#![cfg(unix)]

use crate::git_helper_fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::path::PathBuf;

fn workspace(label: &str) -> (PathBuf, PathBuf, FixtureCleanup) {
    let root =
        PathBuf::from("/tmp").join(format!("guard-brew-reads-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let cwd = home.join("Code/org/app-portal");
    std::fs::create_dir_all(&cwd).unwrap();
    (home, cwd, FixtureCleanup(root))
}

fn decision(label: &str, harness: &str, command: &str) -> String {
    let (home, cwd, _cleanup) = workspace(label);
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .decision
}

#[test]
fn package_manager_status_queries_are_explicitly_benign() {
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "brew services list",
            "brew services list 2>/dev/null | grep -i postgres",
            "brew services info postgresql@16",
            "brew list --versions",
            "brew ls --formula -1",
            "brew list --cask",
            "brew info wget",
            "brew desc wget",
            "brew --prefix postgresql@16",
            "brew --cellar",
            "brew --version",
            "brew deps --tree wget",
            "brew deps --installed",
            "brew uses --installed openssl@3",
            "brew leaves",
            "pg_ctl -D /var/lib/acme-pg status",
            "pg_ctl --version",
        ] {
            assert_eq!(
                decision("allow", harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn package_and_server_changes_stay_reviewed() {
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "brew install wget",
            "brew upgrade",
            "brew update",
            "brew outdated",
            "brew deps",
            "brew deps -1 --tree",
            "brew tap acme/tools",
            "brew uninstall wget",
            "brew link wget",
            "brew cleanup",
            "brew bundle",
            "brew config",
            "brew doctor",
            "brew sh",
            "brew services start postgresql@16",
            "brew services stop postgresql@16",
            "brew services restart postgresql@16",
            "brew info ./widget.rb",
            "brew info acme/tools/widget",
            "HOMEBREW_NO_AUTO_UPDATE=1 brew list",
            "./bin/brew list",
            "brew list && brew install wget",
            "pg_ctl -D /var/lib/acme-pg stop",
            "pg_ctl -D /var/lib/acme-pg start",
            "pg_ctl -D /var/lib/acme-pg restart",
            "pg_ctl -D /var/lib/acme-pg reload",
            "pg_ctl -D /var/lib/acme-pg promote",
            "pg_ctl -D /var/lib/acme-pg init",
            "/nonexistent-acme/bin/pg_ctl -D /var/lib/acme-pg status",
            "./bin/pg_ctl -D /var/lib/acme-pg status",
        ] {
            assert_ne!(
                decision("review", harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
