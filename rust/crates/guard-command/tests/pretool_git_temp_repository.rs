//! Inspecting a scratch checkout below the shared temporary directory: the
//! listing prefix may name its parent through a rooted `..`, and the Git
//! reads after `cd` stay helper-, hook- and ownership-checked.
#![cfg(unix)]
use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn git(directory: &Path, home: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

struct Scratch {
    _cleanup: FixtureCleanup,
    root: PathBuf,
    home: PathBuf,
    org: PathBuf,
    app: PathBuf,
}

fn scratch(tag: &str) -> Scratch {
    let root = Path::new("/tmp").join(format!("guard-temp-repo-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let home = root.join("home");
    let org = root.join("scratch/org");
    let app = org.join("app");
    for directory in [&home.join(".ssh"), &app] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::write(home.join(".ssh/id_rsa"), "not-a-real-key\n").unwrap();
    git(&app, &home, &["init", "--quiet"]);
    std::fs::write(app.join("README.md"), "# app-portal\n").unwrap();
    git(&app, &home, &["add", "-A"]);
    git(&app, &home, &["commit", "--quiet", "-m", "base"]);
    git(
        &app,
        &home,
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/app-portal.git",
        ],
    );
    Scratch {
        _cleanup: FixtureCleanup(root.clone()),
        root,
        home,
        org,
        app,
    }
}

fn decide(scratch: &Scratch, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        None,
        None,
        scratch.home.to_str(),
        scratch.org.to_str(),
    )
}

fn inspection(scratch: &Scratch) -> String {
    let org = scratch.org.display();
    format!(
        "ls {org}/.. && echo \"---\" && ls {org}/ && echo \"---\" && cd {org}/app && \
         git status && echo \"---\" && git remote -v && echo \"---\" && git log --oneline -15"
    )
}

/// A named change that makes the scratch repository able to start code.
type Mutation = (&'static str, fn(&Scratch));

fn executable(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn rooted_parent_listing_then_repository_inspection_is_allowed() {
    let scratch = scratch("allow");
    let org = scratch.org.display();
    for command in [
        inspection(&scratch),
        format!("ls {org}/.. && cd {org}/app && git status --short && git log --oneline -3"),
        format!("ls -la {org}/../org/app"),
        format!("cat {org}/../org/app/README.md"),
    ] {
        let result = decide(&scratch, &command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// A rooted `..` listing is a proven read, so the Git reads after the `cd`
/// get the decision they get alone, whether or not the configuration probe
/// covers their operation.
#[test]
fn rooted_parent_listing_admits_every_read_after_the_cd() {
    let scratch = scratch("unprobed");
    let org = scratch.org.display();
    let prefix = format!("ls {org}/.. && cd {org}/app");
    for command in [
        format!("ls {org}/.."),
        format!("{prefix} && git rev-parse HEAD"),
        format!("{prefix} && git remote -v"),
        format!("{prefix} && git status && git remote -v"),
    ] {
        let result = decide(&scratch, &command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// A skills directory linked to the home directory must not become a home
/// listing through a rooted `..` spelling either.
#[test]
fn rooted_parent_through_a_skills_link_to_home_stays_reviewed() {
    let scratch = scratch("skills-link");
    let home = scratch.home.display();
    std::fs::create_dir_all(scratch.home.join("notes")).unwrap();
    std::fs::create_dir_all(scratch.home.join(".agents")).unwrap();
    std::os::unix::fs::symlink(&scratch.home, scratch.home.join(".agents/skills")).unwrap();
    let command = format!("ls {home}/.agents/skills/notes/..");
    let result = decide(&scratch, &command);
    assert_ne!(result.decision, "allow", "{command}");
    assert!(!result.explicitly_benign, "{command}");
}

#[test]
fn rooted_parent_reads_into_secret_locations_stay_reviewed() {
    let scratch = scratch("secret");
    let org = scratch.org.display();
    let home = scratch.home.display();
    for command in [
        format!("cat {org}/../../home/.ssh/id_rsa"),
        format!("ls {org}/../../home/.ssh"),
        format!("cat {home}/../home/.ssh/id_rsa"),
        format!("cat {org}/../missing/../../home/.ssh/id_rsa"),
    ] {
        let result = decide(&scratch, &command);
        assert_ne!(result.decision, "allow", "{command}");
        assert!(!result.explicitly_benign, "{command}");
    }
}

#[test]
fn execution_capable_repository_configuration_stays_reviewed() {
    let mutations: [Mutation; 5] = [
        ("fsmonitor", |s: &Scratch| {
            git(
                &s.app,
                &s.home,
                &["config", "core.fsmonitor", "./never-run"],
            );
        }),
        ("include", |s: &Scratch| {
            let extra = s.root.join("scratch/extra.gitconfig");
            std::fs::write(&extra, "[core]\n\tfsmonitor = ./never-run\n").unwrap();
            git(
                &s.app,
                &s.home,
                &["config", "include.path", extra.to_str().unwrap()],
            );
        }),
        ("hookspath", |s: &Scratch| {
            let hooks = s.root.join("scratch/hooks");
            executable(&hooks.join("post-index-change"));
            git(
                &s.app,
                &s.home,
                &["config", "core.hooksPath", hooks.to_str().unwrap()],
            );
        }),
        ("hook", |s: &Scratch| {
            executable(&s.app.join(".git/hooks/post-index-change"));
        }),
        ("shared-hookspath", |s: &Scratch| {
            // Not created yet, below a directory anyone may write: another
            // local user could create it with a hook before the read runs.
            let shared = s.root.join("scratch/shared");
            std::fs::create_dir_all(&shared).unwrap();
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
            let hooks = shared.join("hooks");
            git(
                &s.app,
                &s.home,
                &["config", "core.hooksPath", hooks.to_str().unwrap()],
            );
        }),
    ];
    for (tag, mutate) in mutations {
        let scratch = scratch(tag);
        mutate(&scratch);
        let command = inspection(&scratch);
        let result = decide(&scratch, &command);
        assert_ne!(result.decision, "allow", "{tag}: {}", result.reason_code);
        assert!(!result.explicitly_benign, "{tag}");
    }
}

#[test]
fn repository_others_can_write_stays_reviewed() {
    for (tag, relative) in [("gitdir", ".git"), ("config", ".git/config")] {
        let scratch = scratch(tag);
        let target = scratch.app.join(relative);
        let mode = if target.is_dir() { 0o777 } else { 0o666 };
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
        let org = scratch.org.display();
        for command in [
            inspection(&scratch),
            format!("cd {org}/app && git log --oneline -3"),
        ] {
            let result = decide(&scratch, &command);
            assert_ne!(result.decision, "allow", "{tag}: {command}");
        }
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn inert_hook_entries_do_not_block_inspection() {
    let scratch = scratch("inert-hooks");
    let hooks = scratch.app.join(".git/hooks");
    std::fs::write(hooks.join("post-index-change"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(
        hooks.join("post-index-change"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    executable(&hooks.join("pre-commit"));
    let command = inspection(&scratch);
    let result = decide(&scratch, &command);
    assert_eq!(result.decision, "allow", "{}", result.reason_code);
}

#[test]
fn overrides_and_writes_after_the_rooted_prefix_are_not_proven_reads() {
    let scratch = scratch("writes");
    let org = scratch.org.display();
    let prefix = format!("ls {org}/.. && cd {org}/app");
    for tail in [
        "git -c core.fsmonitor=./never-run status",
        "git -c core.pager=./never-run log -1",
        "git commit --allow-empty -m x",
        "git checkout -b topic",
        "git fetch https://example.com/app-portal.git",
        "git pull https://example.com/app-portal.git main",
    ] {
        let command = format!("{prefix} && {tail}");
        let result = decide(&scratch, &command);
        assert_ne!(result.reason_code, "native_exact_safe_command", "{command}");
        assert!(!result.explicitly_benign, "{command}");
    }
}
