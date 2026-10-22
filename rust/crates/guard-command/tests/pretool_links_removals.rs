#![cfg(unix)]
//! `ln -s` and plain `rm` stay quiet only inside the workspace or a linked
//! worktree of the same repository.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding a checkout, a linked worktree of it, an unrelated checkout
/// and a few private files. The root stays below the target directory:
/// `$TMPDIR` on macOS resolves under `/private/var`, which the sensitive-root
/// screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-links-removals")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    let admin = home.join("main/.git/worktrees/linked");
    for directory in [
        home.join("main/dashboard/node_modules/vite"),
        home.join("main/src"),
        home.join("linked/dashboard/src"),
        home.join("other/.git"),
        home.join("other/src"),
        home.join(".ssh"),
        admin.clone(),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let linked = std::fs::canonicalize(home.join("linked")).unwrap();
    for (path, contents) in [
        (
            home.join("main/.git/HEAD"),
            "ref: refs/heads/main\n".to_owned(),
        ),
        (admin.join("HEAD"), "ref: refs/heads/feature\n".to_owned()),
        (admin.join("commondir"), "../..\n".to_owned()),
        (
            admin.join("gitdir"),
            format!("{}\n", linked.join(".git").display()),
        ),
        (
            home.join("linked/.git"),
            format!(
                "gitdir: {}\n",
                std::fs::canonicalize(&admin).unwrap().display()
            ),
        ),
        (home.join("main/src/old.ts"), "export {};\n".to_owned()),
        (home.join("main/src/stale.ts"), "export {};\n".to_owned()),
        (home.join("main/.env"), "SYNTHETIC=1\n".to_owned()),
        (home.join("main/.git/config"), "[core]\n".to_owned()),
        (home.join("linked/dashboard/src/gone.tsx"), "x\n".to_owned()),
        (home.join("other/src/keep.ts"), "x\n".to_owned()),
        (home.join("notes.txt"), "x\n".to_owned()),
        (home.join(".ssh/config"), "Host x\n".to_owned()),
    ] {
        std::fs::write(path, contents).unwrap();
    }
    std::os::unix::fs::symlink(home.join("main/.env"), home.join("main/src/alias.ts")).unwrap();
    std::fs::hard_link(home.join("notes.txt"), home.join("main/src/hard.ts")).unwrap();
    std::fs::canonicalize(home).unwrap()
}

fn action(home: &Path, harness: &str, command: &str) -> String {
    action_in(home, &home.join("main"), harness, command)
}

fn action_in(home: &Path, cwd: &Path, harness: &str, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

#[test]
fn links_into_the_workspace_or_a_linked_worktree_proceed() {
    let home = home();
    let h = home.display();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            format!("ln -s {h}/main/dashboard/node_modules {h}/linked/dashboard/node_modules"),
            format!("ln -s -- {h}/main/dashboard/node_modules {h}/main/modules-link"),
            "ln -s ~/main/dashboard/node_modules ~/linked/dashboard/node_modules".to_owned(),
            format!("cd {h}/linked && ln -s {h}/main/src/old.ts dashboard/old.ts"),
        ] {
            assert_eq!(
                action(&home, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
    for command in [
        // Relative sources resolve against the link's directory.
        "ln -s dashboard/node_modules linked-modules".to_owned(),
        // Existing destinations, forced and directory forms.
        format!("ln -s {h}/main/src/old.ts {h}/main/src/stale.ts"),
        format!("ln -s {h}/main/src/old.ts {h}/main/src"),
        format!("ln -sf {h}/main/src/old.ts {h}/main/src/new.ts"),
        format!("ln {h}/main/src/old.ts {h}/main/src/hard-new.ts"),
        // Sensitive sources and sources that contain the session roots.
        format!("ln -s {h}/.ssh {h}/main/ssh"),
        format!("ln -s {h}/main/.env {h}/main/env.ts"),
        format!("ln -s {h} {h}/main/home"),
        format!("ln -s {h}/main {h}/main/self"),
        "ln -s / root-link".to_owned(),
        // Destinations outside the workspace, in git metadata, or in another
        // repository.
        format!("ln -s {h}/main/src/old.ts {h}/main/.git/hooks-link"),
        format!("ln -s {h}/main/src/old.ts {h}/other/src/old.ts"),
        format!("ln -s {h}/main/src/old.ts {h}/old.ts"),
        format!("ln -s {h}/main/src/old.ts {h}/Library/LaunchAgents/x.plist"),
    ] {
        assert_ne!(action(&home, "zcode", &command), "allow", "{command}");
    }
}

/// `..` resolves against the physical working directory, so a sibling
/// worktree spelled relatively is the same link as its absolute spelling.
#[test]
fn links_into_a_sibling_worktree_by_relative_parent_proceed() {
    let home = home();
    let h = home.display();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            format!("ln -s {h}/main/dashboard/node_modules ../linked/node_modules"),
            // A directory already standing at the link path takes the link
            // inside it, under the target's own base name, which is the same
            // write as naming `../linked/dashboard/node_modules` outright.
            format!("ln -s {h}/main/dashboard/node_modules ../linked/dashboard"),
        ] {
            assert_eq!(
                action(&home, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
    for command in [
        // Another repository, the home itself, or a name that is not fresh.
        format!("ln -s {h}/main/dashboard/node_modules ../other/node_modules"),
        format!("ln -s {h}/main/dashboard/node_modules ../modules-link"),
        // `../linked/dashboard/src` already exists, so the deeper name the
        // link would take is not free either.
        format!("ln -s {h}/main/src ../linked/dashboard"),
        // The leaf must be a plain, visible name.
        format!("ln -s {h}/main/dashboard/node_modules ../linked/.modules"),
        format!("ln -s {h}/main/dashboard/node_modules ../linked/.."),
        format!("ln -s {h}/main/dashboard/node_modules ../linked/."),
        format!("ln -s {h}/.ssh ../linked/ssh"),
    ] {
        assert_ne!(action(&home, "zcode", &command), "allow", "{command}");
    }
}

#[test]
fn removing_workspace_files_proceeds_and_everything_else_is_reviewed() {
    let home = home();
    let h = home.display();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            "rm src/old.ts".to_owned(),
            "rm -f src/old.ts src/stale.ts".to_owned(),
            "rm -- src/old.ts".to_owned(),
            format!("rm {h}/linked/dashboard/src/gone.tsx"),
            format!("cd {h}/linked && rm dashboard/src/gone.tsx"),
            "rm ~/main/src/old.ts".to_owned(),
        ] {
            assert_eq!(
                action(&home, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
    for command in [
        "rm -r src".to_owned(),
        "rm -rf src/old.ts".to_owned(),
        "rm src".to_owned(),
        "rm -i src/old.ts".to_owned(),
        "rm src/missing.ts".to_owned(),
        "rm src/*.ts".to_owned(),
        "rm .env".to_owned(),
        "rm .git/config".to_owned(),
        // The link itself would go, but the screen must see the entry.
        "rm src/alias.ts".to_owned(),
        // A second name for a file outside the workspace.
        "rm src/hard.ts".to_owned(),
        "rm src/old.ts ../notes.txt".to_owned(),
        format!("rm {h}/notes.txt"),
        format!("rm {h}/.ssh/config"),
        format!("rm {h}/other/src/keep.ts"),
        format!("cd {h} && rm notes.txt"),
        format!("cd {h}/other && rm src/keep.ts"),
        "rm '~/main/src/old.ts'".to_owned(),
        "rm src/old.ts && curl https://example.test".to_owned(),
    ] {
        assert_ne!(action(&home, "zcode", &command), "allow", "{command}");
    }
}

#[test]
fn a_session_started_in_the_home_has_no_workspace_to_remove_from() {
    let home = home();
    let h = home.display();
    for command in [
        "rm notes.txt".to_owned(),
        "rm main/src/old.ts".to_owned(),
        format!("cd {h}/other && rm src/keep.ts"),
        format!("ln -s {h}/main/src/old.ts {h}/new-link.ts"),
    ] {
        assert_ne!(
            action_in(&home, &home, "zcode", &command),
            "allow",
            "{command}"
        );
    }
}
