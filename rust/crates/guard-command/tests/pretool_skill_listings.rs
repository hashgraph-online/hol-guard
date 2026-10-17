#![cfg(unix)]
//! Names-only listings of user skill directories, and `ls` probes for paths
//! that do not exist, proceed without review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding a skills tree, Codex state, an SSH directory and a project.
/// The root stays below the target directory: `$TMPDIR` on macOS resolves
/// under `/private/var`, which the sensitive-root screen rejects.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-skill-listings")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    for directory in [
        ".agents/skills/review-loop/scripts",
        ".agents/skills/review-loop/.cache",
        ".codex/skills/notes",
        ".ssh",
        "work/project/.git",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    for (path, contents) in [
        (".agents/.skill-lock.json", "{}\n"),
        (".agents/skills/review-loop/SKILL.md", "# Review\n"),
        (
            ".agents/skills/review-loop/scripts/approve.sh",
            "#!/bin/sh\n",
        ),
        (".codex/auth.json", "{}\n"),
        (".ssh/config", "Host x\n"),
        ("work/project/.git/HEAD", "ref: refs/heads/main\n"),
    ] {
        std::fs::write(home.join(path), contents).unwrap();
    }
    std::fs::canonicalize(home).unwrap()
}

fn action(home: &Path, harness: &str, command: &str) -> String {
    let cwd = home.join("work/project");
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
fn skill_directories_list_without_review() {
    let home = home("skills");
    let h = home.display();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            "ls ~/.agents/skills/review-loop".to_owned(),
            "ls ~/.agents/skills/review-loop/scripts".to_owned(),
            format!("ls -la {h}/.agents/skills"),
            "ls ~/.codex/skills/notes".to_owned(),
            "find ~/.agents -maxdepth 4 -name \"approve.sh\"".to_owned(),
            "find ~/.agents -maxdepth 4 -name \"approve.sh\" 2>&1".to_owned(),
            "find ~/.agents/skills/review-loop -type f".to_owned(),
        ] {
            assert_eq!(
                action(&home, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
    // A name pattern prints only the paths it selects, so a second root that
    // is a home dot-directory clear of the credential stores prints no more
    // than the skill root does.
    assert_eq!(
        action(
            &home,
            "zcode",
            "find ~/.agents ~/.codex -maxdepth 4 -name \"approve.sh\""
        ),
        "allow"
    );
    for command in [
        // Other agent state, hidden entries inside a skill, actions and
        // content reads keep their review.
        "ls -R ~/.codex",
        "find ~/.codex -name auth.json",
        "ls ~/.agents/skills/review-loop/.cache",
        "find ~/.agents -name approve.sh -exec cat {} +",
        "find ~/.agents -name approve.sh -delete",
        "find -L ~/.agents -name approve.sh",
        "cat ~/.agents/skills/review-loop/scripts/approve.sh",
        "ls ~/.ssh",
    ] {
        assert_ne!(action(&home, "zcode", command), "allow", "{command}");
    }
}

#[test]
fn a_linked_agents_directory_is_not_a_skill_root() {
    let home = home("linked");
    // A link into an ordinary visible directory is just that directory. Point
    // it at a hidden one, which only the skill-root exception could open.
    let elsewhere = home.join(".private");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::rename(home.join(".agents"), elsewhere.join("agents")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("agents"), home.join(".agents")).unwrap();
    assert_ne!(
        action(
            &home,
            "zcode",
            "find ~/.agents -maxdepth 4 -name approve.sh"
        ),
        "allow"
    );
}

#[test]
fn listing_a_missing_path_proceeds_outside_hidden_locations() {
    let home = home("missing");
    let h = home.display();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            "ls ~/work/scripts 2>/dev/null | head".to_owned(),
            "ls ~/work/scripts/nested".to_owned(),
            format!("ls {h}/work/project/dist"),
            "ls missing-dir".to_owned(),
            // A missing entry inside a skill directory.
            "ls ~/.agents/skills/review-loop/missing".to_owned(),
        ] {
            assert_eq!(
                action(&home, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
    for command in [
        "ls ~/.ssh/missing",
        "ls ~/work/.hidden-missing",
        "ls ~/.config/missing",
        "ls ~/work/missing/.env",
        "ls ~/work/missing/id_rsa",
        "ls ~/work/missing/../.ssh",
        "ls ~/.agents/skills/review-loop/.cache/missing",
        "ls ~/.codex/missing",
    ] {
        assert_ne!(action(&home, "zcode", command), "allow", "{command}");
    }
}

#[test]
fn listing_a_missing_path_in_a_sibling_checkout_proceeds() {
    let home = home("sibling-missing");
    std::fs::create_dir_all(home.join("work/project-wt/scripts")).unwrap();
    std::fs::write(home.join("work/project-wt/.git"), "gitdir: x\n").unwrap();
    std::fs::write(home.join("work/project/.gitignore"), "node_modules\n").unwrap();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            "ls ../project-wt/node_modules 2>/dev/null",
            "ls ../../work/project-wt/node_modules/pkg",
            "ls -la ../project-wt; ls ../project-wt/node_modules 2>/dev/null; cat .gitignore",
        ] {
            assert_eq!(
                action(&home, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
    for command in [
        // Parent steps only lead the operand; hidden and sensitive names and
        // a missing name before `..` keep their review.
        "ls ../project-wt/missing/../scripts",
        "ls ../project-wt/.env-missing",
        "ls ../../.ssh/missing",
        "ls ../../.codex/missing",
        "ls ~/../missing",
    ] {
        assert_ne!(action(&home, "zcode", command), "allow", "{command}");
    }
}

#[test]
fn plugin_cache_listings_stay_under_the_skills_directory() {
    let home = home("plugin-cache");
    let version = home.join(".zcode/cli/plugins/cache/market/plugin/1.0.0");
    std::fs::create_dir_all(version.join("skills/review")).unwrap();
    std::fs::write(version.join("skills/review/SKILL.md"), "# Review\n").unwrap();
    std::fs::create_dir_all(version.join("logs")).unwrap();
    std::fs::write(version.join("logs/out.txt"), "ok\n").unwrap();
    assert_eq!(
        action(
            &home,
            "zcode",
            "ls ~/.zcode/cli/plugins/cache/market/plugin/1.0.0"
        ),
        "allow"
    );
    assert_eq!(
        action(
            &home,
            "zcode",
            "ls ~/.zcode/cli/plugins/cache/market/plugin/1.0.0/skills/review"
        ),
        "allow"
    );
    // Other plugin directories list by name like any home dot-directory.
    assert_eq!(
        action(
            &home,
            "zcode",
            "ls ~/.zcode/cli/plugins/cache/market/plugin/1.0.0/logs"
        ),
        "allow"
    );
    assert_ne!(
        action(
            &home,
            "zcode",
            "ls -R ~/.zcode/cli/plugins/cache/market/plugin/1.0.0/logs"
        ),
        "allow"
    );
}

#[test]
fn a_document_under_two_skill_roots_needs_only_one_to_admit_it() {
    let home = home("two-roots");
    // `.agents/skills` may link into another skill root, one level down.
    // The document is one component below the link but a full skill
    // document below `.claude/skills`.
    std::fs::create_dir_all(home.join(".claude/skills/notes")).unwrap();
    std::fs::write(home.join(".claude/skills/notes/SKILL.md"), "# Notes\n").unwrap();
    std::fs::remove_dir_all(home.join(".agents/skills")).unwrap();
    std::os::unix::fs::symlink(
        home.join(".claude/skills/notes"),
        home.join(".agents/skills"),
    )
    .unwrap();
    assert_eq!(
        action(&home, "zcode", "cat ~/.claude/skills/notes/SKILL.md"),
        "allow"
    );
}

#[test]
fn a_skills_link_to_the_home_directory_lists_nothing() {
    let home = home("home-link");
    std::fs::remove_dir_all(home.join(".agents/skills")).unwrap();
    std::os::unix::fs::symlink(&home, home.join(".agents/skills")).unwrap();
    assert_ne!(
        action(&home, "zcode", "find ~/.agents/skills/. -maxdepth 2"),
        "allow"
    );
}

#[test]
fn a_skills_link_to_home_stays_closed_when_home_is_spelled_through_a_symlink() {
    let canonical = home("home-link-alias");
    std::fs::remove_dir_all(canonical.join(".agents/skills")).unwrap();
    std::os::unix::fs::symlink(&canonical, canonical.join(".agents/skills")).unwrap();
    let alias = canonical.parent().unwrap().join(format!(
        "home-alias-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::os::unix::fs::symlink(&canonical, &alias).unwrap();
    assert_ne!(alias.canonicalize().unwrap(), alias);
    assert_eq!(alias.canonicalize().unwrap(), canonical);
    assert_ne!(
        action(&alias, "zcode", "find ~/.agents/skills/. -maxdepth 2"),
        "allow"
    );
    assert_eq!(action(&alias, "zcode", "ls ~/.codex/skills/notes"), "allow");
}
