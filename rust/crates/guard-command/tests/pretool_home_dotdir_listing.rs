#![cfg(unix)]
//! Name-only listings of home dot-directories that store no credentials
//! proceed; credential stores, recursive walks, content reads and writes keep
//! review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home with ordinary tool state, credential stores at the top level and
/// below `~/.config` and `~/.local/share`, and a project. The root stays below
/// the target directory: `$TMPDIR` on macOS resolves under `/private/var`,
/// which the sensitive-root screen rejects.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-home-dotdir-listing")
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
        ".agents/skills/example-skill",
        ".config/app-portal/.cache",
        ".config/gh",
        ".config/github-copilot",
        ".local/share/app-portal",
        ".local/share/opencode",
        ".local/share/keyrings",
        ".aws",
        ".codex",
        ".copilot",
        ".docker",
        ".gemini",
        ".gnupg",
        ".hol-guard",
        ".omp/agent",
        ".kube",
        ".ssh",
        "work/project/.git",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    for (path, contents) in [
        (".agents/skills/example-skill/SKILL.md", "# Example\n"),
        (
            ".config/app-portal/settings.json",
            "{\"theme\": \"dark\"}\n",
        ),
        (".config/gh/hosts.yml", "example.com:\n"),
        (".ssh/config", "Host example\n"),
        ("work/project/.git/HEAD", "ref: refs/heads/main\n"),
    ] {
        std::fs::write(home.join(path), contents).unwrap();
    }
    std::os::unix::fs::symlink(home.join(".ssh"), home.join(".remote-hosts")).unwrap();
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
fn ordinary_home_dot_directories_list_by_name() {
    let home = home("allowed");
    let absolute = format!("ls {}/.config/", home.display());
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "ls ~/.config/",
            "ls ~/.config",
            "ls -la ~/.config",
            "ls ~/.agents/",
            "ls ~/.agents/skills/",
            "ls ~/.agents/skills/example-skill/",
            "ls ~/.config/app-portal",
            "ls ~/.local/share",
            "find ~/.config -maxdepth 1 -type d",
            absolute.as_str(),
        ] {
            assert_eq!(
                action(&home, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn credential_stores_keep_review_at_any_depth() {
    let home = home("stores");
    for command in [
        "ls ~/.ssh",
        "ls ~/.ssh/",
        "ls ~/.aws",
        "ls ~/.gnupg",
        "ls ~/.kube",
        "ls ~/.docker",
        "ls ~/.hol-guard",
        "ls ~/.codex",
        "ls ~/.gemini",
        "ls ~/.omp",
        "ls ~/.omp/agent",
        "ls ~/.copilot",
        "find ~/.gemini -maxdepth 1",
        "ls ~/.config/gh",
        "ls ~/.config/github-copilot",
        "ls ~/.local/share/opencode",
        "ls ~/.config/gh/",
        "ls ~/.local/share/keyrings",
        "find ~/.config/gh -maxdepth 1",
        // A link that dresses a store as an ordinary dot-directory.
        "ls ~/.remote-hosts",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

#[test]
fn walks_reads_globs_and_writes_in_home_dot_directories_keep_review() {
    let home = home("neighbours");
    for command in [
        // A recursive listing of `~/.config` prints the names inside `~/.config/gh`.
        "ls -R ~/.config",
        "find ~/.config -maxdepth 2",
        "find ~/.config",
        "find ~/.config -maxdepth 1 -maxdepth 3",
        "grep -r theme ~/.config",
        "cat ~/.config/gh/hosts.yml",
        "ls ~/.config/*",
        "ls ~/.config/app-portal/.cache",
        "ls ~/.config/missing",
        "mkdir -p ~/.config/app-portal/extra",
        "touch ~/.config/app-portal/new.json",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}
