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
        ".config/doctl",
        ".config/gh",
        ".config/github-copilot",
        ".local/share/app-portal",
        ".local/share/opencode",
        ".local/share/keyrings",
        ".aws",
        ".claude/projects/p/memory",
        ".codex/plans",
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
        (".config/doctl/config.yaml", "access-token: x\n"),
        (".config/gh/hosts.yml", "example.com:\n"),
        (".claude/.credentials.json", "{}\n"),
        (".claude/settings.json", "{}\n"),
        (".claude/projects/p/memory/note.md", "# Note\n"),
        (".codex/auth.json", "{}\n"),
        (".codex/config.toml", "model = \"x\"\n"),
        (".codex/plans/todo.md", "# Todo\n"),
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
            "ls -la ~/.config/doctl",
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
        "cat ~/.config/doctl/config.yaml",
        "ls ~/.config/*",
        "ls ~/.config/app-portal/.cache",
        "ls ~/.config/missing",
        "mkdir -p ~/.config/app-portal/extra",
        "touch ~/.config/app-portal/new.json",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

#[test]
fn harness_homes_list_and_read_notes_but_not_logins() {
    let home = home("harness");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "ls ~/.codex",
            "ls -la ~/.codex/plans",
            "ls ~/.claude/projects/p/memory",
            "find ~/.claude -maxdepth 1",
            "cat ~/.claude/projects/p/memory/note.md",
            "sed -n 1,5p ~/.claude/projects/p/memory/note.md",
            "head -20 ~/.codex/plans/todo.md",
        ] {
            assert_eq!(
                action(&home, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
    for command in [
        "ls -R ~/.claude",
        "find ~/.codex -maxdepth 3",
        "cat ~/.codex/auth.json",
        "cat ~/.claude/.credentials.json",
        "grep -n -i guard ~/.claude/settings.json",
        "head ~/.codex/config.toml",
        "sed -i s/a/b/ ~/.claude/projects/p/memory/note.md",
        "ls ~/.claude/.credentials.json",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

#[test]
fn file_reports_the_type_of_an_existing_executable_outside_the_workspace() {
    let home = home("file-type");
    let tool = home.parent().unwrap().join("tool-binary");
    std::fs::write(&tool, b"\x7fELF").unwrap();
    for harness in ["claude-code", "codex", "omp"] {
        let command = format!("file {}", tool.display());
        assert_eq!(
            action(&home, harness, &command),
            "allow",
            "{harness}: {command}"
        );
    }
}

/// A home with a memory index in two Claude Code projects, beside a session
/// transcript and a project that has no index.
fn memory_home(name: &str) -> PathBuf {
    let home = home(name);
    for project in ["p", "-Users-dev-work-api"] {
        let memory = home.join(".claude/projects").join(project).join("memory");
        std::fs::create_dir_all(&memory).unwrap();
        std::fs::write(memory.join("MEMORY.md"), "# Memory\n").unwrap();
    }
    std::fs::write(home.join(".claude/projects/p/session.jsonl"), "{}\n").unwrap();
    std::fs::create_dir_all(home.join(".claude/projects/no-index")).unwrap();
    home
}

#[test]
fn claude_memory_indexes_read_across_projects() {
    let home = memory_home("memory-glob");
    let absolute = format!("cat {}/.claude/projects/*/memory/MEMORY.md", home.display());
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "cat ~/.claude/projects/*/memory/MEMORY.md",
            "cat ~/.claude/projects/*/memory/MEMORY.md 2>/dev/null",
            "ls -la; node --version; cat ~/.claude/projects/*/memory/MEMORY.md 2>/dev/null",
            "cat ~/.claude/projects/*/memory/*.md",
            "cat ~/.claude/projects/?/memory/note.md",
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
fn wildcard_directories_outside_harness_notes_keep_review() {
    let home = memory_home("memory-glob-review");
    for (path, contents) in [
        (".config/app-portal/x.md", "# Notes\n"),
        (".ssh/keys/x", "key\n"),
        ("projects/api/secret.md", "# Secret\n"),
        (".claude/projects/settings.json", "{}\n"),
        (".claude/sessions/a/MEMORY.md", "# Transcript\n"),
    ] {
        std::fs::create_dir_all(home.join(path).parent().unwrap()).unwrap();
        std::fs::write(home.join(path), contents).unwrap();
    }
    for command in [
        "cat ~/.config/*/x.md",
        "cat ~/.ssh/*/x",
        "cat /etc/*/x.md",
        "cat ~/projects/*/secret.md",
        "cat ~/.claude/projects/*/*.jsonl",
        "cat ~/.claude/*/settings.json",
        "cat ~/.claude/s*/*/MEMORY.md",
        "cat ~/.claude/**/MEMORY.md",
        "cat ~/.claude/projects/[p-]*/memory/MEMORY.md",
        "cat ~/.claude/projects/*/missing/MEMORY.md",
    ] {
        assert_ne!(action(&home, "claude-code", command), "allow", "{command}");
    }
}

#[test]
fn memory_index_globs_over_links_and_hidden_projects_keep_review() {
    let command = "cat ~/.claude/projects/*/memory/MEMORY.md 2>/dev/null";

    let outside = memory_home("memory-glob-outside");
    let elsewhere = outside.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("memory")).unwrap();
    std::fs::write(elsewhere.join("memory/MEMORY.md"), "# Elsewhere\n").unwrap();
    std::os::unix::fs::symlink(&elsewhere, outside.join(".claude/projects/linked")).unwrap();
    assert_ne!(action(&outside, "claude-code", command), "allow");

    let transcript = memory_home("memory-glob-transcript");
    let memory = transcript.join(".claude/projects/q/memory");
    std::fs::create_dir_all(&memory).unwrap();
    std::os::unix::fs::symlink(
        transcript.join(".claude/projects/p/session.jsonl"),
        memory.join("MEMORY.md"),
    )
    .unwrap();
    assert_ne!(action(&transcript, "claude-code", command), "allow");

    let hidden = memory_home("memory-glob-hidden");
    let memory = hidden.join(".claude/projects/.archive/memory");
    std::fs::create_dir_all(&memory).unwrap();
    std::fs::write(memory.join("MEMORY.md"), "# Hidden\n").unwrap();
    assert_ne!(action(&hidden, "claude-code", command), "allow");
}

#[test]
fn a_harness_note_that_does_not_exist_yet_reads_as_nothing() {
    let home = memory_home("memory-missing");
    let absolute = format!(
        "ls -la; node --version; cat {}/.claude/projects/no-index/memory/MEMORY.md 2>/dev/null",
        home.display()
    );
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "cat ~/.claude/projects/-Users-dev-new/memory/MEMORY.md 2>/dev/null",
            "cat ~/.claude/projects/p/memory/missing.md",
            "head -20 ~/.codex/plans/missing.md",
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
fn a_structured_read_of_a_missing_note_stays_unproved() {
    let home = memory_home("memory-structured");
    let cwd = home.join("work/project");
    let path = home.join(".claude/projects/no-index/memory/MEMORY.md");
    assert!(!path.exists());
    let result = evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "view", "tool_input": {"file_path": path}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    );
    assert_ne!(result.minimum_action, "allow");
}

#[test]
fn missing_notes_outside_harness_documents_keep_review() {
    let home = memory_home("memory-missing-review");
    let memory = home.join(".claude/projects/p/memory");
    std::os::unix::fs::symlink(home.join(".ssh/new_key"), memory.join("dangling.md")).unwrap();
    std::os::unix::fs::symlink(home.join(".config"), home.join(".claude/projects/linked")).unwrap();
    for command in [
        "cat ~/.claude/sessions/a/missing.md",
        "cat ~/.claude/projects/p/.hidden/missing.md",
        "cat ~/.claude/projects/p/memory/missing.json",
        "cat ~/.config/app-portal/missing.md",
        "cat ~/.claude/projects/p/memory/dangling.md",
        "cat ~/.claude/projects/linked/missing.md",
    ] {
        assert_ne!(action(&home, "claude-code", command), "allow", "{command}");
    }
}
