#![cfg(unix)]
//! Content reads below a hidden directory in the home directory.
//!
//! A hidden component used to end the lookup on its own, so an ordinary
//! `cat ~/.github/workflows/ci.yml` collected an approval nobody answered.
//! What such a read has to clear: one hidden directory directly below home,
//! no credential store at any depth, no file name a secret is conventionally
//! written under, and no tree a narrower rule already owns — a harness home,
//! a shared skill tree and a download cache each keep the rule they had.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home with a Node toolchain, shared skills, a repository's own workflows,
/// a vendored crate, and the credential stores those reads must not reach. The
/// root stays below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-home-dotdir-content-reads")
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
        ".agents/skills/release-check/scripts",
        ".cargo/registry/src/index.crates.io/serde-1.0.0/src",
        ".certs",
        ".claude/projects/app",
        ".claude/shell-snapshots",
        ".codex/plans/order-intake",
        ".codex/sessions/2026-10-16",
        ".codex/skills/release-check",
        ".bun/bin",
        ".local/bin/helpers",
        ".config/doctl",
        ".config/gcloud",
        ".config/gh",
        ".config/configstore",
        ".config/github-copilot",
        ".config/ngrok",
        ".gemini",
        ".ngrok2",
        ".github/workflows",
        ".local/share/opencode",
        ".nvm/versions/node/v25.2.1/lib/node_modules/pkg",
        ".hol-support",
        ".secrets",
        ".ssh",
        "work/project/.git",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    for (path, contents) in [
        (".agents/skills/release-check/SKILL.md", "# Release\n"),
        (".hol-support/SAFETY.md", "# Safety\n"),
        (".agents/skills/release-check/config.json", "{}\n"),
        (".agents/skills/release-check/scripts/run.sh", "#!/bin/sh\n"),
        (
            ".cargo/registry/src/index.crates.io/serde-1.0.0/src/lib.rs",
            "pub fn parse() {}\n",
        ),
        (".bun/bin/bun", "\u{7f}ELF\n"),
        (".local/bin/helpers/run", "#!/bin/sh\n"),
        (".certs/server.pem", "-----BEGIN CERTIFICATE-----\n"),
        (".claude/.credentials.json", "{}\n"),
        (".claude/settings.json", "{\"env\": {}}\n"),
        (".claude/history.jsonl", "{}\n"),
        (".claude/projects/app/7f3.jsonl", "{}\n"),
        (
            ".claude/shell-snapshots/snapshot-zsh.sh",
            "export PATH=/usr/bin\n",
        ),
        (".codex/auth.json", "{}\n"),
        (".codex/plans/order-intake/todo.md", "# Todo\n"),
        (".codex/sessions/2026-10-16/rollout.jsonl", "{}\n"),
        (".codex/skills/release-check/notes.md", "# Notes\n"),
        (".config/doctl/config.yaml", "access-token: x\n"),
        (".config/gcloud/credentials.db", "x\n"),
        (".config/gh/hosts.yml", "example.com:\n"),
        (".config/github-copilot/apps.json", "{}\n"),
        (".claude.json", "{}\n"),
        (".config/configstore/firebase-tools.json", "{}\n"),
        (".config/ngrok/ngrok.yml", "authtoken: x\n"),
        (".envrc", "export TOKEN=x\n"),
        (".ngrok2/ngrok.yml", "authtoken: x\n"),
        (".gemini/oauth_creds.json", "{}\n"),
        (".github/workflows/ci.yml", "name: ci\n"),
        (".local/share/opencode/auth.json", "{}\n"),
        (
            ".nvm/versions/node/v25.2.1/lib/node_modules/pkg/package.json",
            "{\"name\": \"pkg\"}\n",
        ),
        (".secrets/prod.yaml", "password: x\n"),
        (".secrets/service-account.json", "{}\n"),
        (".yarnrc.yml", "npmAuthToken: x\n"),
        (".ssh/config", "Host example\n"),
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

/// The structured read tools: Claude Code's `Read` and Oh My Pi's `read`.
/// They never reach the shell screens, so the class rule has to sit at the
/// resolved-path gate both families end at.
fn native_action(home: &Path, harness: &str, tool: &str, target: &str) -> String {
    let cwd = home.join("work/project");
    let path = home.join(target);
    let path = path.to_str().unwrap();
    let input = if tool == "read" {
        json!({"path": path})
    } else {
        json!({"file_path": path})
    };
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

#[test]
fn ordinary_source_below_a_hidden_directory_reads() {
    let home = home("allowed");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "cat ~/.github/workflows/ci.yml",
            "head -20 ~/.github/workflows/ci.yml",
            "cat ~/.nvm/versions/node/v25.2.1/lib/node_modules/pkg/package.json",
            "cat ~/.cargo/registry/src/index.crates.io/serde-1.0.0/src/lib.rs",
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
fn credential_stores_and_harness_logins_keep_review() {
    let home = home("stores");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "cat ~/.ssh/config",
            "cat ~/.config/gh/hosts.yml",
            "cat ~/.config/doctl/config.yaml",
            "cat ~/.config/github-copilot/apps.json",
            "cat ~/.config/gcloud/credentials.db",
            "cat ~/.local/share/opencode/auth.json",
            "cat ~/.codex/auth.json",
            "cat ~/.claude/.credentials.json",
            "cat ~/.gemini/oauth_creds.json",
        ] {
            assert_ne!(
                action(&home, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

/// A token is written under its own name whatever directory holds it, so the
/// file name is screened even where every component cleared the store list.
#[test]
fn secret_bearing_file_names_keep_review_in_benign_directories() {
    let home = home("names");
    for command in [
        "cat ~/.agents/skills/release-check/config.json",
        "cat ~/.secrets/service-account.json",
        "cat ~/.certs/server.pem",
        "cat ~/.envrc",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

/// A tool writes its own credentials into the first file inside the directory
/// it owns, under whatever name it chose: `ngrok` picks `ngrok.yml`,
/// `firebase-tools` a JSON file named after itself. No stem list can keep up
/// with that, because every tool invents its own name. What they share is the
/// slot — directly inside the tool's directory, or directly below home — so
/// that slot keeps its review and content further down reads. Prose is the
/// exception: a token is not written in Markdown.
#[test]
fn a_tools_own_configuration_keeps_review() {
    let home = home("slots");
    for command in [
        "cat ~/.ngrok2/ngrok.yml",
        "cat ~/.config/ngrok/ngrok.yml",
        "cat ~/.config/configstore/firebase-tools.json",
        "cat ~/.secrets/prod.yaml",
        "cat ~/.yarnrc.yml",
        "cat ~/.claude.json",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
    for (harness, tool) in [("claude-code", "Read"), ("omp", "read")] {
        for target in [
            ".ngrok2/ngrok.yml",
            ".config/configstore/firebase-tools.json",
            ".secrets/prod.yaml",
            ".yarnrc.yml",
        ] {
            assert_ne!(
                native_action(&home, harness, tool, target),
                "allow",
                "{harness} {tool} {target}"
            );
        }
    }
}

/// A tool's program directory holds executables. `cat ~/.bun/bin/bun` prints a
/// binary, which is not a read a task makes; what an agent wants there is
/// whether the tool is installed, and the listing screen already answers that.
/// The same directories are where a link points away from the home directory,
/// so the content side keeps its review.
#[test]
fn a_tools_program_directory_keeps_review() {
    let home = home("programs");
    assert_ne!(action(&home, "codex", "cat ~/.bun/bin/bun"), "allow");
    for (harness, tool) in [("claude-code", "Read"), ("omp", "read")] {
        assert_ne!(
            native_action(&home, harness, tool, ".bun/bin/bun"),
            "allow",
            "{harness} {tool}"
        );
    }
}

/// A program directory holds the same thing one level further down. A helper
/// under `~/.local/bin/helpers` is still an executable, so nesting it does not
/// move it out of the directory's review.
#[test]
fn a_nested_program_directory_keeps_review() {
    let home = home("nested-programs");
    assert_ne!(
        action(&home, "codex", "cat ~/.local/bin/helpers/run"),
        "allow"
    );
    for (harness, tool) in [("claude-code", "Read"), ("omp", "read")] {
        assert_ne!(
            native_action(&home, harness, tool, ".local/bin/helpers/run"),
            "allow",
            "{harness} {tool}"
        );
    }
}

/// A narrower rule owns the agent guidance documents: the skill-document rule
/// answers a `SKILL.md`, and the safety-document rule answers
/// `~/.hol-support/SAFETY.md` with bounds a target screen cannot see. This
/// screen stands aside rather than giving those paths a second answer, so the
/// script beside a skill document stays outside the read rules as before.
#[test]
fn narrower_document_rules_keep_their_paths() {
    let home = home("guidance");
    for command in [
        "cat ~/.agents/skills/release-check/SKILL.md",
        "cat ~/.hol-support/SAFETY.md",
    ] {
        assert_eq!(action(&home, "codex", command), "allow", "{command}");
    }
    for command in [
        "cat ~/.agents/skills/release-check/scripts/run.sh",
        "cat ~/.agents/skills/release-check/config.json",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

/// A harness home keeps the rule it had. Its document side was already open
/// through the harness-notes rule; this screen adds nothing there, and the
/// login, the settings file and the saved conversations stay reviewed.
#[test]
fn a_harness_home_keeps_its_own_rule() {
    let home = home("harness");
    for command in [
        "cat ~/.codex/skills/release-check/notes.md",
        "cat ~/.codex/plans/order-intake/todo.md",
    ] {
        assert_eq!(action(&home, "codex", command), "allow", "{command}");
    }
    for command in [
        "grep -n -i guard ~/.claude/settings.json",
        "cat ~/.codex/sessions/2026-10-16/rollout.jsonl",
        "cat ~/.claude/projects/app/7f3.jsonl",
        "cat ~/.claude/history.jsonl",
        "cat ~/.claude/shell-snapshots/snapshot-zsh.sh",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

/// A `Read` of the same file is the same read. The shell screens sit on a
/// spelling; a structured tool hands over a path, so without the rule at the
/// resolved gate the harnesses that read this way keep asking.
#[test]
fn the_native_read_tool_answers_as_the_shell_does() {
    let home = home("native");
    for (harness, tool) in [("claude-code", "Read"), ("omp", "read")] {
        for target in [
            ".github/workflows/ci.yml",
            ".nvm/versions/node/v25.2.1/lib/node_modules/pkg/package.json",
            ".cargo/registry/src/index.crates.io/serde-1.0.0/src/lib.rs",
            ".codex/plans/order-intake/todo.md",
        ] {
            assert_eq!(
                native_action(&home, harness, tool, target),
                "allow",
                "{harness} {tool} {target}"
            );
        }
        for target in [
            ".agents/skills/release-check/scripts/run.sh",
            ".ssh/config",
            ".config/gh/hosts.yml",
            ".config/gcloud/credentials.db",
            ".local/share/opencode/auth.json",
            ".codex/auth.json",
            ".claude/.credentials.json",
            ".gemini/oauth_creds.json",
            ".agents/skills/release-check/config.json",
            ".secrets/service-account.json",
            ".certs/server.pem",
            ".envrc",
            ".codex/sessions/2026-10-16/rollout.jsonl",
            ".claude/shell-snapshots/snapshot-zsh.sh",
        ] {
            assert_ne!(
                native_action(&home, harness, tool, target),
                "allow",
                "{harness} {tool} {target}"
            );
        }
    }
}
