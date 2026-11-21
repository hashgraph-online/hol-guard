#![cfg(unix)]
//! `fd` below a home dot-directory, where the search pattern bounds what the
//! walk prints.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home whose skill tree is several levels deep and holds an `.env` of its
/// own, beside the credential stores a deeper walk must never name.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-fd-hidden-home-root")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    for directory in [
        ".agents/skills/github-pr-review-loop/scripts",
        ".agents/skills/github-pr-review-loop/references",
        ".agents/skills/cloudflare-vitals",
        ".config/app-portal/scripts",
        ".config/gh",
        ".codex/plans",
        ".ssh",
        "work/project/.git",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    for (path, contents) in [
        (
            ".agents/skills/github-pr-review-loop/SKILL.md",
            "# Review loop\n",
        ),
        (
            ".agents/skills/github-pr-review-loop/scripts/pr-approve-merge.sh",
            "#!/bin/sh\necho merge\n",
        ),
        (
            ".agents/skills/github-pr-review-loop/references/review-merge.md",
            "# Merge\n",
        ),
        (".agents/skills/cloudflare-vitals/.env", "TOKEN=x\n"),
        (".config/app-portal/scripts/run.sh", "#!/bin/sh\n"),
        (".config/gh/hosts.yml", "example.com:\n"),
        (".codex/auth.json", "{}\n"),
        (".codex/plans/todo.md", "# Todo\n"),
        (".ssh/id_ed25519", "key\n"),
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
fn a_literal_pattern_bounds_a_search_below_a_home_dot_directory() {
    let home = home("bounded");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "fd pr-approve-merge ~/.agents/skills/github-pr-review-loop",
            "fd \"pr-approve-merge\" ~/.agents",
            "fd -t f -d 3 pr-approve-merge ~/.agents",
            "fd --type f review-loop ~/.agents",
            "fd SKILL.md ~/.agents/skills",
            "fd -e md review ~/.codex/plans",
            "fd run.sh ~/.agents ~/.config/app-portal",
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
fn a_pattern_that_bounds_nothing_keeps_its_review() {
    let home = home("unbounded");
    for command in [
        // No pattern at all: the walk prints the whole tree.
        "fd . ~/.agents",
        // A regular expression selects whatever the tree happens to hold.
        "fd \".*\" ~/.agents",
        "fd \"review|approve\" ~/.agents",
        "fd \"^pr-\" ~/.agents",
        // Two characters name too little to be the word an agent asked for.
        "fd sh ~/.agents",
        // Path matching is satisfied by a directory prefix, so every entry
        // below that directory prints.
        "fd --full-path scripts ~/.agents",
        "fd -p pr-approve-merge ~/.agents",
        "fd --absolute-path pr-approve-merge ~/.agents",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

#[test]
fn a_pattern_that_could_select_a_credential_keeps_its_review() {
    let home = home("credential");
    for command in [
        "fd auth ~/.codex",
        "fd config ~/.agents",
        "fd credentials ~/.agents",
        "fd token ~/.agents",
        "fd env ~/.agents",
        "fd id_ed25519 ~/.agents",
        "fd settings.json ~/.codex",
        "fd cert.pem ~/.agents",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

#[test]
fn a_root_or_option_that_widens_the_walk_keeps_its_review() {
    let home = home("store");
    for command in [
        // Credential stores keep their review whatever the pattern says.
        "fd pr-approve-merge ~/.ssh",
        "fd hosts.yml ~/.config/gh",
        "fd pr-approve-merge ~/.agents ~/.ssh",
        // Hidden entries, links and a command per match are all refused
        // outright, so the bounded route never sees them.
        "fd --hidden pr-approve-merge ~/.agents",
        "fd -H pr-approve-merge ~/.agents",
        "fd --follow pr-approve-merge ~/.agents",
        "fd pr-approve-merge ~/.agents --exec cat",
        "fd -u pr-approve-merge ~/.agents",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

#[test]
fn a_wildcard_or_a_shared_root_keeps_its_review() {
    let home = home("wildcard");
    for command in [
        // `fd` reads its pattern as a regular expression, so `.` stands for
        // any character and spells the word it is written around.
        "fd a..h ~/.codex",
        "fd t.ken ~/.agents",
        "fd cr.dentials ~/.agents",
        "fd id.ed25519 ~/.agents",
        // A format suffix on its own selects every file of that format the
        // tree holds, the tool's own login among them.
        "fd json ~/.codex",
        "fd yaml ~/.agents",
        "fd toml ~/.codex",
        // A fragment of a suffix, or a spelling written around one, selects
        // those files too.
        "fd son ~/.codex",
        "fd h.json ~/.codex",
        // `~/.config` holds one directory per tool, so a walk below it
        // prints paths through the credential stores beside them.
        "fd yml ~/.config",
        "fd run.sh ~/.config",
        "fd pr-approve-merge ~/.local/share",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}
