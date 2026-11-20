#![cfg(unix)]
//! `find` below a home dot-directory, where a name pattern bounds what the
//! walk prints.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home whose skill tree is several levels deep and holds an `.env` of its
/// own, beside the credential stores a deeper walk must never name.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-find-hidden-home-match")
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
fn a_name_pattern_bounds_what_a_deeper_walk_prints() {
    let home = home("bounded");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "find ~/.agents -maxdepth 4 -name pr-approve-merge.sh",
            "find ~/.agents -maxdepth 4 -name \"pr-approve-merge.sh\" 2>/dev/null",
            "find ~/.agents -name \"*review-loop*\" -type d",
            "find ~/.agents/skills/github-pr-review-loop -type f -name \"*.md\"",
            "find ~/.agents -maxdepth 6 -iname \"REVIEW-MERGE.MD\"",
            "find ~/.codex -maxdepth 4 -name \"*.md\"",
            "find ~/.config/app-portal -maxdepth 4 -name run.sh",
            "find ~/.agents ~/.config/app-portal -maxdepth 4 -name run.sh",
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
fn an_unbounded_or_widened_expression_keeps_its_review() {
    let home = home("unbounded");
    // `~/.agents` is a skill root, which lists without review whatever the
    // expression says, so these use a dot-directory this rule alone reaches.
    for command in [
        // Nothing narrows the output, so the walk prints the whole tree.
        "find ~/.config/app-portal -maxdepth 4",
        "find ~/.config/app-portal -maxdepth 4 -type f",
        // Negation and alternation both print what the pattern excluded.
        "find ~/.config/app-portal -maxdepth 4 -not -name \"*.md\"",
        "find ~/.config/app-portal -maxdepth 4 ! -name \"*.md\"",
        "find ~/.config/app-portal -maxdepth 4 -name \"*.md\" -o -name \"*.sh\"",
        "find ~/.config/app-portal -maxdepth 4 \\( -name \"*.md\" \\)",
        // A pattern that selects everything bounds nothing.
        "find ~/.config/app-portal -maxdepth 4 -name \"*\"",
        // `-path` matches the whole path, so a directory prefix satisfies it
        // and every entry below that directory prints.
        "find ~/.config/app-portal -path \"*/scripts/*\"",
        "find ~/.config/app-portal -wholename \"*/scripts/pr-approve-merge.sh\"",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

#[test]
fn a_pattern_that_could_name_a_credential_keeps_its_review() {
    let home = home("credential");
    for command in [
        "find ~/.config/app-portal -maxdepth 4 -name .env",
        "find ~/.config/app-portal -maxdepth 4 -name \".env*\"",
        "find ~/.config/app-portal -maxdepth 4 -name \"*.pem\"",
        "find ~/.config/app-portal -maxdepth 4 -name auth.json",
        "find ~/.config/app-portal -maxdepth 4 -name credentials.json",
        "find ~/.config/app-portal -maxdepth 4 -name \"id_*\"",
        "find ~/.config/app-portal -maxdepth 4 -name config.toml",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

#[test]
fn a_root_inside_a_credential_store_keeps_its_review() {
    let home = home("store");
    for command in [
        "find ~/.ssh -maxdepth 2 -name \"*.pub\"",
        "find ~/.config/gh -maxdepth 2 -name \"*.yml\"",
        // An action runs a program per match whatever the pattern says.
        "find ~/.config/app-portal -maxdepth 4 -name \"*.sh\" -exec cat {} ;",
        "find ~/.config/app-portal -maxdepth 4 -name \"*.sh\" -delete",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

#[test]
fn a_print_before_the_pattern_keeps_its_review() {
    let home = home("print-order");
    for command in [
        // `find` runs the print for every entry it reaches before the
        // pattern filters anything, so the whole tree prints.
        "find ~/.config/app-portal -print -name run.sh",
        "find ~/.config/app-portal -print0 -name run.sh",
        "find ~/.codex -print -name todo.md",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
    assert_eq!(
        action(
            &home,
            "codex",
            "find ~/.config/app-portal -name run.sh -print"
        ),
        "allow"
    );
}

#[test]
fn a_glob_that_could_reach_a_login_keeps_its_review() {
    let home = home("glob");
    for command in [
        "find ~/.codex -maxdepth 4 -name \"*.json\"",
        "find ~/.codex -maxdepth 4 -name \"*h.json\"",
        // A long literal run that is a kind and not a name: the dot binds an
        // extension, and `json` is what every file of the kind is written
        // under, `auth.json` among them.
        "find ~/.codex -maxdepth 4 -name \"*notes.json\"",
        "find ~/.codex -maxdepth 4 -name \"*json*\"",
        "find ~/.codex -maxdepth 4 -name \"a?th.json\"",
        "find ~/.codex -maxdepth 4 -name \"aut*\"",
        "find ~/.codex -maxdepth 4 -name \"[ac]*.json\"",
        "find ~/.config/app-portal -maxdepth 4 -name \"*.sh\"",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

#[test]
fn a_shared_root_keeps_its_review_once_the_walk_goes_deeper() {
    let home = home("shared-root");
    for command in [
        // `~/.config` holds one directory per tool, so a walk below it prints
        // paths through the credential stores the listing screen refuses.
        "find ~/.config -name hosts.yml",
        "find ~/.config -maxdepth 4 -name run.sh",
        "find ~/.local/share -maxdepth 4 -name run.sh",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
    // The directory's own entry names still list: that walk stops at the
    // tool directories themselves and never enters one.
    assert_eq!(
        action(&home, "codex", "find ~/.config -maxdepth 1"),
        "allow"
    );
}

#[test]
fn a_wildcard_reaches_a_login_through_the_letters_it_stands_for() {
    let home = home("wildcard");
    for command in [
        // `a*uth*` spells `auth` once the wildcards stand for nothing, and
        // `to*ken` and `cred?ntials` spell what they are named after.
        "find ~/.codex -maxdepth 4 -name \"a*uth*\"",
        "find ~/.codex -maxdepth 4 -name \"to*ken*.md\"",
        "find ~/.codex -maxdepth 4 -name \"cred?ntials*.md\"",
        "find ~/.codex -maxdepth 4 -name \"*k?y.md\"",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
    // A name that merely holds a secret-bearing word among its letters is an
    // ordinary name: the screen reads a wildcard-free pattern as a whole
    // file name, the way a file name is read.
    for command in [
        "find ~/.codex -maxdepth 4 -name keyboard",
        "find ~/.codex -maxdepth 4 -name tokenizer.rs",
        "find ~/.codex -maxdepth 4 -name accounting.md",
    ] {
        assert_eq!(action(&home, "codex", command), "allow", "{command}");
    }
}
