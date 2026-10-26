#![cfg(unix)]

//! `rg` inclusion globs such as `*.md` or `README*` could name a credential
//! file, so they are proven by what they select in the searched tree.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn fixture() -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-rg-inclusion-globs")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    for name in ["game", "notes"] {
        let w = home.join(name);
        std::fs::create_dir_all(w.join(".git")).unwrap();
        for file in [
            "README.md",
            "AGENTS.md",
            "package.json",
            "index.html",
            "docs/guide.md",
            "src/main.ts",
            ".env",
        ] {
            write(w.join(file), "synthetic fixture\n");
        }
        write(w.join(".gitignore"), ".env\n");
    }
    // A credential directory whose files these globs would select.
    write(home.join("notes/secrets/README.md"), "synthetic fixture\n");
    write(home.join("notes/secrets/keys.md"), "synthetic fixture\n");
    Fixture { root, home }
}

fn run(f: &Fixture, cwd: &str, command: &str) -> PreToolResultV1 {
    let cwd = f.home.join(cwd);
    evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        f.home.to_str(),
        cwd.to_str(),
    )
}

fn check(f: &Fixture, cwd: &str, command: &str, want_allow: bool) {
    let r = run(f, cwd, command);
    assert_eq!(
        r.minimum_action,
        if want_allow { "allow" } else { "review" },
        "{cwd}: {command}: {} {}",
        r.minimum_action,
        r.reason_code
    );
}

#[test]
fn inclusion_globs_that_select_no_secret_are_allowed() {
    let f = fixture();
    for command in [
        "rg --files -g '!node_modules' -g '!\\.git' -g '!\\.env*' -g 'AGENTS.md' -g 'package.json' -g 'index.html' -g 'README*'",
        "rg --files -g 'README*'",
        "rg --files -g '*.md'",
        "rg --files --glob '*.md' docs",
        "rg --files --glob=*.md",
        "rg --files -g*.md .",
        "rg -n TODO -g '*.md'",
        "rg -n TODO -g '*.{md,html}' -g '!docs'",
        "rg -n TODO -g '*.md' README.md",
        // A glob that names a path selects inside that directory only.
        "rg -n TODO -g 'docs/*.md'",
        "rg --files -g 'docs/**'",
        "rg --files -g 'src/**' -g 'AGENTS.md'",
    ] {
        check(&f, "game", command, true);
    }
}

#[test]
fn inclusion_globs_that_reach_a_secret_stay_reviewed() {
    let f = fixture();
    for command in [
        "rg --files -g 'README*'",
        "rg --files -g '*.md'",
        "rg -n TODO -g '*.md'",
        "rg -n TODO -g '*.md' secrets",
        // A path-shaped glob is held to what it selects, like any other.
        "rg --files -g 'secrets/*.md'",
        "rg -n TODO -g 'secrets/**'",
    ] {
        check(&f, "notes", command, false);
    }
    for command in [
        // The secret file itself, a case-blind glob, and globs that could
        // select `.git`.
        "rg --files -g '.env*'",
        "rg --files --iglob '*.md'",
        "rg -n TODO -g '*'",
        "rg -n TODO -g '.g*'",
        // A bare `*` beside a path-shaped glob matches `.git` itself, which
        // is what lets ripgrep descend into it.
        "rg -n TODO -g 'src/**' -g '*'",
        "rg -n TODO --hidden -g '*.md'",
        "rg -n TODO --no-ignore -g '*.md'",
    ] {
        check(&f, "game", command, false);
    }
}
