#![cfg(unix)]

//! Claude Code `Bash` searches (`rg`, `grep -r`) over an ordinary workspace
//! that keeps a gitignored `.env` at its root.

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
        .join("../../target/pretool-workspace-rg-grep")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    write(home.join(".ssh/id_rsa"), "synthetic fixture\n");
    for name in ["app", "tracked", "custom", "noignore"] {
        let w = home.join(name);
        std::fs::create_dir_all(w.join(".git")).unwrap();
        for file in [
            "src/main.rs",
            "rust/crates/a/src/lib.rs",
            "rust/crates/a/Cargo.toml",
            "target/debug/out.txt",
            ".env",
            "config/.env.local",
        ] {
            write(w.join(file), "fn main() {}\n");
        }
    }
    // A linked worktree keeps a `.git` file pointing at the main checkout.
    let wt = home.join("wt");
    write(wt.join("src/main.rs"), "fn main() {}\n");
    write(wt.join(".env"), "KEY=1\n");
    write(wt.join(".gitignore"), ".env\n");
    write(
        home.join("main/.git/worktrees/wt/HEAD"),
        "ref: refs/heads/x\n",
    );
    write(
        wt.join(".git"),
        &format!(
            "gitdir: {}\n",
            home.join("main/.git/worktrees/wt").display()
        ),
    );
    write(home.join("app/.gitignore"), ".env\n.env.*\ntarget/\n");
    write(home.join("tracked/.gitignore"), "target/\n");
    write(home.join("custom/.gitignore"), ".env\n.env.*\n");
    write(home.join("custom/.ignore"), "!.env\n");
    Fixture { root, home }
}

fn run(f: &Fixture, cwd: &str, command: &str) -> PreToolResultV1 {
    let cwd = f.home.join(cwd);
    evaluate_pre_tool_envelope_with_context(
        "claude-code",
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
    eprintln!("{cwd}: {command} => {} {}", r.minimum_action, r.reason_code);
    assert_eq!(
        r.minimum_action,
        if want_allow { "allow" } else { "review" },
        "{cwd}: {command}: {} {}",
        r.minimum_action,
        r.reason_code
    );
}

#[test]
fn rg_workspace_searches_are_allowed() {
    let f = fixture();
    for c in ["rg -n foo", "rg --files src | head", "rg -l foo src"] {
        check(&f, "wt", c, true);
    }
    for c in [
        r#"rg -n "fn main" rust/crates/a/src"#,
        "rg --files src | head",
        "rg -n foo",
        "rg -l foo src",
        "rg --files",
        "rg foo .",
        "rg -n foo rust/crates --glob '*.rs'",
        "rg -n foo -t rust",
    ] {
        check(&f, "app", c, true);
    }
}

#[test]
fn grep_recursive_workspace_searches_are_allowed() {
    let f = fixture();
    for c in [
        "grep -r foo rust/crates",
        "grep -rn foo src",
        "grep -rn foo rust/crates --include='*.rs'",
    ] {
        check(&f, "app", c, true);
    }
}

#[test]
fn searches_that_can_reach_secrets_stay_reviewed() {
    let f = fixture();
    for c in [
        "rg foo .env",
        "rg foo config/.env.local",
        "rg foo ~/.ssh",
        "rg foo ..",
        "rg --no-ignore foo",
        "rg -u foo",
        "rg -uu foo",
        "rg -uuu foo",
        "rg --hidden foo",
        "rg -L foo",
        "rg --follow foo",
        "rg --pre cat foo",
        "rg -g '.env' foo",
        "rg -g '*.local' foo",
        "grep -r foo .env",
        "grep -r foo ~/.ssh",
        "grep -r foo ..",
        "grep -R foo .",
    ] {
        check(&f, "app", c, false);
    }
    // grep walks hidden files and ignores .gitignore, so `.env` is in reach.
    for c in [
        "grep -r foo .",
        "grep -rn foo config",
        "grep -rn foo . --include='*.rs'",
    ] {
        check(&f, "app", c, false);
    }
}

#[test]
fn rg_skips_hidden_files_so_a_root_env_is_not_in_reach_without_hidden_flags() {
    // Without `--hidden`/`-u`/`--no-ignore` style flags (all refused above)
    // ripgrep skips `.env`, tracked or ignored alike. An ignore file that
    // whitelists it (`custom`) does make ripgrep search it, so that workspace
    // is left out here.
    let f = fixture();
    for cwd in ["app", "tracked", "noignore"] {
        check(&f, cwd, "rg -n foo", true);
    }
}
