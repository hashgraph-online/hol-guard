#![cfg(unix)]

//! `cd` into a dynamic route folder whose name holds brackets, such as
//! `app/items/[slug]`, followed by a read inside it.
//!
//! Quoted, the shell passes the folder name through as typed, so the read
//! runs in the folder the proof resolves. Unquoted, `[slug]` is a glob class
//! that can match a one-letter sibling instead, so it keeps the review.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use guard_contracts::GuardExecutionEnvironmentV1;
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
        .join("../../target/pretool-cd-quoted-bracket-directory")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let site = home.join("storefront");
    std::fs::create_dir_all(site.join(".git")).unwrap();
    write(
        site.join("app/items/[slug]/parts/card.tsx"),
        "export function Card() {}\n",
    );
    write(
        site.join("app/items/[slug]/page.tsx"),
        "export default function Page() {}\n",
    );
    // A one-letter sibling the unquoted class `[slug]` matches, holding an
    // environment file.
    write(site.join("app/items/s/.env"), "KEY=fixture\n");
    // A route that keeps a local environment file beside its component.
    write(site.join("app/items/[id]/page.tsx"), "export default 1;\n");
    write(site.join("app/items/[id]/.env"), "KEY=fixture\n");
    // A key store whose folder name holds brackets.
    write(home.join(".ssh/[keys]/id_ed25519"), "fixture\n");
    Fixture { root, home }
}

/// Checks that the omp and zcode shell harnesses both settle `command` on
/// the expected action, reporting the pair when either differs.
fn check(f: &Fixture, command: &str, want_allow: bool) {
    let home = f.home.to_str().unwrap();
    let cwd = f.home.join("storefront");
    let environment = GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".to_owned()],
        environment_digest: "0".repeat(64),
        home: Some(home.to_owned()),
        git_config_no_system: true,
        ..Default::default()
    };
    let want = if want_allow { "allow" } else { "review" };
    let actions = ["omp", "zcode"].map(|harness| {
        evaluate_pre_tool_envelope_with_execution_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            PathContext {
                home_dir: Some(home),
                cwd: cwd.to_str(),
                ..PathContext::default()
            },
            Some(&environment),
        )
        .minimum_action
    });
    assert_eq!(actions, [want, want].map(String::from), "{command}");
}

#[test]
fn quoted_bracket_folders_are_entered_as_written() {
    let f = fixture();
    let site = f.home.join("storefront");
    let site = site.display();
    for command in [
        format!("cd \"{site}/app/items/[slug]/parts\" && grep -n \"export\" card.tsx | head -40"),
        format!("cd '{site}/app/items/[slug]/parts' && cat card.tsx"),
        "cd \"app/items/[slug]\" && ls".to_string(),
        "cd app/items/\"[slug]\" && grep -n export page.tsx".to_string(),
    ] {
        check(&f, &command, true);
    }
}

#[test]
fn bracket_folders_that_could_reach_more_keep_their_review() {
    let f = fixture();
    let site = f.home.join("storefront");
    let site = site.display();
    let home = f.home.display();
    for command in [
        // Unquoted, the class matches the sibling `s` and its environment
        // file.
        "cd app/items/[slug] && cat .env".to_string(),
        format!("cd \"{site}/app/items/\"[slug] && ls -a"),
        // A quoted star is still refused as a directory name.
        "cd \"app/items/*\" && ls".to_string(),
        // The quoted folder holds an environment file.
        "cd \"app/items/[id]\" && cat .env".to_string(),
        // A quoted bracket folder inside a key store.
        format!("cd \"{home}/.ssh/[keys]\" && cat id_ed25519"),
    ] {
        check(&f, &command, false);
    }
}
