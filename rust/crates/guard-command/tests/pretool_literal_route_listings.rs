#![cfg(unix)]

//! Listings of framework route folders, which are spelled with brackets.
//!
//! `ls ~/work/app/api/groups/\[slug\]/` lists one Next.js route folder. The
//! escaped or quoted brackets reach `ls` as typed, so the folder it lists is
//! screened as the path spelled out, wherever the spelling starts. The same
//! escape can also name a link the pattern would not match, so a literal
//! entry must clear the screen on its own.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
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
        .join("../../target/pretool-literal-route-listings")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let app = home.join("webapp");
    std::fs::create_dir_all(app.join(".git")).unwrap();
    write(
        app.join("app/api/groups/[slug]/route.ts"),
        "export function GET() {}\n",
    );
    // A folder named like a bracket class that is a link to the key folder,
    // beside the plain folder the class would match.
    write(home.join(".ssh/id_ed25519"), "");
    write(app.join("trap/k/a.txt"), "plain\n");
    std::os::unix::fs::symlink(home.join(".ssh"), app.join("trap/[k]")).unwrap();
    Fixture { root, home }
}

fn check(f: &Fixture, command: &str, want_allow: bool) {
    check_with_shell_home(f, &f.home, command, want_allow);
}

/// Evaluates `command` for a shell whose HOME is `shell_home`.
fn check_with_shell_home(f: &Fixture, shell_home: &Path, command: &str, want_allow: bool) {
    let cwd = f.home.join("webapp");
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_digest: "0".repeat(64),
        home: Some(shell_home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    let result: PreToolResultV1 = evaluate_pre_tool_envelope_with_execution_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: f.home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        Some(&environment),
    );
    assert_eq!(
        result.minimum_action,
        if want_allow { "allow" } else { "review" },
        "{command}: {} {}",
        result.minimum_action,
        result.reason_code
    );
}

#[test]
fn a_route_folder_listed_by_its_full_path_is_allowed() {
    let f = fixture();
    let groups = f.home.join("webapp/app/api/groups");
    let groups = groups.to_str().unwrap();
    for command in [
        format!(r#"ls "{groups}"/\[slug\]/"#),
        format!(r#"ls -la "{groups}"/\[slug\]"#),
        format!(r#"ls "{groups}"/ 2>/dev/null; ls "{groups}"/\[slug\]/ 2>/dev/null"#),
        format!(r#"ls "{groups}/[slug]/""#),
        format!("ls '{groups}/[slug]'"),
        r"ls ~/webapp/app/api/groups/\[slug\]/".to_string(),
        r"ls app/api/groups/\[slug\]/".to_string(),
    ] {
        check(&f, &command, true);
    }
}

#[test]
fn a_route_folder_listing_keeps_its_other_screens() {
    let f = fixture();
    let groups = f.home.join("webapp/app/api/groups");
    let groups = groups.to_str().unwrap();
    for command in [
        r"ls ~/.ssh/\[slug\]".to_string(),
        format!(r#"ls -R "{groups}"/\[slug\]"#),
    ] {
        check(&f, &command, false);
    }
}

#[test]
fn an_escaped_class_that_names_a_key_folder_link_is_reviewed() {
    let f = fixture();
    let trap = f.home.join("webapp/trap");
    let trap = trap.to_str().unwrap();
    for command in [
        r"ls trap/\[k\]".to_string(),
        r"ls trap/\[k\]/".to_string(),
        format!(r#"ls "{trap}"/\[k\]"#),
        "ls 'trap/[k]'".to_string(),
    ] {
        check(&f, &command, false);
    }
    // Unescaped, the shell matches the class against `k`, the plain folder.
    check(&f, "ls trap/[k]", true);
}

#[test]
fn a_home_spelled_route_folder_needs_the_shell_home_to_be_the_declared_one() {
    let f = fixture();
    // The shell expands `~` from its own HOME. When that names another
    // folder, the screen never saw what `ls` would list.
    let other = f.root.join("other");
    std::fs::create_dir_all(&other).unwrap();
    check_with_shell_home(&f, &other, r"ls ~/webapp/app/api/groups/\[slug\]/", false);
    check_with_shell_home(&f, &f.home, r"ls ~/webapp/app/api/groups/\[slug\]/", true);
}
