#![cfg(unix)]

//! Searches of quoted Next.js route paths that hold both a route group and a
//! dynamic segment, such as `"app/(group)/blog/[slug]/page.tsx"`.
//!
//! A quoted word is never glob-expanded, in any shell, so the program receives
//! the brackets and parentheses exactly as typed. The path it names is then
//! screened like the same path without them. An unquoted bracket class is
//! still expanded by the shell, so it keeps the expansion proof, which does
//! not model the grouping parentheses mean to zsh and to extglob.

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
        .join("../../target/pretool-quoted-route-group-search")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    // The session works in one repository and searches a sibling one.
    std::fs::create_dir_all(home.join("portal/.git")).unwrap();
    let site = home.join("site");
    std::fs::create_dir_all(site.join(".git")).unwrap();
    for file in [
        "app/(group)/blog/[slug]/page.tsx",
        // A directory spelled like zsh's "not" pattern, so the literal name
        // holds only a component.
        "app/(group)/blog/^[slug]/page.tsx",
        "app/(shop)/s/[id]/page.tsx",
    ] {
        write(site.join(file), "export default function Page() {}\n");
    }
    // A one-letter sibling the class `[slug]` matches once the shell expands
    // it, holding an environment file.
    write(site.join("app/(group)/blog/s/.env"), "KEY=fixture\n");
    // A route that keeps a local environment file beside its component.
    write(
        site.join("app/(admin)/[id]/page.tsx"),
        "export default 1;\n",
    );
    write(site.join("app/(admin)/[id]/.env"), "KEY=fixture\n");
    Fixture { root, home }
}

fn check(f: &Fixture, command: &str, want_allow: bool) {
    let cwd = f.home.join("portal");
    let result: PreToolResultV1 = evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        f.home.to_str(),
        cwd.to_str(),
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
fn quoted_route_group_paths_are_searched_as_written() {
    let f = fixture();
    let site = f.home.join("site");
    let site = site.display();
    for command in [
        format!("grep -n export \"{site}/app/(group)/blog/[slug]/page.tsx\""),
        format!("grep -n -A8 export '{site}/app/(shop)/s/[id]/page.tsx' | head -14"),
        format!("rg -n export \"{site}/app/(group)/blog/[slug]/page.tsx\""),
        format!("rg -n export \"{site}/app/(shop)/s/[id]\""),
    ] {
        check(&f, &command, true);
    }
}

#[test]
fn route_group_searches_that_could_reach_more_keep_their_review() {
    let f = fixture();
    let site = f.home.join("site");
    let site = site.display();
    for command in [
        // The route keeps an environment file, so the tree below it is not
        // ordinary, quoted or not.
        format!("rg -n KEY \"{site}/app/(admin)/[id]\""),
        format!("grep -n KEY \"{site}/app/(admin)/[id]/.env\""),
        // The class sits outside the quotes, so the shell expands it to the
        // sibling `s`, whose environment file keeps the review.
        format!("rg -n KEY \"{site}/app/(group)/blog/\"[slug]"),
        // With zsh's `EXTENDED_GLOB`, an unquoted `^` means "every entry but
        // this one", so the search reaches the sibling `s` and its
        // environment file, even though every bracket is quoted.
        format!("rg -n KEY \"{site}/app/(group)/blog/\"^\"[slug]\""),
    ] {
        check(&f, &command, false);
    }
}
