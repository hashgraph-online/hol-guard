#![cfg(unix)]

//! Searches of a route in a sibling repository, which is spelled with brackets.
//!
//! An agent working in one repository names another below home by its
//! absolute or `~` path, and a Next.js route there carries a bracket class.
//! The class matches nothing, so `rg` receives the word as typed and the
//! sibling screens read it as the path it spells.

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

/// An unquoted operand spelling of a fixture path. Whitespace in the checkout
/// path would otherwise split the word, and only the brackets are meant to
/// reach the shell unescaped.
fn bare(path: &str) -> String {
    path.replace(' ', "\\ ")
}

fn fixture() -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-rg-sibling-bracket")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");

    // The repository the agent works in.
    let portal = home.join("portal");
    std::fs::create_dir_all(portal.join(".git")).unwrap();
    write(portal.join("src/main.ts"), "export const a = 1;\n");

    // The sibling the agent searches.
    let badges = home.join("badges");
    std::fs::create_dir_all(badges.join(".git")).unwrap();
    for file in [
        "app/badge/[slug]/page.tsx",
        "app/badge/[slug]/route.ts",
        "app/[locale]/layout.tsx",
        "components/badge.tsx",
    ] {
        write(badges.join(file), "export default function Page() {}\n");
    }
    // A route whose class matches a one-letter sibling once case is folded.
    write(badges.join("app/[sidebar]/page.tsx"), "export default 2;\n");
    write(badges.join("app/S/page.tsx"), "export default 3;\n");
    write(badges.join(".gitignore"), "dist/\n");

    // The sibling agents really name sits a directory below home.
    let nested = home.join("projects/listing-badges");
    std::fs::create_dir_all(nested.join(".git")).unwrap();
    write(
        nested.join("app/blog/[slug]/blog-post-content.tsx"),
        "export const a = 1;\n",
    );

    // A sibling whose ignore file can re-include anything.
    let tools = home.join("tools");
    std::fs::create_dir_all(tools.join(".git")).unwrap();
    write(tools.join("app/[id]/page.tsx"), "export default 4;\n");
    write(tools.join("app/[id]/.env"), "TOKEN=fixture\n");
    write(tools.join(".ignore"), "!.env\n");

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
fn bracketed_routes_in_a_sibling_repository_are_searched() {
    let f = fixture();
    for command in [
        "rg -n export ~/badges/app/badge/[slug]",
        "rg -n export ~/badges/app/badge/[slug]/page.tsx",
        "rg -ln export ~/badges/app/[locale]",
        "rg -n export ~/badges/app/badge/[slug] ~/badges/components",
        "rg -n export -B14 -A6 ~/badges/app/badge/[slug]/page.tsx",
        "rg -c export ~/badges/app/[locale]/layout.tsx",
    ] {
        check(&f, command, true);
    }
    // The absolute spelling, quoted and bare, is the one agents write most.
    let badges = f.home.join("badges");
    let route = bare(
        &badges
            .join("app/badge/[slug]/page.tsx")
            .display()
            .to_string(),
    );
    for command in [
        format!("rg -n export {route}"),
        format!(
            "rg -n \"export|default\" \"{}\"",
            badges.join("app/badge/[slug]/page.tsx").display()
        ),
        format!(
            "rg -ln export {}/app/[locale]",
            bare(&badges.display().to_string())
        ),
        format!(
            "rg -n \"rel=|target=\" {}/app/blog/[slug]/blog-post-content.tsx",
            bare(&f.home.join("projects/listing-badges").display().to_string())
        ),
    ] {
        check(&f, &command, true);
    }
}

#[test]
fn bracketed_sibling_searches_that_could_reach_more_keep_their_review() {
    let f = fixture();
    for command in [
        // An ignore file in the sibling can re-include a hidden file, so the
        // walk proves nothing about what the search would read.
        "rg -n TOKEN ~/tools/app/[id]",
        // Under `nocaseglob` the class matches the directory named `S`.
        "rg -n export ~/badges/app/[sidebar]",
        // A negated class is this matcher's own refusal, not a literal name.
        "rg -n export ~/badges/components/[!x]",
        // A class that can match a leading dot would name a hidden entry
        // under `dotglob`.
        "rg -n export ~/badges/app/[,-0]",
    ] {
        check(&f, command, false);
    }
}
