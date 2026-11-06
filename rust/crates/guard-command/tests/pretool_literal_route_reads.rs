#![cfg(unix)]

//! Content reads of framework route files, which are spelled with brackets.
//!
//! `head -50 app/blog/[slug]/page.tsx` names one file of a Next.js route. The
//! bracket class matches no entry, so the shell hands the program the word as
//! it was typed, and the file it names is screened as the path it spells out.

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
        .join("../../target/pretool-literal-route-reads")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let app = home.join("portal");
    std::fs::create_dir_all(app.join(".git")).unwrap();
    for file in [
        "app/blog/[slug]/page.tsx",
        "app/blog/[slug]/blog-post-content.tsx",
        "app/[locale]/layout.tsx",
        "app/dashboard/page.tsx",
    ] {
        write(app.join(file), "export default function Page() {}\n");
    }
    // A route whose class also reaches a one-letter sibling once the shell
    // folds case, so the word the program receives is not this route.
    write(app.join("app/[sidebar]/page.tsx"), "export default 2;\n");
    write(app.join("app/S/page.tsx"), "export default 3;\n");
    // A route that keeps a local environment file beside its component.
    write(app.join("app/admin/[id]/page.tsx"), "export default 1;\n");
    write(app.join("app/admin/[id]/.env"), "TOKEN=fixture\n");
    write(app.join(".gitignore"), ".env\n");
    // A name one space away from the route file, pointing at the file the
    // route's own screens refuse.
    std::os::unix::fs::symlink(
        app.join("app/admin/[id]/.env"),
        app.join("app/blog/[slug]/page.tsx "),
    )
    .unwrap();
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
fn reads_of_bracketed_route_files_are_allowed() {
    let f = fixture();
    for command in [
        "cat ~/portal/app/blog/[slug]/page.tsx",
        "head -50 ~/portal/app/blog/[slug]/blog-post-content.tsx",
        "tail -n 20 app/[locale]/layout.tsx",
        "wc -l app/blog/[slug]/page.tsx",
        "sed -n '1,40p' app/[locale]/layout.tsx",
        "awk '/noreferrer/ {print}' app/blog/[slug]/blog-post-content.tsx",
        "cat app/[locale]/layout.tsx app/dashboard/page.tsx",
    ] {
        check(&f, command, true);
    }
}

#[test]
fn bracketed_reads_that_could_reach_more_keep_their_review() {
    let f = fixture();
    for command in [
        // The environment file is what the class names, and no spelling of it
        // reads as an ordinary route file.
        "cat ~/portal/app/admin/[id]/.env",
        // Nothing is there to screen, so there is no proof to give.
        "cat ~/portal/app/blog/[missing]/page.tsx",
        // A negated class is this matcher's own refusal, not a literal name.
        "cat ~/portal/app/[!x]/layout.tsx",
        // A parent component leaves the tree whose rules were inspected.
        "cat ../portal/app/[locale]/layout.tsx",
        // Under `nocaseglob` the class matches the sibling named `S`, so the
        // word is not the literal route file the screens resolved.
        "cat ~/portal/app/[sidebar]/page.tsx",
        // A directory is not a content read however it is spelled.
        "cat ~/portal/app/blog/[slug]",
        // The trailing space is part of the name the shell passes on, so the
        // word names a link beside the route file rather than the route file.
        "cat 'app/blog/[slug]/page.tsx '",
    ] {
        check(&f, command, false);
    }
}
