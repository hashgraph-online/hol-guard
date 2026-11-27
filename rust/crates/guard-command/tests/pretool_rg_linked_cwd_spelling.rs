#![cfg(unix)]
//! A content search run from a working directory the harness spells through
//! a directory link, as macOS spells `/private/tmp` as `/tmp`:
//! `rg -n "needle" src lib -g '*.ts*' | head`. The shell already resolved
//! that directory, so the link redirects nothing, and the same search from
//! the resolved spelling was allowed. A link in the search target itself
//! still keeps the review.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

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

fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-rg-linked-cwd-spelling")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    write(home.join(".ssh/id_ed25519"), "synthetic key\n");
    let app = root.join("scratch/storefront");
    write(app.join("src/index.ts"), "export const batch = 1;\n");
    write(
        app.join("src/view.tsx"),
        "export const View = () => null;\n",
    );
    write(app.join("lib/format.ts"), "export const format = 1;\n");
    write(app.join("app/page.tsx"), "export default 1;\n");
    write(app.join("workers/queue.ts"), "export const queue = 1;\n");
    write(app.join(".gitignore"), "node_modules/\n");
    for arguments in [
        &["init", "-q"][..],
        &["add", "-A"][..],
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ][..],
    ] {
        let status = std::process::Command::new("git")
            .args(arguments)
            .current_dir(&app)
            .env("HOME", &home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
    // The spelling the harness reports: a link to the scratch directory.
    std::os::unix::fs::symlink(root.join("scratch"), root.join("tmp")).unwrap();
    Fixture { root, home }
}

fn action(fixture: &Fixture, cwd: &Path, command: &str) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        fixture.home.to_str(),
        cwd.to_str(),
    );
    (result.minimum_action, result.reason_code)
}

#[test]
fn a_search_from_a_linked_cwd_spelling_matches_the_resolved_one() {
    let fixture = fixture("allowed");
    for cwd in [
        fixture.root.join("scratch/storefront"),
        fixture.root.join("tmp/storefront"),
    ] {
        for command in [
            "rg -n \"ordinary_batch\" src -g '*.ts*'",
            "rg -n \"ordinary_batch\" src lib app workers -g '*.ts*' | head -20",
            "rg -n \"ordinary_batch\" src -g '*.ts' -g '*.tsx' | head -20",
        ] {
            assert_eq!(
                action(&fixture, &cwd, command),
                ("allow".to_owned(), "native_exact_safe_command".to_owned()),
                "{} {command}",
                cwd.display()
            );
        }
    }
}

#[test]
fn a_link_the_search_itself_names_keeps_the_review() {
    let fixture = fixture("reviewed");
    let app = fixture.root.join("scratch/storefront");
    // A link inside the target hands the search the home key store.
    std::os::unix::fs::symlink(fixture.home.join(".ssh"), app.join("keys")).unwrap();
    // A working directory that resolves to the key store.
    std::os::unix::fs::symlink(fixture.home.join(".ssh"), fixture.root.join("tmp/inbox")).unwrap();
    for (cwd, command) in [
        ("tmp/storefront", "rg -n \"ordinary_batch\" keys -g '*'"),
        (
            "tmp/storefront",
            "rg -n \"ordinary_batch\" src keys -g '*.ts*'",
        ),
        ("tmp/inbox", "rg -n \"ordinary_batch\" . -g '*'"),
        (
            "tmp/storefront",
            "rg -n \"ordinary_batch\" ../../home -g '*' | head",
        ),
    ] {
        let (action, reason) = action(&fixture, &fixture.root.join(cwd), command);
        assert_ne!(action, "allow", "{cwd} {command}: {reason}");
    }
}
