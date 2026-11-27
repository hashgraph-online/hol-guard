#![cfg(unix)]
//! Agents check whether a scratch path exists, then step into a sibling
//! checkout to read its history:
//! `ls -d /tmp/build 2>&1 | head; cd ../app && git log --oneline -1`. The
//! `cd` creates no file and no link, and the missing path is absolute, so the
//! hop cannot change which file the listing names.
use crate::git_helper_fixture as fixture;
use crate::pretool_git_session_ops::default_controls;
use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::path::Path;

fn evaluate(home: &Path, cwd: &Path, command: &str) -> (String, String) {
    let controls = default_controls();
    let decision = evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    );
    (decision.minimum_action, decision.reason_code)
}

fn repository(home: &Path, path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    fixture::git(home, path, &["init", "--quiet"]);
    fixture::git(
        home,
        path,
        &["config", "user.email", "fixture@example.test"],
    );
    fixture::git(home, path, &["config", "user.name", "fixture"]);
    std::fs::write(path.join("README.md"), "# fixture\n").unwrap();
    fixture::git(home, path, &["add", "-A"]);
    fixture::git(home, path, &["commit", "--quiet", "-m", "fixture"]);
}

#[test]
fn a_directory_hop_keeps_an_absent_temporary_listing_proven() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-absent-temporary-read-cd-hop")
        .join(std::process::id().to_string());
    let _ = std::fs::remove_dir_all(&root);
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let home = home.canonicalize().unwrap();
    let session = home.join("work").join("session");
    let sibling = home.join("work").join("app");
    repository(&home, &session);
    repository(&home, &sibling);
    std::fs::write(home.join("notes.md"), "notes\n").unwrap();
    let absent = format!("/tmp/hg-cd-hop-absent-{}", std::process::id());
    let other = format!("/tmp/hg-cd-hop-other-{}", std::process::id());
    assert!(std::fs::symlink_metadata(&absent).is_err());

    for command in [
        format!("ls -d {absent} {other} 2>&1 | head; cd ../app && git log --oneline -1"),
        format!(
            "ls -d {absent} 2>&1 | head; cd {} && git log --oneline -1",
            sibling.display()
        ),
        format!("cat {absent} 2>/dev/null; cd ../app && ls"),
        format!("ls -d {absent}; cd ../app; git diff --stat"),
    ] {
        let (action, reason) = evaluate(&home, &session, &command);
        assert_eq!(
            (action.as_str(), reason.as_str()),
            ("allow", "native_exact_safe_command"),
            "{command}"
        );
    }

    for command in [
        // A working-tree Git command is no object reader, with or without a hop.
        format!("ls -d {absent}; cd ../app && git status --short"),
        // A link or a rename could put another file at the absent name before
        // the read opens it.
        format!(
            "cd /tmp && ln -s {} {absent}; cat {absent}",
            home.join("notes.md").display()
        ),
        format!("cd ../app && mv README.md {absent}; cat {absent}"),
        // A hop with an option is not a plain hop.
        format!("ls -d {absent}; cd -P ../app && git log --oneline -1"),
    ] {
        let (action, _) = evaluate(&home, &session, &command);
        assert_ne!(action, "allow", "{command}");
    }
}
