#![cfg(unix)]

//! `ls <checkout>/app/(group)/topics/secret-rotation-demo`: a listing of a
//! committed feature directory whose name carries a credential word.
//!
//! `ls` prints names and never reads a file. A directory of the session's
//! repository, or of one of its linked worktrees, whose every entry that
//! repository tracks shows only names already committed, and a path there
//! that does not exist shows nothing. A listing that could show an untracked
//! name, a credential store, or a checkout outside the session's repository
//! keeps the review its name earns.

use crate::git_helper_fixture::evaluate_pre_tool_envelope_with_context;
use crate::pretool_git_session_ops::{default_controls, git, session, Session};
use serde_json::json;
use std::path::Path;

const PAGE: &str = "export default function Page() { return null; }\n";

fn commit(s: &Session, checkout: &Path, files: &[&str]) {
    for file in files {
        let path = checkout.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, PAGE).unwrap();
    }
    let mut add = vec!["add", "--"];
    add.extend_from_slice(files);
    git(&s.home, checkout, &add);
    git(&s.home, checkout, &["commit", "--quiet", "-m", "pages"]);
}

fn action(s: &Session, cwd: &Path, command: &str) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&default_controls()),
        None,
        s.home.to_str(),
        cwd.to_str(),
    );
    (result.minimum_action, result.reason_code)
}

fn feature_session(label: &str) -> Session {
    let s = session(label);
    commit(
        &s,
        &s.worktree,
        &[
            "app/(group)/topics/input-handling/page.tsx",
            "app/(group)/topics/secret-rotation-demo/page.tsx",
            "app/(group)/topics/secret-rotation-demo/view/card.tsx",
        ],
    );
    s
}

#[test]
fn listing_committed_secret_named_feature_directories_is_allowed() {
    let s = feature_session("ls-feature");
    let w = s.worktree.display().to_string();
    // From the primary checkout into its linked worktree, with one guide
    // path that does not exist yet.
    let across = format!(
        "ls \"{w}/app/(group)/topics/input-handling\" \
         \"{w}/app/(group)/topics/secret-rotation-demo\" \
         \"{w}/app/(group)/guides/keeping-secrets-guide\""
    );
    let mut held = Vec::new();
    let (verdict, reason) = action(&s, &s.primary, &across);
    if verdict != "allow" {
        held.push(format!("{reason}: {across}"));
    }
    // From inside the worktree, relative and with flags.
    for command in [
        "ls 'app/(group)/topics/secret-rotation-demo'",
        "ls -la 'app/(group)/topics/secret-rotation-demo'",
        "ls 'app/(group)/topics/secret-rotation-demo/view'",
    ] {
        let (verdict, reason) = action(&s, &s.worktree, command);
        if verdict != "allow" {
            held.push(format!("{reason}: {command}"));
        }
    }
    assert!(held.is_empty(), "{held:#?}");
}

#[test]
fn listing_that_could_show_more_than_committed_names_keeps_its_review() {
    let s = feature_session("ls-feature-floor");
    let w = s.worktree.display().to_string();
    // An untracked file beside the committed page could be anything.
    std::fs::write(
        s.worktree
            .join("app/(group)/topics/secret-rotation-demo/notes.txt"),
        "draft\n",
    )
    .unwrap();
    // A directory named as a store keeps its review even when committed.
    commit(&s, &s.worktree, &["config/secrets/readme.md"]);
    // A checkout of another repository is not the session's.
    let other = s.home.join("other");
    std::fs::create_dir_all(&other).unwrap();
    git(&s.home, &other, &["init", "--quiet", "-b", "main"]);
    git(&s.home, &other, &["config", "user.name", "Guard Fixture"]);
    git(
        &s.home,
        &other,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    commit(&s, &other, &["secret-rotation-demo/page.tsx"]);
    let o = other.display().to_string();
    for command in [
        format!("ls \"{w}/app/(group)/topics/secret-rotation-demo\""),
        format!("ls \"{w}/config/secrets\""),
        format!("ls -R \"{w}/app/(group)/topics/input-handling\" \"{w}/app/(group)/topics/secret-rotation-demo/view\""),
        format!("ls \"{o}/secret-rotation-demo\""),
        format!("cat \"{w}/app/(group)/topics/secret-rotation-demo/view/card.tsx\" \"{w}/app/(group)/topics/secret-rotation-demo/notes.txt\""),
    ] {
        let (verdict, reason) = action(&s, &s.primary, &command);
        assert_ne!(verdict, "allow", "{reason}: {command}");
    }
    // The shell expands these before `ls` runs, so the literal spelling
    // missing from the checkout says nothing about what is listed; a hidden
    // name keeps its review even where it does not exist; and a folder the
    // repository commits nothing in is not one of its own.
    std::fs::create_dir_all(s.worktree.join("scratch")).unwrap();
    for command in [
        "ls ~/.ssh".to_string(),
        "ls \"$HOME/.ssh\"".to_string(),
        "ls app/{secrets,keys}".to_string(),
        "ls 'app/(group)/topics/secret-*'".to_string(),
        format!("ls \"{w}/app/(group)/topics/.secret-cache\""),
        format!("ls \"{w}/scratch/secret-notes\""),
    ] {
        let (verdict, reason) = action(&s, &s.worktree, &command);
        assert_ne!(verdict, "allow", "{reason}: {command}");
    }
}
