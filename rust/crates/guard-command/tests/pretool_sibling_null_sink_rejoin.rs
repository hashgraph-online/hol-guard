//! A sibling checkout's list that sends a run's output to the null device.
//!
//! The parse drops every inert null-sink spelling from a segment's words, but
//! `sink_peel` writes back only the contiguous `2>/dev/null`. A list holding
//! any other spelling must therefore be refused here rather than admitted
//! into a containment the sink then declines to rejoin.
#![cfg(unix)]

use crate::pretool_contained_wrappers::{classify, fixture, package};

/// A spelling the peel resolves itself still reaches containment when a
/// filter stage bounds it; every other spelling the parse drops keeps its
/// review, because the sink cannot write it back into the list it runs.
#[test]
fn only_the_sink_the_peel_writes_back_rejoins_a_sibling_list() {
    let root = fixture();
    let sibling = root.join("sibling-worktree");
    std::fs::create_dir_all(sibling.join("dashboard")).unwrap();
    // A linked worktree marks its root with a `.git` file.
    std::fs::write(sibling.join(".git"), "gitdir: /nonexistent\n").unwrap();
    package(&sibling);
    let sibling = sibling.to_str().unwrap();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            format!("cd {sibling} && git status >/dev/null && git log --oneline -5 && ls"),
            format!("cd {sibling} && git status > /dev/null && git log --oneline -5 && ls"),
            format!("cd {sibling} && git status 1>/dev/null && git log --oneline -5 && ls"),
            format!("cd {sibling} && git status &>/dev/null && git log --oneline -5 && ls"),
            format!("cd {sibling} && git status >>/dev/null && git log --oneline -5 && ls"),
            // A `2>` with a blank before its target is dropped by the parse
            // too, and the peel's own lexer reads it as two tokens.
            format!("cd {sibling} && git status 2> /dev/null && git log --oneline -5 && ls"),
        ] {
            let result = classify(&root, harness, &command);
            assert_ne!(
                result.minimum_action, "sandbox-required",
                "{harness}: {command}"
            );
        }
    }
}
