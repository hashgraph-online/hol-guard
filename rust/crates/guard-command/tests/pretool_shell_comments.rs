//! A comment in a shell command is not a step.
//!
//! Agents label the steps of a script with comments, `# list open PRs`
//! above `gh pr list`. Each note was read as a step running a program named
//! `#`, and a `;` in a note split off another step, so the whole script went
//! to review although every real step was proven read-only. A word-start `#`
//! now ends the line's shell text, the way `bash`, `zsh` and `sh` read it,
//! while a `#` inside a word, a quote, arithmetic or a nested command still
//! counts as text.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-shell-comments-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("data.json"), "{\"a\": 1}\n").unwrap();
    fixture::git(&root, &project, &["init", "--quiet", "-b", "main"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

fn action(root: &Path, command: &str) -> String {
    fixture::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(&fixture::local_admin_controls(Vec::new())),
        None,
        root.to_str(),
        root.join("project").to_str(),
    )
    .minimum_action
}

#[test]
fn comments_beside_read_only_steps_are_allowed() {
    let (root, _cleanup) = checkout("allowed");
    for command in [
        "# list the files\nls",
        "ls # list; then count",
        "ls;# note\npwd",
        "ls\n  # then the directory\npwd",
        "# status, threads; list intake\ngit status --short 2>&1 | head -80\necho done",
        "git log --oneline -3 # recent; newest first",
    ] {
        assert_eq!(action(&root, command), "allow", "{command:?}");
    }
}

#[test]
fn a_hash_that_opens_no_comment_keeps_the_step_after_it() {
    let (root, _cleanup) = checkout("kept");
    for command in [
        "ls # note\nrm -f data.json",
        "ls a\\\n#x; rm -f data.json",
        "ls \\\n# x\nrm -f data.json",
        "ls 'x'#y; rm -f data.json",
        "ls a#b; rm -f data.json",
        "echo $'a\\'b # x'; rm -f data.json",
        "echo \"a # b\"; rm -f data.json",
        "(( 1 # 2 )); rm -f data.json",
        "ls \u{a0}#; rm -f data.json",
        "echo ok\r#; rm -f data.json",
        "echo #x '\nrm -f data.json\n#x '",
    ] {
        assert_ne!(action(&root, command), "allow", "{command:?}");
    }
}
