#![cfg(unix)]
//! A `for` loop in a command that also holds a shell comment, as in a note
//! line between two checks:
//!
//! ```sh
//! for n in 7001 7002; do gh pr view "$n" --json number | jq -c '{n:.number}'; done
//! # also look for open intake branches
//! gh pr list --json number,headRefName
//! ```
//!
//! The parser reads every step without its comments, but the recognizers
//! that write a loop out read the raw text, saw `#` as a command and gave
//! up, so the whole command kept a review that its steps did not.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;

fn action(command: &str, home: &std::path::Path) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    let cwd = home.join("work/repo");
    evaluate_pre_tool_envelope_with_execution_context(
        "cursor",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        Some(&environment),
    )
    .minimum_action
}

fn fixture() -> std::path::PathBuf {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/loop-comment-lines")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work/repo", ".ssh"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    std::fs::write(root.join(".ssh/id_ed25519"), "key\n").unwrap();
    std::fs::canonicalize(root).unwrap()
}

#[test]
fn a_comment_beside_a_loop_does_not_keep_the_loop_from_being_written_out() {
    let home = fixture();
    for command in [
        "# Live heads for the waiting PRs\nfor n in 7001 7002 7003; do\n  gh pr view \"$n\" --repo example/project --json number,headRefOid | jq -c '{n:.number, head:.headRefOid[0:12]}'\ndone\n# also look for intake branches\ngh pr list --repo example/project --state open --json number,headRefName | jq '[.[] | select(.headRefName | test(\"^(intake/pr-|regen/artifacts-)\"))]'",
        "for n in 1 2; do echo \"$n\"; done\n# then the list\ngh pr list --repo example/project",
        "# list two\nfor n in 1 2; do echo $n; done\necho done",
        "for n in 1 2; do echo $n; done # note\necho done",
        "for n in 1 2; do echo $n; done\n# trailing note",
    ] {
        assert_eq!(action(command, &home), "allow", "{command}");
    }
}

#[test]
fn the_steps_around_a_comment_are_still_judged() {
    let home = fixture();
    for command in [
        "# list two\nfor n in 1 2; do echo $n; done\nrm -rf ~/.ssh",
        "for n in 1 2; do rm -rf ~/.ssh; done\n# note",
        "for n in 1 2; do echo $n; done # note\ncat ~/.ssh/id_ed25519",
        // A `#` inside quotes is data, not a comment, so the step after it is
        // still there to judge.
        "for n in 1 2; do echo $n; done\necho '\n# note\n'; rm -rf ~/.ssh",
    ] {
        assert_ne!(action(command, &home), "allow", "{command}");
    }
}
