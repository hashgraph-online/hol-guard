#![cfg(unix)]
//! A `jq` filter that holds a credential word, as in a run list filtered by
//! title: `jq '[.[] | select(.displayTitle | test("secret-blast"))]'`.
//!
//! The filter is a pure function of the value jq reads, so the word names a
//! string or a key in that value and nothing on this machine. The whole-step
//! credential screen still read it and sent the command to review. Input
//! files, redirects and filters outside the grammar keep the screen.

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
        .join("../../target/jq-filter-credential-words")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work/repo", ".ssh", ".secrets"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    std::fs::write(root.join("work/repo/settings.json"), "{}\n").unwrap();
    std::fs::write(root.join(".ssh/id_ed25519"), "key\n").unwrap();
    std::fs::write(root.join(".secrets/token.json"), "{}\n").unwrap();
    std::fs::canonicalize(root).unwrap()
}

#[test]
fn a_credential_word_inside_a_proven_filter_is_not_a_local_read() {
    let home = fixture();
    for command in [
        "gh run list --repo example/project --status action_required --limit 100 --json databaseId,headSha,displayTitle,number | jq '[.[] | select(.displayTitle | test(\"webcrawl|secret-blast|errd\"; \"i\"))] | unique_by(.displayTitle)'",
        "gh pr list --repo example/project --json title | jq -r '.[] | select(.title | test(\"password reset\")) | .title'",
        "jq -r '.secret_scanning.status' settings.json",
    ] {
        assert_eq!(action(command, &home), "allow", "{command}");
    }
}

#[test]
fn files_redirects_and_unproven_filters_keep_the_screen() {
    let home = fixture();
    for command in [
        "jq '.secret' ~/.ssh/id_ed25519",
        "jq '.secret' < ~/.ssh/id_ed25519",
        "cat ~/.secrets/token.json | jq '.secret'",
        "jq '.a' ~/.secrets/token.json",
        "jq -n 'env.AWS_SECRET_ACCESS_KEY'",
        "jq -n '$ENV.GITHUB_TOKEN'",
        "gh run list --json displayTitle | jq '[.[] | select(.displayTitle | test(\"secret\"))]' > ~/.ssh/authorized_keys",
    ] {
        assert_ne!(action(command, &home), "allow", "{command}");
    }
}
