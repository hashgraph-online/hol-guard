#![cfg(unix)]
//! A quoted `grep` pattern that holds a backslash, as in a basic-regex
//! alternation: `grep -n "staging.hol\|https://.*staging" deploy.sh`.
//!
//! A pattern whose glob characters are all quoted reaches `grep` as written,
//! so it is a search pattern and never a file name. The quote reader gave up
//! on any backslash, so every quoted pattern with `\|` lost that proof and was
//! screened as a glob: `/.*s` could expand to `/.aws`, and the step went to the
//! sandbox. A file operand, an unquoted glob and a substitution keep their
//! screens.

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
        .join("../../target/grep-quoted-backslash-patterns")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work/repo", ".ssh"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    std::fs::write(root.join("work/repo/deploy.sh"), "echo deploy\n").unwrap();
    std::fs::write(root.join("work/repo/.env.local"), "TOKEN=x\n").unwrap();
    std::fs::write(root.join(".ssh/id_ed25519"), "key\n").unwrap();
    std::fs::canonicalize(root).unwrap()
}

#[test]
fn a_quoted_alternation_with_a_backslash_is_a_pattern() {
    let home = fixture();
    for command in [
        r#"grep -n "staging.hol\|STAGING_URL\|staging origin\|https://.*staging" deploy.sh | head -8"#,
        r#"grep -n "x\|/.*s" deploy.sh"#,
        r#"grep -n 'error\|/.*env' deploy.sh"#,
        r#"cat deploy.sh | grep -n "TODO\|/.*config""#,
    ] {
        assert_eq!(action(command, &home), "allow", "{command}");
    }
}

#[test]
fn a_secret_operand_or_unquoted_glob_beside_the_pattern_is_still_screened() {
    let home = fixture();
    for command in [
        r#"grep -n "x\|y" ~/.ssh/id_ed25519"#,
        r#"grep -n "x\|y" .env*"#,
        r#"grep -n "x\|.en*" .en*"#,
        r#"grep -n "x\|$(cat ~/.ssh/id_ed25519)" deploy.sh"#,
    ] {
        assert_ne!(action(command, &home), "allow", "{command}");
    }
}
