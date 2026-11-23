#![cfg(unix)]
//! Globs and `for` loops that walk a toolchain kept in a hidden folder of
//! home, as in `cat ~/.nvm/versions/node/v25.2.1/lib/node_modules/*/package.json`
//! or `for d in ~/.nvm/versions/node/v25.2.1/lib/node_modules/*; do ...; done`.
//!
//! Each package manifest there already reads without review when it is named
//! on its own, but the wildcard-directory walk refused any hidden folder in its
//! root and the loop unroller refused any pattern starting at the root, so the
//! same reads stopped once a glob or loop spelled them. Both now hand every
//! expanded word to the literal read proof, so a glob over a credential store
//! or a system folder keeps exactly the review its written-out reads get.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;

fn allowed(harness: &str, command: &str, home: &std::path::Path) -> bool {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    let cwd = home.join("work/repo");
    let answer = evaluate_pre_tool_envelope_with_execution_context(
        harness,
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
    );
    answer.minimum_action == "allow"
}

#[test]
fn globs_and_loops_over_a_hidden_toolchain_read_like_their_written_out_reads() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/hidden-root-globs")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    let modules = ".nvm/versions/node/v25.2.1/lib/node_modules";
    for directory in [
        "work/repo",
        &format!("{modules}/widget-lint"),
        &format!("{modules}/npm"),
        ".aws/profiles/default",
        ".config/tool/.private/one",
    ] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let root = std::fs::canonicalize(root).unwrap();
    for package in ["widget-lint", "npm"] {
        std::fs::write(
            root.join(format!("{modules}/{package}/package.json")),
            "{\"name\":\"x\",\"version\":\"1.0.0\"}\n",
        )
        .unwrap();
    }
    std::fs::write(root.join(".aws/profiles/default/credentials"), "[default]\n").unwrap();
    std::fs::write(root.join(".config/tool/.private/one/state.json"), "{}\n").unwrap();
    let modules = root.join(modules);
    let modules = modules.to_str().unwrap();
    for harness in ["claude-code", "codex", "omp"] {
        for (command, expected) in [
            (format!("cat {modules}/*/package.json"), true),
            ("cat ~/.nvm/versions/node/v25.2.1/lib/node_modules/*/package.json".to_owned(), true),
            (format!("for d in {modules}/*; do printf '%s\\n' \"$d\"; done"), true),
            (
                format!(
                    "for package_dir in {modules}/*; do if [ -f \"$package_dir/package.json\" ]; then printf '\\n%s\\n' \"$package_dir\"; sed -n '1,80p' \"$package_dir/package.json\"; fi; done"
                ),
                true,
            ),
            (
                "for d in ~/.nvm/versions/node/v25.2.1/lib/node_modules/*; do cat \"$d/package.json\"; done".to_owned(),
                true,
            ),
            // Every expanded word is still a read of its own.
            ("cat ~/.aws/*/default/credentials".to_owned(), false),
            ("cat ~/.config/tool/.private/*/state.json".to_owned(), false),
            ("for f in ~/.aws/profiles/*; do cat \"$f/credentials\"; done".to_owned(), false),
            ("for f in /etc/*.conf; do cat \"$f\"; done".to_owned(), false),
            (format!("for d in {modules}/*; do rm -rf \"$d\"; done"), false),
            (format!("for d in {modules}/../*; do cat \"$d\"; done"), false),
        ] {
            assert_eq!(allowed(harness, &command, &root), expected, "{harness}: {command}");
        }
    }
}
