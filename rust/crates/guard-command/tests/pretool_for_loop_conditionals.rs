#![cfg(unix)]
//! A `for` loop whose body holds an `if … fi` statement is decided like the
//! conditionals it writes out, one per word.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding one project. The root stays below the target directory:
/// `$TMPDIR` on macOS resolves under `/private/var`, which the sensitive-root
/// screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-for-loop-conditionals")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("README.md"), "# Fixture\n").unwrap();
    std::fs::write(project.join("src/a.md"), "a\n").unwrap();
    std::fs::canonicalize(home).unwrap()
}

fn action(home: &Path, command: &str) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    let cwd = home.join("project");
    let result = evaluate_pre_tool_envelope_with_execution_context(
        "claude-code",
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
    format!("{} {}", result.minimum_action, result.reason_code)
}

#[test]
fn a_loop_of_read_only_conditionals_proceeds() {
    let home = home();
    for command in [
        "for p in /opt/homebrew/bin/python3 /usr/bin/python3; do if [ -x \"$p\" ]; then echo \"$p\"; fi; done",
        "for f in README.md src; do if [ -d \"$f\" ]; then echo \"dir $f\"; else echo \"file $f\"; fi; done",
        "for f in README.md src/a.md; do if [ -f \"$f\" ]; then wc -l \"$f\"; elif [ -d \"$f\" ]; then ls \"$f\"; fi; done",
        "for f in README.md src\ndo\n  if [ -e \"$f\" ]\n  then\n    echo \"$f\"\n  fi\ndone",
        "for f in README.md src/a.md; do echo \"== $f\"; if test -f \"$f\"; then head -3 \"$f\"; fi; done 2>/dev/null",
    ] {
        assert_eq!(
            action(&home, command),
            "allow native_exact_safe_command",
            "{command}"
        );
    }
}

#[test]
fn a_conditional_that_writes_or_nests_keeps_its_review() {
    let home = home();
    for command in [
        "for f in a b; do if [ -f \"$f\" ]; then rm \"$f\"; fi; done",
        "for f in a b; do if [ -f \"$f\" ]; then echo x > \"$f\"; fi; done",
        "for f in a b; do if [ -f \"$f\" ]; then if [ -r \"$f\" ]; then cat \"$f\"; fi; fi; done",
        "for f in a b; do if f=x; then echo \"$f\"; fi; done",
        "for f in a b; do if [ -f \"$f\" ]; then echo \"$f\"; fi > out; done",
        "for f in a b; do if [ -f \"$f\" ]; then echo \"$f\"; done",
    ] {
        assert!(
            !action(&home, command).starts_with("allow"),
            "{command} was allowed"
        );
    }
}
