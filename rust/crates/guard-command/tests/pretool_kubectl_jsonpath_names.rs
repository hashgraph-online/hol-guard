//! A `kubectl` inventory read whose `jsonpath` loop renders names alone.
//!
//! `…containers[*].env[*]` is the container's environment list, not a dotenv
//! file, so the read is ordinary work. A template that renders a value beside
//! the name prints the environment itself and still asks.

#![cfg(unix)]

use serde_json::json;

fn decide(harness: &str, command: &str) -> (String, String) {
    let result = guard_command::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        None,
        None,
    );
    (result.minimum_action, result.reason_code)
}

const HARNESSES: [&str; 4] = ["omp", "zcode", "claude-code", "codex"];

#[test]
fn a_loop_over_environment_names_reads_an_inventory() {
    for command in [
        concat!(
            "kubectl -n alpha-namespace get deployment alpha-frontend -o ",
            r#"'jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}{"\n"}{end}'"#
        ),
        concat!(
            "kubectl get deployment alpha-frontend -o ",
            r#"'jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}{"\n"}{end}'"#
        ),
        r#"kubectl get pods -o 'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}'"#,
    ] {
        for harness in HARNESSES {
            let (action, reason) = decide(harness, command);
            assert_eq!(action, "allow", "{harness}: {reason}: {command}");
        }
    }
}

#[test]
fn a_loop_that_renders_the_environment_values_still_asks() {
    for command in [
        concat!(
            "kubectl -n alpha-namespace get deployment alpha-frontend -o ",
            r#"'jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}{"="}{.value}{"\n"}{end}'"#
        ),
        concat!(
            "kubectl -n alpha-namespace get deployment alpha-frontend -o ",
            r#"'jsonpath={range .spec.template.spec.containers[*].env[*]}{.value}{"\n"}{end}'"#
        ),
    ] {
        for harness in HARNESSES {
            let (action, reason) = decide(harness, command);
            assert_ne!(action, "allow", "{harness}: {reason}: {command}");
        }
    }
}
