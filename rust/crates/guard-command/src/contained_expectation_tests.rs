use serde_json::{json, Value};

use super::expectation;

fn ask(kind: &str, plan_profile: Value, command: &[&str]) -> (String, String) {
    let answer = expectation(&json!({
        "kind": kind,
        "plan_profile": plan_profile,
        "command": command,
    }))
    .expect("expectation");
    let text = |key: &str| answer[key].as_str().expect(key).to_owned();
    (text("reason"), text("profile"))
}

fn refused(input: Value) -> bool {
    expectation(&input).is_err_and(|error| error.reason_code == "contained_expectation_invalid")
}

#[test]
fn every_planner_names_its_reason_and_the_hook_profile() {
    let cases: [(&str, Value, &[&str], &str, &str); 9] = [
        (
            "inline_eval",
            json!("node-eval-readonly-v1"),
            &["node", "-e", "1"],
            "native_node_eval_readonly_containment_required",
            "node-eval-readonly-v1",
        ),
        (
            "inline_eval",
            json!("node-eval-readonly-v1"),
            &["/opt/bin/bun", "-e", "1"],
            "native_bun_eval_readonly_containment_required",
            "node-eval-readonly-v1",
        ),
        (
            "inline_eval",
            json!("python-eval-readonly-v1"),
            &["python3", "-c", "1"],
            "native_python_eval_readonly_containment_required",
            "python-eval-readonly-v1",
        ),
        (
            "node_tool",
            json!("node-build-output-v1"),
            &["vite", "build"],
            "native_node_build_output_containment_required",
            "node-build-output-v1",
        ),
        (
            "node_tool",
            json!("node-tool-readonly-v1"),
            &["tsc", "--noEmit"],
            "native_node_tool_readonly_containment_required",
            "node-tool-readonly-v1",
        ),
        (
            "git",
            Value::Null,
            &["git", "diff"],
            "native_git_readonly_containment_required",
            "git-readonly-v1",
        ),
        (
            "vitest",
            Value::Null,
            &["vitest", "run"],
            "native_vitest_readonly_containment_required",
            "vitest-readonly-v1",
        ),
        (
            "node_test",
            Value::Null,
            &["node", "--test"],
            "native_node_test_readonly_containment_required",
            "node-test-readonly-v1",
        ),
        (
            "pytest",
            Value::Null,
            &["pytest", "-q"],
            "native_pytest_readonly_containment_required",
            "pytest-readonly-v2",
        ),
    ];
    for (kind, plan_profile, command, reason, profile) in cases {
        assert_eq!(
            ask(kind, plan_profile, command),
            (reason.to_owned(), profile.to_owned()),
            "{kind} {command:?}"
        );
    }
}

#[test]
fn the_transport_search_path_is_accepted_and_ignored() {
    let answer = expectation(&json!({
        "kind": "git",
        "plan_profile": null,
        "command": ["git", "diff"],
        "search_path": "/usr/bin",
    }))
    .expect("expectation");
    assert_eq!(
        answer["reason"],
        json!("native_git_readonly_containment_required")
    );
}

#[test]
fn a_profile_the_planner_did_not_choose_is_refused() {
    assert!(refused(json!({
        "kind": "inline_eval",
        "plan_profile": "node-tool-readonly-v1",
        "command": ["node", "-e", "1"],
    })));
    assert!(refused(json!({
        "kind": "node_tool",
        "plan_profile": null,
        "command": ["tsc"],
    })));
    assert!(refused(json!({
        "kind": "git",
        "plan_profile": "git-readonly-v1",
        "command": ["git", "diff"],
    })));
    assert!(refused(json!({
        "kind": "package_test",
        "plan_profile": null,
        "command": ["npm", "test"],
    })));
}

#[test]
fn a_malformed_request_is_refused() {
    assert!(refused(json!([])));
    assert!(refused(
        json!({"kind": "git", "command": ["git"], "extra": 1})
    ));
    assert!(refused(json!({"plan_profile": null, "command": ["git"]})));
    assert!(refused(
        json!({"kind": "git", "plan_profile": 1, "command": ["git"]})
    ));
    assert!(refused(json!({"kind": "git", "plan_profile": null})));
    assert!(refused(
        json!({"kind": "git", "plan_profile": null, "command": [1]})
    ));
}

#[test]
fn the_operation_answers_through_the_contained_argv_evaluator() {
    let answer = crate::contained_argv::evaluate(
        "contained_expectation",
        &json!({"kind": "pytest", "plan_profile": null, "command": ["pytest"]}),
    )
    .expect("handled");
    assert_eq!(
        answer["value"],
        json!({
            "reason": "native_pytest_readonly_containment_required",
            "profile": "pytest-readonly-v2",
        })
    );
    let refused =
        crate::contained_argv::evaluate("contained_expectation", &json!({})).expect("handled");
    assert_eq!(
        refused["reason_code"],
        json!("contained_expectation_invalid")
    );
}
