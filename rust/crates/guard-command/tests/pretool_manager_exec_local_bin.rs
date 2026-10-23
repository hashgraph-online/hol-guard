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

/// `npm exec`, `npm x` and `yarn exec` run the workspace's own installed
/// binary, the work `npx` names. They reach the same read-only sink `npx` and
/// `pnpm exec` already reach, rather than the review `npx` never had.
#[test]
fn a_manager_exec_spelling_reaches_the_read_only_tool_sink() {
    for harness in ["omp", "zcode", "claude-code"] {
        for command in [
            "npm exec tsc --noEmit",
            "npm exec -- tsc --noEmit",
            "npm x tsc --noEmit",
            "npm exec eslint src",
            "npm x eslint src",
            "yarn exec eslint src",
            "yarn exec prettier --check src",
            "pnpm exec tsc --noEmit",
        ] {
            let result = classify(harness, command);
            assert_eq!(result.decision, "deny", "{harness} {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.reason_code, "native_node_tool_readonly_containment_required",
                    "{harness} {command}"
                );
            }
        }
    }
}

/// Vitest through the same spellings, which has its own sink.
#[test]
fn a_manager_exec_spelling_reaches_the_vitest_sink() {
    for command in [
        "npm exec vitest run",
        "npm exec -- vitest run",
        "npm x vitest run",
        "yarn exec vitest run",
    ] {
        let result = classify("omp", command);
        assert_eq!(result.decision, "deny", "{command}");
        if cfg!(target_os = "macos") {
            assert_eq!(
                result.reason_code, "native_vitest_readonly_containment_required",
                "{command}"
            );
        }
    }
}

/// What the spelling does not admit: a write, a tool the sink does not run,
/// `bun exec`, which runs a shell string rather than a binary, and a manager
/// option before the subcommand, which fans the run out past one package.
#[test]
fn a_manager_option_or_a_write_keeps_the_review() {
    for command in [
        "npm exec tsc",
        "npm exec eslint --fix src",
        "npm x prettier --write src",
        "yarn exec prettier src",
        "npm exec other",
        "npm --workspace web exec tsc --noEmit",
        "npm exec -w web tsc --noEmit",
        "yarn --cwd /elsewhere exec eslint src",
        "bun exec tsc --noEmit",
        "npm exec tsc --noEmit && rm -rf /",
        "npm exec vitest watch",
        "npm exec --no-install vitest run",
        "npm exec --",
    ] {
        let result = classify("omp", command);
        assert_ne!(
            result.reason_code, "native_node_tool_readonly_containment_required",
            "{command}"
        );
        assert_ne!(
            result.reason_code, "native_vitest_readonly_containment_required",
            "{command}"
        );
    }
}
