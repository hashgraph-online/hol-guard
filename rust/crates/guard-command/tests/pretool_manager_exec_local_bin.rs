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
        "npm --workspace web exec tsc --noEmit",
        "npm -w web exec tsc --noEmit",
        "npm --registry https://registry.example exec tsc",
        "npm --loglevel exec tsc",
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

/// A pnpm or yarn option that only chooses how much the manager prints names
/// no package, so the `exec` behind it is still the local-bin run and reaches
/// the same sink the bare spelling does.
#[test]
fn a_reporting_option_before_exec_keeps_the_local_bin_run() {
    for command in [
        "pnpm --silent exec tsc --noEmit",
        "pnpm -s exec tsc --noEmit",
        "pnpm --no-color exec tsc --noEmit",
        "pnpm --color exec eslint src",
        "pnpm --reporter silent exec tsc --noEmit",
        "pnpm --reporter=silent exec tsc --noEmit",
        "pnpm --loglevel error exec tsc --noEmit",
        "pnpm --loglevel=error exec tsc --noEmit",
        "pnpm --use-stderr exec tsc --noEmit",
        "pnpm --silent --no-color exec tsc --noEmit",
        "pnpm --silent exec -- tsc --noEmit",
        "npm --silent exec tsc --noEmit",
        "npm -s exec tsc --noEmit",
        "npm --quiet exec tsc --noEmit",
        "npm --no-color exec tsc --noEmit",
        "npm --loglevel error exec tsc --noEmit",
        "npm --loglevel=error exec eslint src",
        "npm --silent x tsc --noEmit",
        "npm --silent exec -- tsc --noEmit",
        "yarn --silent exec eslint src",
        "yarn -s exec eslint src",
        "yarn --no-progress exec eslint src",
        "yarn --non-interactive --no-color exec eslint src",
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
}

/// What the peel does not reach: the pnpm options that choose which packages
/// the run covers, the ones that move the directory or the registry, a value
/// option whose value is missing so the peel eats the verb, and yarn's
/// `--cwd`, which the reporting list leaves out.
#[test]
fn a_package_choosing_option_before_exec_keeps_the_review() {
    for command in [
        "pnpm -r exec tsc --noEmit",
        "pnpm --recursive exec tsc --noEmit",
        "pnpm --filter web exec tsc --noEmit",
        "pnpm -F web exec tsc --noEmit",
        "pnpm --filter-prod web exec tsc --noEmit",
        "pnpm --parallel exec tsc --noEmit",
        "pnpm --workspace-concurrency 2 exec tsc --noEmit",
        "pnpm --silent -r exec tsc --noEmit",
        "pnpm -r --silent exec tsc --noEmit",
        "pnpm --dir /elsewhere exec tsc --noEmit",
        "pnpm --registry https://registry.example exec tsc --noEmit",
        "pnpm --ignore-scripts exec tsc --noEmit",
        "pnpm --reporter exec tsc --noEmit",
        "pnpm --loglevel exec tsc --noEmit",
        "yarn --cwd /elsewhere exec eslint src",
        "yarn --silent --cwd /elsewhere exec eslint src",
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
