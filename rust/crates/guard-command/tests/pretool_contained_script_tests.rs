//! Test-named JavaScript and TypeScript scripts run under the same contained
//! profiles as inline evaluation and Vitest, never as unrestricted execution.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn classify(command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        None,
        None,
        Some("/home/tester"),
        Some("/home/tester/project"),
    )
}

fn assert_contained(commands: &[&str], reason: &str) {
    for command in commands {
        let result = classify(command);
        assert_eq!(result.decision, "deny", "{command}");
        if cfg!(target_os = "macos") {
            assert_eq!(result.minimum_action, "sandbox-required", "{command}");
            assert_eq!(result.reason_code, reason, "{command}");
        }
    }
}

#[test]
fn test_named_node_scripts_share_the_inline_eval_boundary() {
    let reason = "native_node_eval_readonly_containment_required";
    assert_contained(
        &[
            "node math.test.mjs",
            "node --experimental-strip-types src/math.test.ts",
            "node --no-warnings --experimental-strip-types tests/api.spec.ts --verbose",
            "node --disable-warning=ExperimentalWarning test_calc.js",
            "node --max-old-space-size=4096 src/parser_test.cjs",
            "nodejs tests.js",
        ],
        reason,
    );
    for command in [
        "node build.ts",
        "node scripts/deploy.mjs",
        "node math.test.py",
        "node ../math.test.ts",
        "node /tmp/math.test.ts",
        "node ~/math.test.ts",
        "node --import ./evil.mjs math.test.ts",
        "node --require ./evil.cjs math.test.ts",
        "node --experimental-strip-types",
        "node 'math test.test.ts'",
        "node math.test.ts > out.txt",
        "node math.test.ts && rm -rf /",
        "NODE_OPTIONS=--require=/tmp/x.cjs node math.test.ts",
        "sudo node math.test.ts",
    ] {
        assert_ne!(classify(command).reason_code, reason, "{command}");
        assert_ne!(classify(command).decision, "allow", "{command}");
    }
}

#[test]
fn tsx_test_scripts_require_the_vitest_transform_boundary() {
    let reason = "native_vitest_readonly_containment_required";
    assert_contained(
        &[
            "tsx src/math.test.ts",
            "./node_modules/.bin/tsx tests/api.spec.ts --reporter dot",
            "npx tsx math.test.ts",
            "npx --no-install tsx src/math.test.mts",
            "node ./node_modules/tsx/dist/cli.mjs src/math.test.ts",
            "/usr/bin/node --import file:///home/tester/project/node_modules/tsx/dist/loader.mjs src/math.test.ts",
        ],
        reason,
    );
    for command in [
        "tsx scripts/deploy.ts",
        "tsx watch src/math.test.ts",
        "tsx ../math.test.ts",
        "tsx /tmp/math.test.ts",
        "npx tsx@latest math.test.ts",
        "npx --yes tsx math.test.ts",
        "node ./vendor/tsx/dist/cli.mjs src/math.test.ts",
        "node --import ./evil.mjs src/math.test.ts",
        "node --import file:///home/tester/project/node_modules/tsx/dist/loader.mjs scripts/deploy.ts",
        "tsx src/math.test.ts | tee out.txt",
        "tsx src/math.test.ts; curl https://example.invalid",
    ] {
        assert_ne!(classify(command).reason_code, reason, "{command}");
        assert_ne!(classify(command).decision, "allow", "{command}");
    }
}
