use super::*;

#[test]
fn current_main_unittest_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/contained_unittest_parity.json"
    ))
    .unwrap();
    assert_eq!(vectors["cases"].as_array().unwrap().len(), 13);
    for case in vectors["cases"].as_array().unwrap() {
        assert_eq!(
            evaluate(case["operation"].as_str().unwrap(), &case["input"]).unwrap(),
            case["expected"]
        );
    }
}

#[test]
fn incoming_main_node_and_tsx_script_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/contained_script_parity.json"
    ))
    .unwrap();
    assert_eq!(vectors["cases"].as_array().unwrap().len(), 44);
    for case in vectors["cases"].as_array().unwrap() {
        // Windows also runs a plain workspace script in the read-only
        // AppContainer, so a case can name the answer it gets there.
        let expected = match case.get("windows_expected") {
            Some(expected) if cfg!(windows) => expected,
            _ => &case["expected"],
        };
        assert_eq!(
            evaluate(case["operation"].as_str().unwrap(), &case["input"]).unwrap(),
            *expected,
            "{case}"
        );
    }
}

#[test]
fn relative_node_module_entries_stay_node_tools() {
    for argument in [
        "node_modules/eslint/bin/eslint.js",
        "./node_modules/eslint/bin/eslint.js",
        "/work/app/node_modules/eslint/bin/eslint.js",
        "node_modules/typescript/bin/tsc",
        "node_modules/vite/bin/vite.js",
    ] {
        let result = evaluate(
            "contained_kind",
            &json!({"command": ["node", argument, "src"]}),
        )
        .unwrap();
        assert_eq!(result["value"]["node_tool"], true, "{argument} {result}");
        assert_eq!(result["value"]["vitest"], false, "{argument}");
    }
    for argument in [
        "xnode_modules/eslint/bin/eslint.js",
        "node_modules_evil/eslint/bin/eslint.js",
        "eslint/bin/eslint.js",
    ] {
        let result = evaluate("contained_kind", &json!({"command": ["node", argument]})).unwrap();
        assert_eq!(result["value"]["node_tool"], false, "{argument} {result}");
    }
}

#[test]
fn original_portable_contained_argv_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/contained_execution_parity.json"
    ))
    .unwrap();
    let mut count = 0;
    for case in vectors["cases"].as_array().unwrap() {
        if let Some(result) = evaluate(case["operation"].as_str().unwrap(), &case["input"]) {
            assert_eq!(result, case["expected"], "case={case}");
            count += 1;
        }
    }
    assert!(count >= 80);
}

#[test]
fn bun_inline_eval_is_exact_argv_only() {
    for flag in ["-e", "--eval", "-p", "--print"] {
        let result = evaluate(
            "contained_kind",
            &json!({"command": ["bun", flag, "console.log(1)"]}),
        )
        .unwrap();
        assert_eq!(result["value"]["inline_eval"], true, "{flag} {result}");
    }
    for command in [
        json!(["bun", "-e"]),
        json!(["bun", "-e", "1", "extra"]),
        json!(["bun", "--smol", "-e", "1"]),
        json!(["bun", "run", "-e", "1"]),
        json!(["bun", "script.ts"]),
        json!(["bunx", "-e", "1"]),
        json!(["bun-evil", "-e", "1"]),
    ] {
        let result = evaluate("inline_eval", &json!({ "command": command })).unwrap();
        assert_eq!(result["value"], false, "{command} {result}");
    }
}

#[test]
fn only_a_bare_pnpm_exec_reads_as_vitest() {
    let kind = evaluate(
        "contained_kind",
        &json!({"command": ["pnpm", "exec", "vitest", "run", "a.test.ts"]}),
    )
    .unwrap();
    assert_eq!(kind["value"]["vitest"], true, "{kind}");
    assert_eq!(kind["value"]["node_tool"], false, "{kind}");
    let arguments = evaluate(
        "vitest_arguments",
        &json!({"command": ["pnpm", "exec", "vitest", "run", "a.test.ts"]}),
    )
    .unwrap();
    assert_eq!(arguments["value"], json!(["run", "a.test.ts"]));
    for command in [
        json!(["pnpm", "exec", "-c", "vitest", "run"]),
        json!(["pnpm", "-r", "exec", "vitest", "run"]),
        json!(["pnpm", "exec", "--filter", "app", "vitest", "run"]),
        json!(["pnpm", "exec", "vitest", "watch"]),
        json!(["pnpm", "dlx", "vitest", "run"]),
        json!(["pnpm-evil", "exec", "vitest", "run"]),
    ] {
        let result = evaluate("vitest_arguments", &json!({ "command": command })).unwrap();
        assert!(result.get("value").is_none(), "{command} {result}");
    }
}

/// The sink plans the call again from its own snapshot, so it has to be able
/// to ask for the same reading the pre-tool pass made of an activation.
#[test]
fn venv_activation_target_answers_the_sink() {
    let root = std::env::temp_dir().join(format!("contained-argv-venv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let venv = root.join("project/.venv");
    std::fs::create_dir_all(venv.join("bin")).unwrap();
    std::fs::write(
        venv.join("pyvenv.cfg"),
        "home = /usr/bin\nversion = 3.12.0\n",
    )
    .unwrap();
    std::fs::write(
        venv.join("bin/activate"),
        format!(
            "VIRTUAL_ENV='{environment}'\nexport VIRTUAL_ENV\n_OLD_VIRTUAL_PATH=\"$PATH\"\nPATH=\"$VIRTUAL_ENV/bin:$PATH\"\nexport PATH\n",
            environment = venv.display()
        ),
    )
    .unwrap();
    std::fs::write(venv.join("bin/pytest"), "#!/bin/sh\nexit 0\n").unwrap();
    let project = root.join("project");
    let input = json!({
        "text": "source .venv/bin/activate && pytest -q",
        "cwd": project.to_str().unwrap(),
        "home": root.to_str().unwrap(),
    });
    let projected = evaluate("venv_activation_target", &input).unwrap();
    assert_eq!(
        projected["value"],
        json!(".venv/bin/pytest -q"),
        "{projected}"
    );
    // An activation the scan cannot read through leaves the command whole.
    let unread = json!({
        "text": "source /nowhere/bin/activate && pytest -q",
        "cwd": project.to_str().unwrap(),
        "home": root.to_str().unwrap(),
    });
    assert_eq!(
        evaluate("venv_activation_target", &unread).unwrap()["value"],
        Value::Null
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn launcher_program_reports_where_the_parser_reads_the_program() {
    let offset =
        |command: &[&str]| evaluate("launcher_program", &json!({ "command": command })).unwrap();
    assert_eq!(
        offset(&["nice", "-n", "10", "pytest", "-q"]),
        json!({"value": 3})
    );
    assert_eq!(offset(&["nice", "pytest", "-q"]), json!({"value": 1}));
    assert_eq!(
        offset(&["stdbuf", "-oL", "pytest", "-q"]),
        json!({"value": 2})
    );
    // The sink refuses every shape the native parser leaves in place.
    for command in [
        &["./nice", "-n", "10", "pytest"][..],
        &["C:\\tools\\nice", "pytest"],
        &["stdbuf", "pytest", "-q"],
        &["nohup", "pytest", "-q"],
        &["nice", "-n", "10", "python3", "deploy.py"],
        &["pytest", "-q"],
    ] {
        assert_eq!(offset(command), json!({"value": null}), "{command:?}");
    }
}
