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
/// to ask for the same reading the pre-tool pass made of an activation or a
/// trailing group.
#[test]
fn contained_target_answers_the_sink() {
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
    let projected = evaluate("contained_target", &input).unwrap();
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
        evaluate("contained_target", &unread).unwrap()["value"],
        Value::Null
    );
    // A trailing group runs exactly the list inside it, around an activation
    // or not.
    for (text, expected) in [
        ("(.venv/bin/pytest -q)", ".venv/bin/pytest -q"),
        ("( .venv/bin/pytest -q )", ".venv/bin/pytest -q"),
        ("{ .venv/bin/pytest -q; }", ".venv/bin/pytest -q"),
        (
            "(source .venv/bin/activate && pytest -q)",
            ".venv/bin/pytest -q",
        ),
    ] {
        let grouped = json!({
            "text": text,
            "cwd": project.to_str().unwrap(),
            "home": root.to_str().unwrap(),
        });
        assert_eq!(
            evaluate("contained_target", &grouped).unwrap()["value"],
            json!(expected),
            "{text}"
        );
    }
    // A group behind a conditional that holds a list keeps its parentheses:
    // flattened, `touch b` would run whether or not `false` succeeded.
    let conditional = json!({
        "text": "false && (.venv/bin/pytest -q; touch b)",
        "cwd": project.to_str().unwrap(),
        "home": root.to_str().unwrap(),
    });
    assert_eq!(
        evaluate("contained_target", &conditional).unwrap()["value"],
        Value::Null
    );
    // A plain call is its own answer.
    let plain = json!({
        "text": ".venv/bin/pytest -q",
        "cwd": project.to_str().unwrap(),
        "home": root.to_str().unwrap(),
    });
    assert_eq!(
        evaluate("contained_target", &plain).unwrap()["value"],
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
    // The shell's `exec` is read here too. The sink keeps no list of launcher
    // names of its own, so every name this op answers for is one it peels.
    assert_eq!(offset(&["exec", "pytest", "-q"]), json!({"value": 1}));
    // The sink refuses every shape the native parser leaves in place.
    for command in [
        &["./nice", "-n", "10", "pytest"][..],
        &["C:\\tools\\nice", "pytest"],
        &["stdbuf", "pytest", "-q"],
        &["nohup", "pytest", "-q"],
        &["nice", "-n", "10", "python3", "deploy.py"],
        &["pytest", "-q"],
        &["exec"],
        &["exec", "-a", "name", "pytest"],
        &["exec", "./deploy.sh"],
    ] {
        assert_eq!(offset(command), json!({"value": null}), "{command:?}");
    }
}

#[test]
fn transparent_prefix_reports_where_the_parser_reads_the_program() {
    let offset =
        |command: &[&str]| evaluate("transparent_prefix", &json!({ "command": command })).unwrap();
    assert_eq!(offset(&["command", "pytest", "-q"]), json!({"value": 1}));
    assert_eq!(offset(&["time", "pytest", "-q"]), json!({"value": 1}));
    assert_eq!(
        offset(&["env", "CI=1", "pytest", "-q"]),
        json!({"value": 2})
    );
    // The parser reads the two system paths as the `env` they name, so the
    // sink peels them too rather than planning `/usr/bin/env` as the program.
    assert_eq!(
        offset(&["/usr/bin/env", "CI=1", "pytest", "-q"]),
        json!({"value": 2})
    );
    assert_eq!(offset(&["/bin/env", "CI=1", "pytest"]), json!({"value": 2}));
    assert_eq!(
        offset(&["env", "CI=1", "TZ=UTC", "pytest"]),
        json!({"value": 3})
    );
    for command in [
        // An `env` carrying no assignment only bypasses shell functions, and
        // extension floors key on that spelling, so it stays the executable.
        &["env", "pytest", "-q"][..],
        &["env", "-i", "pytest"],
        &["env", "CI=1"],
        // A word that is no assignment and no program leaves the prefix whole.
        &["env", "FOO=1", "A-B=1", "rm"],
        &["command", "-v", "pytest"],
        &["time", "-p", "pytest"],
        &["nice", "pytest"],
        &["pytest", "-q"],
    ] {
        assert_eq!(offset(command), json!({"value": null}), "{command:?}");
    }
}
