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
        // No caller asks for the test-script screen as an operation any more,
        // so its recorded vectors read the screen the planners still use.
        if case["operation"] == "test_script" {
            let input = &case["input"];
            let named = named_test_script(
                input["value"].as_str().unwrap(),
                input["node"].as_bool().unwrap_or(false),
            );
            assert_eq!(json!({ "value": named }), case["expected"], "case={case}");
            count += 1;
            continue;
        }
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

/// The route that admits `npm exec` peels npm's own exec options, so the sink
/// has to read the same argv or the run it planned is not the run that was
/// admitted.
#[test]
fn npm_exec_reads_the_runner_behind_its_own_options() {
    for command in [
        json!(["npm", "exec", "--no", "--", "vitest", "run"]),
        json!(["npm", "exec", "--prefer-offline", "vitest", "run"]),
        json!(["npm", "x", "-y", "--silent", "vitest", "run"]),
    ] {
        let kind = evaluate("contained_kind", &json!({ "command": command })).unwrap();
        assert_eq!(kind["value"]["vitest"], true, "{command} {kind}");
        assert_eq!(kind["value"]["node_tool"], false, "{command} {kind}");
        let arguments = evaluate("vitest_arguments", &json!({ "command": command })).unwrap();
        assert_eq!(arguments["value"], json!(["run"]), "{command}");
    }
    for command in [
        // `--workspace` chooses which package the run reaches, so it is not
        // one of the options that only precede the tool.
        json!(["npm", "exec", "--workspace", "app", "vitest", "run"]),
        // pnpm's and yarn's exec options select packages too, and neither is
        // read from npx's table.
        json!(["pnpm", "exec", "--no", "vitest", "run"]),
        json!(["yarn", "exec", "--no", "vitest", "run"]),
        json!(["npm", "exec", "--no", "--"]),
    ] {
        let result = evaluate("vitest_arguments", &json!({ "command": command })).unwrap();
        assert!(result.get("value").is_none(), "{command} {result}");
    }
}

/// The admission and the classifier read one spelling, so the kind the sink
/// plans is always the kind the admitting reason names. `manager_exec_tool`
/// takes that one reading rather than keeping a second copy of it beside the
/// admission's: if the two answered differently, a widening on either side
/// would admit a run on one route and leave the sink refusing it on another.
#[test]
fn the_classifier_reads_the_local_bin_spelling_the_admission_reads() {
    for (command, tool) in [
        (json!(["pnpm", "exec", "vitest", "run"]), "vitest"),
        (json!(["npm", "exec", "--", "jest", "--ci"]), "jest"),
        (
            json!(["npm", "x", "--yes", "mocha", "--reporter", "spec"]),
            "mocha",
        ),
        (json!(["yarn", "exec", "tsc", "--noEmit"]), "tsc"),
    ] {
        let kind = evaluate("contained_kind", &json!({ "command": command })).unwrap();
        let expected = tool == "tsc";
        assert_eq!(kind["value"]["node_tool"], expected, "{command} {kind}");
        assert_eq!(kind["value"]["vitest"], !expected, "{command} {kind}");
    }
    // pnpm resolves a bare word against the manifest before it falls back to
    // `pnpm exec`, and since pnpm 7 the words behind that word go to the
    // script, so the shorthand cannot be read as the local-bin run without the
    // manifest neither side here sees. Both readings leave it alone together.
    for command in [
        json!(["pnpm", "vitest", "run"]),
        json!(["pnpm", "jest", "--ci"]),
        json!(["pnpm", "tsc", "--noEmit"]),
        json!(["pnpm", "test"]),
        json!(["pnpm", "run", "test"]),
        json!(["pnpm", "-r", "vitest", "run"]),
    ] {
        let kind = evaluate("contained_kind", &json!({ "command": command })).unwrap();
        assert_eq!(kind["value"]["vitest"], false, "{command} {kind}");
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
fn contained_target_reads_a_bounded_inline_shell_as_its_script() {
    // The review reads `bash -ec 'pytest -q'` as `pytest -q`, so the sink has
    // to plan that script or it refuses the run the review sent it.
    for (text, script) in [
        ("bash -ec 'pytest -q'", "pytest -q"),
        ("sh -c 'pytest -q'", "pytest -q"),
        ("bash -e -c 'pytest -q'", "pytest -q"),
        // The sink re-authorizes the script on its own, so a chained script
        // is projected here and refused there.
        ("bash -ec 'pytest -q && rm -rf x'", "pytest -q && rm -rf x"),
    ] {
        let input = json!({ "text": text });
        assert_eq!(
            evaluate("contained_target", &input).unwrap()["value"],
            json!(script),
            "{text}"
        );
    }
    // A shell that reads more than its script, a script that expands, or a
    // command with no shell in front stays whole.
    for text in [
        "bash -lc 'pytest -q'",
        "zsh -c 'pytest -q'",
        "bash -c 'pytest \"$X\"'",
        "pytest -q",
    ] {
        let input = json!({ "text": text });
        assert_eq!(
            evaluate("contained_target", &input).unwrap()["value"],
            Value::Null,
            "{text}"
        );
    }
}

#[path = "contained_argv_program_tests.rs"]
mod program;
#[path = "contained_argv_script_tests.rs"]
mod script;
