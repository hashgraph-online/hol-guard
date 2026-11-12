//! How a named script, plan grant or hook command reads through this lexer.
use super::super::*;

#[test]
fn a_manifest_script_reads_the_way_the_route_that_admits_it_reads_it() {
    // `package_script_route` reads a named script's words with this lexer, so
    // the sink that runs the script asks for that reading rather than making
    // its own.
    assert_eq!(
        evaluate(
            "script_words",
            &json!({ "script": "eslint src --max-warnings 0" })
        )
        .unwrap()["value"],
        json!(["eslint", "src", "--max-warnings", "0"])
    );
    // This lexer leaves a backslash alone where the platform spells paths with
    // it; Python's `shlex`, which the sink used to split the script with,
    // escapes on every platform.
    assert_eq!(
        evaluate("script_words", &json!({ "script": "eslint .\\src" })).unwrap()["value"],
        if cfg!(windows) {
            json!(["eslint", ".\\src"])
        } else {
            json!(["eslint", ".src"])
        }
    );
    // An unterminated quote is not a reading of the script, so the run is
    // refused rather than started on whatever a partial parse leaves.
    assert_eq!(
        evaluate("script_words", &json!({ "script": "eslint 'src" })).unwrap()["reason_code"],
        json!("node_tool_invalid_command")
    );
    // A manifest entry that is not text names nothing to run.
    assert_eq!(
        evaluate("script_words", &json!({ "script": 7 })).unwrap()["reason_code"],
        json!("node_tool_invalid_command")
    );
}

#[test]
fn the_grant_a_workspace_plan_carries_is_read_against_the_words_the_command_spells() {
    // A script outside the workspace earns a read root only when the command
    // names it, and `;` ends the word that names it even with no space in
    // front.
    assert_eq!(
        evaluate(
            "command_absolute_words",
            &json!({ "command_text": "python3 /tmp/run/good.py;echo ok" })
        )
        .unwrap()["value"],
        json!(["/tmp/run/good.py"])
    );
    // `>` and `|` end a word the same way, and the file a redirect writes is
    // relative, so it names no grant.
    assert_eq!(
        evaluate(
            "command_absolute_words",
            &json!({ "command_text": "python3 /tmp/run/good.py>out.log|head" })
        )
        .unwrap()["value"],
        json!(["/tmp/run/good.py"])
    );
    // `#` is an ordinary character here, so a directory spelled with one is
    // read whole and a command that writes one onto a path names a different
    // file than the plan's grant.
    assert_eq!(
        evaluate(
            "command_absolute_words",
            &json!({ "command_text": "python3 /tmp/run#2/good.py" })
        )
        .unwrap()["value"],
        json!(["/tmp/run#2/good.py"])
    );
    assert_eq!(
        evaluate(
            "command_absolute_words",
            &json!({ "command_text": "python3 /tmp/run/good.py#x" })
        )
        .unwrap()["value"],
        json!(["/tmp/run/good.py#x"])
    );
    // A relative word names no file the plan could have granted.
    assert_eq!(
        evaluate(
            "command_absolute_words",
            &json!({ "command_text": "python3 run/good.py" })
        )
        .unwrap()["value"],
        json!([])
    );
    // An unterminated quote is not a reading of the command, so no grant is
    // admitted against a partial parse.
    assert_eq!(
        evaluate(
            "command_absolute_words",
            &json!({ "command_text": "python3 '/tmp/run" })
        )
        .unwrap()["reason_code"],
        json!("pytest_restricted_invalid_command")
    );
    // A request without the text names nothing to read.
    assert_eq!(
        evaluate("command_absolute_words", &json!({ "command": ["python3"] })).unwrap()
            ["reason_code"],
        json!("pytest_restricted_invalid_command")
    );
}

#[test]
fn a_hook_command_reads_the_way_the_screen_that_admitted_it_read_it() {
    // `pretool` lexes the hook's command text with this lexer when it decides
    // the run is contained, so the sink asks for that same reading rather than
    // splitting the text again on its way to a receipt.
    assert_eq!(
        evaluate(
            "command_words",
            &json!({ "command_text": "CI=1 pytest -q tests/test_a.py" })
        )
        .unwrap()["value"],
        json!(["CI=1", "pytest", "-q", "tests/test_a.py"])
    );
    // The two readings part on a backslash: this lexer leaves it alone where
    // the platform spells paths with it, and Python's `shlex`, which the sink
    // used, escapes on every platform. A receipt drawn over the escaped words
    // would not name the run that executes.
    assert_eq!(
        evaluate(
            "command_words",
            &json!({ "command_text": "pytest tests\\a.py" })
        )
        .unwrap()["value"],
        if cfg!(windows) {
            json!(["pytest", "tests\\a.py"])
        } else {
            json!(["pytest", "testsa.py"])
        }
    );
    // An unterminated quote is not a reading of the command, so no receipt is
    // drawn over a partial parse.
    assert_eq!(
        evaluate("command_words", &json!({ "command_text": "pytest 'tests" })).unwrap()
            ["reason_code"],
        json!("pytest_restricted_invalid_command")
    );
    // A request without the text names nothing to run.
    assert_eq!(
        evaluate("command_words", &json!({ "command": ["pytest"] })).unwrap()["reason_code"],
        json!("pytest_restricted_invalid_command")
    );
}

#[test]
fn script_run_verb_reads_every_managers_own_aliases() {
    // npm's command table maps `run-script`, `rum` and `urn` onto `run`, so a
    // line spelled any of those ways starts the same script.
    for word in ["run", "run-script", "rum", "urn"] {
        assert!(names_script_run_verb("npm", word), "npm {word}");
    }
    // pnpm lists only `run-script`.
    assert!(names_script_run_verb("pnpm", "run-script"));
    for word in ["rum", "urn"] {
        assert!(!names_script_run_verb("pnpm", word), "pnpm {word}");
    }
    // yarn and bun spell it `run` alone. Reading an alias they do not carry
    // would admit a word they pass to the manifest instead.
    for manager in ["yarn", "bun"] {
        assert!(names_script_run_verb(manager, "run"), "{manager} run");
        for word in ["run-script", "rum", "urn"] {
            assert!(!names_script_run_verb(manager, word), "{manager} {word}");
        }
    }
    // A path-spelled manager answers for the program it names.
    assert!(names_script_run_verb("/usr/local/bin/npm", "run-script"));
    // Nothing else is the verb.
    assert!(!names_script_run_verb("npm", "runs"));
    assert!(!names_script_run_verb("npm", "exec"));
}

#[test]
fn aliased_test_script_name_resolves_to_the_manifest_key() {
    // `t` and `tst` are npm's and pnpm's own aliases of `test`, and both run
    // the manifest's `test` entry, so the name returned is the key the sink
    // looks up rather than the word the line spells.
    for manager in ["npm", "pnpm"] {
        for word in ["t", "tst"] {
            assert_eq!(
                aliased_test_script_name(manager, word),
                Some("test"),
                "{manager} {word}"
            );
        }
    }
    // yarn and bun pass a bare word straight to the manifest, so reading `t`
    // as `test` for them would run an entry the line never named.
    for manager in ["yarn", "bun"] {
        for word in ["t", "tst"] {
            assert_eq!(
                aliased_test_script_name(manager, word),
                None,
                "{manager} {word}"
            );
        }
    }
    // The canonical spelling needs no mapping, and no other word is an alias.
    assert_eq!(aliased_test_script_name("npm", "test"), None);
    assert_eq!(aliased_test_script_name("npm", "ts"), None);
    assert_eq!(
        aliased_test_script_name("/opt/homebrew/bin/pnpm", "t"),
        Some("test")
    );
}

/// The sink reads the kind off the same words the admission did, so a Bun run
/// of one workspace test file has to arrive as a Node test rather than as the
/// tool kind every other `bun` line takes.
#[test]
fn bun_running_one_test_file_reads_as_a_node_test() {
    for command in [
        json!(["bun", "src/app-routing.test.ts"]),
        json!(["bun", "src/shell-navigation.test.tsx"]),
        json!(["bun", "api.spec.mjs"]),
        json!(["/opt/homebrew/bin/bun", "tests/test_parser.js"]),
    ] {
        let kind = evaluate("contained_kind", &json!({ "command": command })).unwrap();
        assert_eq!(kind["value"]["node_test"], true, "{command} {kind}");
        assert_eq!(kind["value"]["node_tool"], false, "{command} {kind}");
        assert_eq!(kind["value"]["vitest"], false, "{command} {kind}");
        assert_eq!(kind["value"]["inline_eval"], false, "{command} {kind}");
    }
    for command in [
        json!(["bun", "src/server.ts"]),
        json!(["bun", "../other/app.test.ts"]),
        json!(["bun", "src/app.test.ts", "src/other.test.ts"]),
    ] {
        let kind = evaluate("contained_kind", &json!({ "command": command })).unwrap();
        assert_eq!(kind["value"]["node_test"], false, "{command} {kind}");
    }
}
