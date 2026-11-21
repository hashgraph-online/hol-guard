//! How the argv lexer reports the program a launcher or prefix hides.
use super::super::*;

#[test]
fn launcher_program_reports_where_the_parser_reads_the_program() {
    let offset = |command: &[&str]| {
        let command: Vec<String> = command.iter().map(|word| (*word).to_owned()).collect();
        crate::parser_wrappers::launcher_program(&command, 0)
    };
    assert_eq!(offset(&["nice", "-n", "10", "pytest", "-q"]), Some(3));
    assert_eq!(offset(&["nice", "pytest", "-q"]), Some(1));
    assert_eq!(offset(&["stdbuf", "-oL", "pytest", "-q"]), Some(2));
    // The shell's `exec` is read here too. The sink keeps no list of launcher
    // names of its own, so every name this answers for is one it peels.
    assert_eq!(offset(&["exec", "pytest", "-q"]), Some(1));
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
        assert_eq!(offset(command), None, "{command:?}");
    }
}

#[test]
fn transparent_prefix_reports_where_the_parser_reads_the_program() {
    let offset = |command: &[&str]| {
        let command: Vec<String> = command.iter().map(|word| (*word).to_owned()).collect();
        crate::parser_wrappers::transparent_prefix(&command, 0).map(|(index, _)| index)
    };
    assert_eq!(offset(&["command", "pytest", "-q"]), Some(1));
    assert_eq!(offset(&["time", "pytest", "-q"]), Some(1));
    assert_eq!(offset(&["env", "CI=1", "pytest", "-q"]), Some(2));
    // The parser reads the two system paths as the `env` they name, so the
    // sink peels them too rather than planning `/usr/bin/env` as the program.
    assert_eq!(offset(&["/usr/bin/env", "CI=1", "pytest", "-q"]), Some(2));
    assert_eq!(offset(&["/bin/env", "CI=1", "pytest"]), Some(2));
    assert_eq!(offset(&["env", "CI=1", "TZ=UTC", "pytest"]), Some(3));
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
        assert_eq!(offset(command), None, "{command:?}");
    }
}

#[test]
fn a_relative_vitest_entry_names_the_same_runner_as_the_absolute_one() {
    for argument in [
        "node_modules/vitest/vitest.mjs",
        "./node_modules/vitest/vitest.mjs",
        "dashboard/node_modules/vitest/vitest.mjs",
        "/work/app/node_modules/vitest/vitest.mjs",
        "node_modules/vitest/dist/cli.js",
        "./node_modules/vitest/dist/cli.js",
        "/work/app/node_modules/vitest/dist/cli.js",
    ] {
        let command = json!(["node", argument, "run", "src"]);
        let kind = evaluate("contained_kind", &json!({ "command": command.clone() })).unwrap();
        assert_eq!(kind["value"]["vitest"], true, "{argument} {kind}");
        let arguments = evaluate("vitest_arguments", &json!({ "command": command })).unwrap();
        assert_eq!(arguments["value"], json!(["run", "src"]), "{argument}");
    }
}

#[test]
fn bun_launching_a_runner_entry_names_the_runner_node_names() {
    for (argument, tail, arguments) in [
        (
            "node_modules/vitest/vitest.mjs",
            json!(["run", "src"]),
            json!(["run", "src"]),
        ),
        (
            "./node_modules/vitest/dist/cli.js",
            json!(["run"]),
            json!(["run"]),
        ),
        (
            "node_modules/jest/bin/jest.js",
            json!(["src"]),
            json!(["src"]),
        ),
        (
            "node_modules/mocha/bin/mocha.js",
            json!(["test/unit"]),
            json!(["test/unit"]),
        ),
    ] {
        let mut command = vec![json!("bun"), json!(argument)];
        command.extend(tail.as_array().unwrap().iter().cloned());
        let command = json!(command);
        let kind = evaluate("contained_kind", &json!({ "command": command.clone() })).unwrap();
        assert_eq!(kind["value"]["vitest"], true, "{argument} {kind}");
        // The node-tool sink reads a manifest script, not an entry launch, so
        // a runner entry has to leave that route alone.
        assert_eq!(kind["value"]["node_tool"], false, "{argument} {kind}");
        let found = evaluate("vitest_arguments", &json!({ "command": command })).unwrap();
        assert_eq!(found["value"], arguments, "{argument}");
    }
}

#[test]
fn bun_naming_no_runner_entry_still_names_no_runner() {
    for command in [
        // `--cwd` sits where the entry would be, so the call names no file
        // this route may run.
        json!([
            "bun",
            "--cwd",
            "app",
            "node_modules/vitest/vitest.mjs",
            "run"
        ]),
        json!(["bun", "xnode_modules/vitest/vitest.mjs", "run"]),
        json!(["bun", "node_modules/vite/dist/cli.js", "run"]),
    ] {
        let kind = evaluate("contained_kind", &json!({ "command": command.clone() })).unwrap();
        assert_eq!(kind["value"]["vitest"], false, "{command} {kind}");
    }
}

#[test]
fn a_relative_jest_entry_names_the_same_runner_as_the_absolute_one() {
    for argument in [
        "node_modules/jest/bin/jest.js",
        "./node_modules/jest/bin/jest.js",
        "/work/app/node_modules/jest/bin/jest.js",
    ] {
        let command = json!(["node", argument, "src"]);
        let arguments = evaluate("vitest_arguments", &json!({ "command": command })).unwrap();
        assert_eq!(arguments["value"], json!(["src"]), "{argument}");
    }
}

#[test]
fn a_relative_mocha_entry_names_the_same_runner_as_the_absolute_one() {
    for argument in [
        "node_modules/mocha/bin/mocha.js",
        "./node_modules/mocha/bin/mocha.js",
        "/work/app/node_modules/mocha/bin/mocha.js",
        // Mocha 8 and 9 publish the shim without the extension.
        "node_modules/mocha/bin/mocha",
        "./node_modules/mocha/bin/mocha",
    ] {
        let command = json!(["node", argument, "test/unit"]);
        let kind = evaluate("contained_kind", &json!({ "command": command.clone() })).unwrap();
        assert_eq!(kind["value"]["vitest"], true, "{argument} {kind}");
        let arguments = evaluate("vitest_arguments", &json!({ "command": command })).unwrap();
        assert_eq!(arguments["value"], json!(["test/unit"]), "{argument}");
    }
}

#[test]
fn a_lookalike_entry_still_names_no_runner() {
    for argument in [
        "xnode_modules/vitest/vitest.mjs",
        "node_modules_evil/vitest/vitest.mjs",
        "vitest/vitest.mjs",
        "node_modules/vitest/dist/vitest.mjs",
        "node_modules/jest/bin/jest.js.bak",
        "node_modules/mocha/bin/mocha.sh",
        "node_modules/mocha/bin/_mocha.js",
        "node_modules/xmocha/bin/mocha",
        "node_modules/vite/dist/cli.js",
        "node_modules/xvitest/dist/cli.js",
        "node_modules/vitest/dist/cli.mjs",
    ] {
        let command = json!(["node", argument, "run"]);
        let kind = evaluate("contained_kind", &json!({ "command": command })).unwrap();
        assert_eq!(kind["value"]["vitest"], false, "{argument} {kind}");
    }
}
