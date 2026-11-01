use super::node_tool_modes::{prettier_checks, PRETTIER_ENTRIES};
use super::{
    entry_tool, local_package_entry, node_tool_route, program_name, supported_tool, tool_entries,
    writes_or_chains, NodeToolRoute, ToolMode,
};

fn words(command: &[&str]) -> Vec<String> {
    command.iter().map(|word| (*word).to_string()).collect()
}

fn route(command: &[&str]) -> NodeToolRoute {
    node_tool_route(&words(command), None, false, None)
}

fn windows_route(command: &[&str]) -> NodeToolRoute {
    node_tool_route(&words(command), None, true, None)
}

fn tool(route: &NodeToolRoute) -> Option<(&'static str, Vec<String>, ToolMode)> {
    match route {
        NodeToolRoute::Tool {
            name,
            arguments,
            mode,
            ..
        } => Some((name, arguments.clone(), *mode)),
        _ => None,
    }
}

fn refusal(route: &NodeToolRoute) -> Option<(&'static str, &'static str)> {
    match route {
        NodeToolRoute::Invalid { code, message } => Some((code, message)),
        _ => None,
    }
}

#[test]
fn a_local_runner_spelling_reaches_the_tool_it_names() {
    for command in [
        ["npx", "eslint", "src"].as_slice(),
        ["npx", "--no-install", "eslint", "src"].as_slice(),
        ["bunx", "eslint", "src"].as_slice(),
        ["bun", "x", "eslint", "src"].as_slice(),
        ["npm", "exec", "eslint", "src"].as_slice(),
        ["npm", "exec", "--", "eslint", "src"].as_slice(),
        ["npm", "x", "eslint", "src"].as_slice(),
        ["pnpm", "exec", "eslint", "src"].as_slice(),
        ["yarn", "exec", "--", "eslint", "src"].as_slice(),
        ["npm", "--silent", "exec", "eslint", "src"].as_slice(),
        ["pnpm", "--silent", "exec", "eslint", "src"].as_slice(),
        ["pnpm", "--reporter=silent", "exec", "eslint", "src"].as_slice(),
        ["yarn", "--silent", "exec", "--", "eslint", "src"].as_slice(),
        ["/usr/local/bin/eslint", "src"].as_slice(),
    ] {
        let route = route(command);
        assert_eq!(
            tool(&route),
            Some(("eslint", words(&["src"]), ToolMode::Report)),
            "{command:?}"
        );
    }
}

#[test]
fn a_named_package_script_is_read_from_the_manifest_instead() {
    for (command, task) in [
        (["npm", "run", "lint"].as_slice(), "lint"),
        (["bun", "run", "lint"].as_slice(), "lint"),
        (["pnpm", "lint"].as_slice(), "lint"),
        (["yarn", "lint"].as_slice(), "lint"),
    ] {
        assert_eq!(
            route(command),
            NodeToolRoute::Script {
                task: task.to_owned()
            },
            "{command:?}"
        );
    }
}

#[test]
fn a_manager_subcommand_is_not_a_script_name() {
    for command in [
        ["pnpm", "install"].as_slice(),
        ["yarn", "publish"].as_slice(),
        ["npm", "lint"].as_slice(),
        ["npm", "run", "lint", "extra"].as_slice(),
    ] {
        assert_eq!(
            refusal(&route(command)).map(|(_, message)| message),
            Some("Only a single named package script is supported."),
            "{command:?}"
        );
    }
}

#[test]
fn a_run_carries_its_own_arguments_into_the_script_body() {
    // `npm run lint -- --max-warnings=0` names the `lint` script and hands it
    // `--max-warnings=0`, so the first reading names the script and the second
    // gates the body holding the word the run passed on.
    let command = words(&["npm", "run", "lint", "--", "--max-warnings=0"]);
    assert_eq!(
        node_tool_route(&command, None, false, None),
        NodeToolRoute::Script {
            task: "lint".to_owned()
        }
    );
    let body = words(&["eslint", "."]);
    assert_eq!(
        tool(&node_tool_route(&command, Some(&body), false, None)),
        Some((
            "eslint",
            words(&[".", "--max-warnings=0"]),
            ToolMode::Report
        ))
    );

    // A word the run passes on is gated as the body's own, so a fixing run is
    // refused with the body rather than slipping past between the readings.
    let fixing = words(&["npm", "run", "lint", "--", "--fix"]);
    assert_eq!(
        refusal(&node_tool_route(&fixing, Some(&body), false, None)).map(|(_, message)| message),
        Some("The lint/typecheck input has write or shell effects.")
    );
}

#[test]
fn a_script_body_is_gated_as_the_run_it_spells() {
    let body = words(&["tsc", "--noEmit"]);
    let route = node_tool_route(
        &words(&["npm", "run", "typecheck"]),
        Some(&body),
        false,
        None,
    );
    assert_eq!(
        tool(&route),
        Some(("tsc", words(&["--noEmit"]), ToolMode::Report))
    );

    let empty: Vec<String> = Vec::new();
    assert_eq!(
        refusal(&node_tool_route(
            &words(&["npm", "run", "x"]),
            Some(&empty),
            false,
            None
        ))
        .map(|(_, message)| message),
        Some("The requested local script is empty.")
    );
}

#[test]
fn a_package_script_does_not_run_contained_on_windows_yet() {
    let route = windows_route(&["npm", "run", "lint"]);
    assert_eq!(
        refusal(&route),
        Some((
            "pytest_restricted_sandbox_unavailable",
            "Package scripts do not run contained on Windows yet."
        ))
    );
}

#[test]
fn an_exec_spelling_without_a_runner_names_the_missing_runner() {
    for command in [
        ["npm", "exec"].as_slice(),
        ["npm", "exec", "--"].as_slice(),
        ["pnpm", "exec", "--flag"].as_slice(),
        ["npx"].as_slice(),
        ["npx", "--no-install"].as_slice(),
    ] {
        assert_eq!(
            refusal(&route(command)).map(|(_, message)| message),
            Some("Missing local runner."),
            "{command:?}"
        );
    }
}

#[test]
fn node_started_on_a_published_entrypoint_resolves_the_tool_it_is() {
    let routed = route(&["node", "node_modules/typescript/bin/tsc", "--noEmit"]);
    match &routed {
        NodeToolRoute::Tool {
            name,
            expected_entry,
            runtime_arguments,
            ..
        } => {
            assert_eq!(*name, "tsc");
            assert_eq!(
                expected_entry.as_deref(),
                Some("node_modules/typescript/bin/tsc")
            );
            assert!(runtime_arguments.is_empty());
        }
        other => panic!("expected a tool, got {other:?}"),
    }

    assert_eq!(
        refusal(&route(&["node"])).map(|(_, message)| message),
        Some("Missing local entrypoint.")
    );
    assert!(refusal(&route(&["node", "scripts/build.js"])).is_some());
}

#[test]
fn a_bounded_heap_option_is_carried_and_an_unbounded_one_is_refused() {
    match &route(&[
        "node",
        "--max-old-space-size=4096",
        "node_modules/eslint/bin/eslint.js",
        "src",
    ]) {
        NodeToolRoute::Tool {
            name,
            runtime_arguments,
            arguments,
            ..
        } => {
            assert_eq!(*name, "eslint");
            assert_eq!(runtime_arguments, &words(&["--max-old-space-size=4096"]));
            assert_eq!(arguments, &words(&["src"]));
        }
        other => panic!("expected a tool, got {other:?}"),
    }

    for value in ["0", "15", "131073", "", "4096x", "٤٠٩٦"] {
        let option = format!("--max-old-space-size={value}");
        let command = words(&["node", &option, "node_modules/eslint/bin/eslint.js"]);
        assert_eq!(
            refusal(&node_tool_route(&command, None, false, None)).map(|(_, message)| message),
            Some("Invalid bounded Node memory option."),
            "{option}"
        );
    }
}

#[test]
fn a_checking_mode_is_required_of_every_admitted_tool() {
    for command in [
        ["npx", "tsc"].as_slice(),
        ["npx", "prettier", "."].as_slice(),
        ["npx", "vite"].as_slice(),
        ["npx", "vite", "preview"].as_slice(),
        ["npx", "webpack"].as_slice(),
    ] {
        assert_eq!(
            refusal(&route(command)).map(|(_, message)| message),
            Some("Only local ESLint, no-emit TypeScript and Prettier in a checking mode are supported."),
            "{command:?}"
        );
    }
    for check in ["--check", "-c", "--list-different", "-l"] {
        assert!(
            tool(&route(&["npx", "prettier", check, "."])).is_some(),
            "{check}"
        );
    }
    assert_eq!(
        tool(&route(&["npx", "vite", "build"])).map(|(name, _, mode)| (name, mode)),
        Some(("vite", ToolMode::Build))
    );
}

#[test]
fn a_write_or_shell_token_is_refused_after_the_tool_is_known() {
    for argument in [
        "--fix",
        "--fix-dry-run",
        "--fix=all",
        "--output-file",
        "-o",
        "--output-file=report.txt",
        "--write",
        "-w",
        "--write=.",
        "&&",
        "|",
        ";",
    ] {
        let command = words(&["npx", "eslint", "src", argument]);
        assert_eq!(
            refusal(&node_tool_route(&command, None, false, None)).map(|(_, message)| message),
            Some("The lint/typecheck input has write or shell effects."),
            "{argument}"
        );
    }
}

#[test]
fn a_windows_program_name_drops_its_executable_suffix() {
    assert_eq!(program_name("C:\\tools\\ESLint.EXE", true), "eslint");
    assert_eq!(program_name("C:\\tools\\eslint.cmd", true), "eslint.cmd");
    assert_eq!(program_name("/usr/bin/eslint", false), "eslint");
    assert_eq!(program_name("eslint.exe", false), "eslint.exe");
    assert!(tool(&windows_route(&["C:\\bin\\npx.EXE", "eslint", "src"])).is_some());
}

#[test]
fn a_published_entrypoint_is_recognised_only_below_node_modules() {
    assert!(local_package_entry(
        "node_modules/eslint/bin/eslint.js",
        "eslint/bin/eslint.js"
    ));
    assert!(local_package_entry(
        "./packages/app/node_modules/eslint/bin/eslint.js",
        "eslint/bin/eslint.js"
    ));
    assert!(!local_package_entry(
        "vendored/eslint/bin/eslint.js",
        "eslint/bin/eslint.js"
    ));
    assert_eq!(entry_tool("node_modules/vite/bin/vite.js"), "vite");
    assert_eq!(entry_tool("scripts/build.js"), "");
}

#[test]
fn the_shared_table_answers_for_every_admitted_tool() {
    assert_eq!(
        tool_entries("prettier").map(|(tool, entries)| (tool, entries.to_vec())),
        Some(("prettier", PRETTIER_ENTRIES.to_vec()))
    );
    assert_eq!(tool_entries("webpack"), None);
    assert_eq!(
        supported_tool("tsc", &words(&["--noEmit"])).map(|(name, _, mode)| (name, mode)),
        Some(("tsc", ToolMode::Report))
    );
    assert!(supported_tool("tsc", &words(&[])).is_none());
    assert!(prettier_checks(&words(&["--check"])));
    assert!(!prettier_checks(&words(&["."])));
    assert!(writes_or_chains(&words(&["--write"])));
    assert!(!writes_or_chains(&words(&["src"])));
}

/// A generated type-check project keeps the no-emit mode in the file rather
/// than on the command line, so the route reads it there and writes it back
/// onto the argv it admits.
#[test]
fn a_project_declaring_no_emit_reaches_the_reporting_tool() {
    let directory = tempfile::tempdir().expect("temp root");
    std::fs::write(
        directory.path().join("tsconfig.tmp-devcheck.json"),
        r#"{"compilerOptions":{"noEmit":true}}"#,
    )
    .expect("config");

    let command = words(&[
        "./node_modules/.bin/tsc",
        "-p",
        "tsconfig.tmp-devcheck.json",
        "--pretty",
        "false",
    ]);
    assert_eq!(
        tool(&node_tool_route(
            &command,
            None,
            false,
            Some(directory.path())
        )),
        Some((
            "tsc",
            words(&[
                "-p",
                "tsconfig.tmp-devcheck.json",
                "--pretty",
                "false",
                "--noEmit"
            ]),
            ToolMode::Report
        ))
    );

    // Without the directory, and with a project that never says so, the run
    // keeps the review it had.
    assert!(tool(&node_tool_route(&command, None, false, None)).is_none());
    std::fs::write(
        directory.path().join("tsconfig.tmp-devcheck.json"),
        r#"{"compilerOptions":{"strict":true}}"#,
    )
    .expect("config");
    assert!(tool(&node_tool_route(
        &command,
        None,
        false,
        Some(directory.path())
    ))
    .is_none());
}
