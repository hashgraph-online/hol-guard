use super::readonly_test_reason;
use crate::contained_node_tool::{node_tool_route, NodeToolRoute, ToolMode};

fn reason(command: &str) -> Option<&'static str> {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    readonly_test_reason(&model)
}

#[test]
fn a_relative_vitest_entry_reads_as_the_project_runner() {
    for command in [
        "node node_modules/vitest/vitest.mjs run",
        "node node_modules/vitest/vitest.mjs run --root /work/tree/app",
        "node ./node_modules/vitest/vitest.mjs run src",
        "node dashboard/node_modules/vitest/vitest.mjs run",
        "node /work/app/node_modules/vitest/vitest.mjs run",
        "node node_modules/vitest/dist/cli.js run",
        "node ./node_modules/vitest/dist/cli.js run src",
        "node /work/app/node_modules/vitest/dist/cli.js run --root /work/tree/app",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_relative_jest_entry_reads_as_the_project_runner() {
    for command in [
        "node node_modules/jest/bin/jest.js",
        "node ./node_modules/jest/bin/jest.js src",
        "node /work/app/node_modules/jest/bin/jest.js",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_lookalike_entry_reads_as_no_runner() {
    for command in [
        "node xnode_modules/vitest/vitest.mjs run",
        "node node_modules_evil/vitest/vitest.mjs run",
        "node vitest/vitest.mjs run",
        "node node_modules/vitest/dist/vitest.mjs run",
        "node node_modules/vitest/vitest.mjs watch",
        "node node_modules/vite/dist/cli.js run",
        "node node_modules/xvitest/dist/cli.js run",
        "node node_modules/vitest/dist/cli.mjs run",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn admission_and_the_route_read_one_tool_table() {
    // The pre-tool pass admits the work and the sink plans the run. Both read
    // `contained_node_tool`'s table, so the reason a spelling is admitted with
    // has to be the mode the route lands in: a reporting tool carries the
    // read-only reason, a build carries the build reason, and a spelling the
    // table does not name carries neither.
    for (command, expected) in [
        ("npx eslint src", Some(ToolMode::Report)),
        ("bunx tsc --noEmit", Some(ToolMode::Report)),
        ("npx prettier --check .", Some(ToolMode::Report)),
        (
            "npm exec -- prettier --list-different .",
            Some(ToolMode::Report),
        ),
        // The same run with npm's own quiet option in front of the tool.
        (
            "npm exec --silent -- prettier --list-different .",
            Some(ToolMode::Report),
        ),
        (
            "node node_modules/typescript/bin/tsc --noEmit",
            Some(ToolMode::Report),
        ),
        (
            "node node_modules/prettier/bin/prettier.cjs --check .",
            Some(ToolMode::Report),
        ),
        ("npx vite build", Some(ToolMode::Build)),
        // `--no-install` only refuses to fetch a missing tool, so it names no
        // tool and both sides step over it.
        ("npx --no-install eslint src", Some(ToolMode::Report)),
        ("bunx --no-install vite build", Some(ToolMode::Build)),
        (
            "node node_modules/vite/bin/vite.js build",
            Some(ToolMode::Build),
        ),
        // Modes the table refuses: emitting `tsc`, rewriting Prettier, a fixing
        // ESLint, and a program the table never names.
        ("npx tsc", None),
        ("npx prettier .", None),
        ("npx eslint src --fix", None),
        ("npx rimraf dist", None),
        // A build that writes or chains is one the sink turns away in every
        // mode, so it is not admitted to containment either.
        ("npx vite build -w", None),
        ("npx vite build --output-file dist/log", None),
    ] {
        let words: Vec<String> = command.split(' ').map(str::to_owned).collect();
        let routed = match node_tool_route(&words, None, false) {
            NodeToolRoute::Tool { mode, .. } => Some(mode),
            _ => None,
        };
        assert_eq!(routed, expected, "{command}");
        let admitted = match expected {
            Some(ToolMode::Report) => Some("native_node_tool_readonly_containment_required"),
            Some(ToolMode::Build) => Some("native_node_build_output_containment_required"),
            None => None,
        };
        assert_eq!(reason(command), admitted, "{command}");
    }
}

#[test]
fn an_inert_npm_exec_option_leaves_the_run_the_tool_it_names() {
    // `npm exec` is `npx` under another name and takes the same options in
    // front of the tool: they answer the install prompt, pick the cache over
    // the registry, or quiet the runner. None of them names a package, so the
    // run behind them is still the workspace's own test runner, the one the
    // `npx` spelling has always been admitted as.
    for command in [
        "npm exec --no -- vitest run",
        "npm exec --yes -- vitest run",
        "npm exec -y -- vitest run",
        "npm exec --no-install -- vitest run",
        "npm exec --prefer-offline --silent -- vitest run",
        "npm exec --no vitest run",
        "npm x --no -- vitest run",
        "npm x -q -- jest",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
    // An option that names the package to fetch, one no table lists, and the
    // managers whose own exec options choose which packages a run reaches are
    // all left with the review they had.
    for command in [
        "npm exec --package=cowsay -- vitest run",
        "npm exec -p cowsay -- vitest run",
        "npm exec --call -- vitest run",
        "npm exec --prefix ../other -- vitest run",
        "npm exec --yes=false -- vitest run",
        "pnpm exec --recursive -- vitest run",
        "yarn exec --silent -- vitest run",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}
