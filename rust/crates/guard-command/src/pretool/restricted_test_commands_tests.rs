use super::{package_permission_contained, readonly_test_reason};
use crate::contained_node_tool::{node_tool_route, NodeToolRoute, ToolMode};

fn parsed(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
}

fn reason(command: &str) -> Option<&'static str> {
    readonly_test_reason(&parsed(command), None)
}

#[test]
fn the_node_test_reason_carries_bun_s_package_protection_permission() {
    // Bun is a package-manager image, so the package firewall reports its
    // package-protection permission on every Bun launch. `bun test` resolves to
    // the Node test reason, and a reason that does not accept that permission
    // leaves the run at review however well the rest of the screen reads.
    for command in [
        "bun test",
        "bun test src/parser.test.ts",
        "bun test --coverage",
        "bun test -t adds",
    ] {
        let model = parsed(command);
        let found = readonly_test_reason(&model, None);
        assert_eq!(
            found,
            Some("native_node_test_readonly_containment_required"),
            "{command}"
        );
        assert!(
            package_permission_contained(found, Some(&model)),
            "{command}"
        );
    }
}

#[test]
fn bun_running_one_workspace_test_file_takes_the_node_test_boundary() {
    // `bun src/app-routing.test.ts` is the pass `bun test` takes over that one
    // file: `bun test` discovers and loads the same file under this profile.
    for command in [
        "bun src/app-routing.test.ts",
        "bun src/shell-navigation.test.tsx",
        "bun api.spec.mjs",
        "bun tests/test_parser.js",
    ] {
        let model = parsed(command);
        let found = readonly_test_reason(&model, None);
        assert_eq!(
            found,
            Some("native_node_test_readonly_containment_required"),
            "{command}"
        );
        assert!(
            package_permission_contained(found, Some(&model)),
            "{command}"
        );
    }
}

#[test]
fn bun_keeps_the_review_for_a_file_outside_the_workspace_or_a_second_word() {
    // A path that leaves the tree, a name no project gives a test file, and a
    // line carrying more than the one file each stay at ordinary review.
    for command in [
        "bun /tmp/payload.test.ts",
        "bun ../other/app.test.ts",
        "bun ~/scratch/app.test.ts",
        "bun src/server.ts",
        "bun src/app.test.ts --preload ./setup.ts",
        "bun src/app.test.ts src/other.test.ts",
        "bun src/app.test.sh",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
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
fn bun_launching_the_project_runner_reads_as_the_run_node_spells() {
    for command in [
        "bun node_modules/vitest/vitest.mjs run",
        "bun node_modules/vitest/vitest.mjs run --root /work/tree/app",
        "bun ./node_modules/vitest/vitest.mjs run src",
        "bun ../app/node_modules/vitest/vitest.mjs run",
        "bun node_modules/vitest/dist/cli.js run",
        "bun node_modules/jest/bin/jest.js src",
        "bun node_modules/mocha/bin/mocha.js test/unit",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn bun_launching_no_project_runner_reads_as_no_runner() {
    for command in [
        // `--cwd` names no entry at this position, and the sink reads the
        // call the same way, so admitting it here would run a file the call
        // never spelled.
        "bun --cwd app node_modules/vitest/vitest.mjs run",
        "bun --cwd=app node_modules/vitest/vitest.mjs run",
        "bun xnode_modules/vitest/vitest.mjs run",
        "bun node_modules/vitest/vitest.mjs watch",
        // No verb selects the run, so the watch spelling decides, and a call
        // left watching never finishes inside the sink. `run --watch` is not
        // here: Vitest's `run` command turns the watch off whatever follows
        // it, which is the reading the `node` spelling of this entry already
        // carries.
        "bun node_modules/vitest/vitest.mjs --watch",
        "bun node_modules/vite/dist/cli.js run",
    ] {
        assert_ne!(
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
fn a_relative_mocha_entry_reads_as_the_project_runner() {
    for command in [
        "node node_modules/mocha/bin/mocha.js",
        "node ./node_modules/mocha/bin/mocha.js test/unit",
        "node /work/app/node_modules/mocha/bin/mocha.js",
        // Mocha 8 and 9 publish the same shim without the extension, and the
        // sink runs whichever of the two the workspace holds.
        "node node_modules/mocha/bin/mocha",
        "node ./node_modules/mocha/bin/mocha test/unit",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_mocha_run_that_does_not_watch_is_contained() {
    // Mocha runs once unless it is told to watch, so the plain call is the
    // contained one and a `--watch false` beside it reads the same way:
    // yargs-parser spends the next word on a declared boolean, which is the
    // spelling Vitest's mri would have read as a test filter instead.
    for command in [
        "npx mocha",
        "mocha",
        "mocha test/unit",
        "npx mocha --reporter spec test/unit",
        "npx mocha --watch=false",
        "npx mocha --watch false",
        "npx mocha --watch-files src",
        "npx mocha --w=false",
        "npx mocha -- --watch",
        "bunx mocha --require ./test/setup.js",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_mocha_run_that_watches_or_leaves_its_workspace_keeps_its_review() {
    // `init` scaffolds a configuration rather than running tests, `-w` is
    // Mocha's short `--watch` unlike Jest's, and a value naming a path this
    // workspace does not hold would load a module the read-only admission
    // never covered.
    for command in [
        "npx mocha --watch",
        "npx mocha -w",
        "npx mocha --watch=true",
        "npx mocha --watch true",
        "npx mocha --watch=0",
        "npx mocha init",
        "npx mocha --config /etc/mocharc.json",
        "npx mocha --require ../../outside/setup.js",
        "node node_modules/mocha/bin/mocha.js --watch",
        // yargs-parser answers an option by its alias, so the long spelling
        // of Mocha's `-w` turns the watch on under its own name.
        "npx mocha --w",
        "npx mocha --w=true",
        // Mocha restores the dashes on a `--node-option` value and hands it
        // to Node, which has a watch mode of its own and a debugger that
        // holds the process until a client attaches.
        "npx mocha -n watch",
        "npx mocha --node-option watch",
        "npx mocha --node-option=watch",
        "npx mocha --node-option=--inspect-brk",
        "npx mocha -n --inspect-brk",
        // yargs-parser answers `-n` by its long spelling too, so `--n` hands
        // Node the same option the short group does.
        "npx mocha --n watch",
        "npx mocha --n=--inspect-brk",
    ] {
        assert_eq!(reason(command), None, "{command}");
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
        "node node_modules/xmocha/bin/mocha",
        "node node_modules/mocha/bin/mocha.sh",
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
        let routed = match node_tool_route(&words, None, false, None) {
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

#[test]
fn a_runner_told_not_to_watch_runs_once() {
    // Both runners watch by default, so a script or an agent that wants one
    // pass says so on the line. Reading the option's name and ignoring its
    // value sent exactly those calls to review, while the plain `jest` and
    // the `vitest run` beside them were contained.
    for command in [
        "npx jest --watchAll=false",
        "npx jest --watch=false",
        "npx jest --watch-all=false",
        "npx jest --watchAll false",
        "npx vitest --run",
        "npx vitest --no-watch",
        "npx vitest --watch=false",
        "npx vitest related src/a.ts --run",
        "npx vitest bench --run",
        "vitest --run src",
        // CAC hands a first operand it has no command for to the default
        // command, whose operands are test filters, so these are the same
        // one pass `vitest run` names and the spelling `jest` and `mocha`
        // were already contained in.
        "npx vitest src/a.test.ts --run",
        "npx vitest src/a.test.ts src/b.test.ts --no-watch",
        "vitest math --watch=false",
        "node node_modules/vitest/vitest.mjs --run",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_runner_left_watching_keeps_its_review() {
    // A watching run never finishes inside the sink, and a line that asks for
    // one pass only in a spelling the runner's own parser does not read is
    // still a watching run: mri spends no word on a declared boolean, the last
    // watch option on the line wins, nothing after `--` is an option at all,
    // and a word naming a command the reading does not model keeps its review
    // wherever it stands.
    for command in [
        "npx jest --watch",
        "npx jest --watchAll=true",
        "npx jest --watchAll true",
        "npx jest --watch=0",
        "npx vitest",
        "npx vitest --watch",
        "npx vitest --watch=true",
        "npx vitest --watch false",
        "npx vitest --watch=false --watch",
        "npx vitest --no-watch -w",
        // mri reads a `--no-` prefix as the option set to false, so `--no-run`
        // undoes the `--run` before it and leaves Vitest watching.
        "npx vitest --run --no-run",
        "npx vitest --no-watch --no-run",
        "npx vitest -- --run",
        "npx vitest --run init",
        "npx vitest --run watch",
        "npx vitest related src/a.ts",
        "npx vitest init --run",
        // A filter is not the pass: without a watch-off spelling Vitest keeps
        // watching the files the filter selected.
        "npx vitest src/a.test.ts",
        "npx vitest src/a.test.ts --run --watch",
        "node node_modules/vitest/vitest.mjs --watch",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[path = "restricted_test_commands_manager_tests.rs"]
mod manager;

#[test]
fn pnpm_runs_a_word_none_of_its_subcommands_claims_as_the_local_bin_run() {
    // pnpm hands a word it does not recognise to `pnpm exec`, so each of
    // these starts the workspace's own installed runner exactly as the
    // explicit spelling does. The words behind the runner rule out a manifest
    // script, which carries a tail of its own only after a `--` separator.
    for command in [
        "pnpm vitest run",
        "pnpm jest --ci",
        "pnpm mocha --reporter spec",
    ] {
        let explicit = command.replacen("pnpm ", "pnpm exec ", 1);
        assert_eq!(reason(command), reason(&explicit), "{command}");
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
    // An option in front of the word fans the run out past one package, and a
    // word pnpm runs itself or names a manifest script stays with the script
    // reading, which resolves the body behind the name.
    for command in [
        "pnpm -r test",
        "pnpm --filter dashboard test",
        "pnpm --recursive run test",
        "pnpm run test",
        "pnpm test",
        "pnpm install",
        // `--reporter` takes the next word as its value, so the line that
        // reaches this reading lost the `exec` the author wrote. The reading
        // does not put the verb back: a peel that swallowed one of pnpm's own
        // subcommands keeps the review the written line had.
        "pnpm --reporter exec vitest run",
        "pnpm --loglevel exec vitest run",
    ] {
        assert_ne!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}
