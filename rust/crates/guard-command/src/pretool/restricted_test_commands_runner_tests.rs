//! How a project's own test runner reads when it is launched directly,
//! and which of its words leave the workspace it was installed in.
use super::reason;

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
fn a_relative_ava_entry_reads_as_the_project_runner() {
    for command in [
        // AVA moved its entry twice without renaming the package, so all
        // three spellings name the runner a workspace may hold.
        "node node_modules/ava/entrypoints/cli.js",
        "node ./node_modules/ava/entrypoints/cli.mjs test/unit.js",
        "node /work/app/node_modules/ava/cli.js",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn an_ava_run_that_does_not_watch_is_contained() {
    // AVA runs its suite once and exits, so the plain call is the contained
    // one. It reads yargs, so a declared boolean spends the next word:
    // `--watch false` and `--watch=false` both finish, and `--no-watch` reads
    // as `nowatch`, which names no option this screen models.
    for command in [
        "npx ava",
        "ava",
        "ava test/unit.js",
        "npx ava --tap",
        "npx ava --serial --verbose",
        "npx ava --concurrency 2 test/unit.js",
        "npx ava -c 2",
        "npx ava --watch=false",
        "npx ava --watch false",
        "npx ava --no-watch",
        "npx ava -- --watch",
        "bunx ava --fail-fast",
        "node node_modules/ava/entrypoints/cli.js --fail-fast",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn an_ava_run_that_watches_or_leaves_its_workspace_keeps_its_review() {
    // `debug` starts AVA under an inspector and waits for it, `reset-cache`
    // clears the precompiler cache rather than running tests, `-w` is AVA's
    // short `--watch`, and `--node-arguments` hands its value to the worker's
    // Node, which has a watch mode and a debugger of its own.
    for command in [
        "npx ava --watch",
        "npx ava -w",
        "npx ava --watch=true",
        "npx ava --watch true",
        // yargs compares the value exactly, so `0` names no boolean and the
        // option keeps the default its presence sets.
        "npx ava --watch=0",
        "npx ava debug",
        "npx ava debug test/unit.js",
        "npx ava reset-cache",
        "npx ava --config /etc/ava.config.js",
        "npx ava --node-arguments=--inspect-brk",
        "npx ava --node-arguments --inspect-brk",
        "node node_modules/ava/entrypoints/cli.js --watch",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn a_relative_single_pass_runner_entry_reads_as_the_project_runner() {
    for command in [
        "node node_modules/jasmine/bin/jasmine.js",
        "node ./node_modules/qunit/bin/qunit.js test/unit.js",
        "node /work/app/node_modules/uvu/bin.js test",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_single_pass_runner_that_stays_in_its_workspace_is_contained() {
    // None of the three watches by default. Jasmine and uvu cannot watch at
    // all, and QUnit watches only when the flag is on the line, so the plain
    // call is the contained one for each of them.
    for command in [
        "npx jasmine",
        "jasmine",
        "npx jasmine --filter=auth",
        "npx jasmine --config=spec/support/jasmine.json --reporter=dot",
        "npx jasmine spec/unit_spec.js",
        "npx jasmine help",
        "npx jasmine version",
        "npx jasmine enumerate",
        "npx qunit",
        "npx qunit test/",
        "npx qunit --filter auth --reporter tap",
        "npx qunit -f auth",
        "npx uvu",
        "npx uvu test",
        "npx uvu test spec",
        "npx uvu -r tsm test",
        "npx uvu --bail",
        "bunx uvu test",
        "node node_modules/qunit/bin/qunit.js --seed 1",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_single_pass_runner_that_writes_or_watches_keeps_its_review() {
    // `init` writes Jasmine's configuration file and `examples` copies
    // example specs and sources over whatever stands where they land, so
    // neither is a run of the project's own suite. Jasmine matches a command
    // name wherever it stands on the line, including behind `--`, so the
    // screen reads the whole line the way Jasmine does.
    //
    // QUnit's `--watch` is read by Commander, which declares it as a flag
    // taking no value: the `false` after it is another file to run, not the
    // option's value, so `--watch false` watches where AVA's and Mocha's
    // finish.
    for command in [
        "npx jasmine init",
        "npx jasmine examples",
        "npx jasmine --filter=auth init",
        "npx jasmine -- init",
        "npx jasmine --config=/etc/jasmine.json",
        "npx jasmine --helper=../../tools/helper.js",
        "npx qunit --watch",
        "npx qunit -w",
        "npx qunit --watch false",
        "npx qunit --watch=false",
        "npx qunit -fw",
        "npx qunit --require /etc/setup.js",
        "npx uvu --cwd /tmp/elsewhere",
        "npx uvu -r ../../tools/tsm test",
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
        "node node_modules/xava/entrypoints/cli.js",
        "node node_modules/ava/entrypoints/cli.cjs",
        "node node_modules/ava/entrypoints/main.js",
        "node node_modules/xjasmine/bin/jasmine.js",
        "node node_modules/jasmine/lib/jasmine.js",
        "node node_modules/qunit/bin/qunit.mjs",
        "node node_modules/uvu/bin.mjs",
        "node node_modules/uvu/run/bin.js",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn a_jasmine_word_that_sets_the_environment_keeps_its_review() {
    // Jasmine walks the whole line before it reads an option and writes every
    // word that is not a long option and holds an `=` into `process.env`. Such
    // a word names no path, so the workspace screen cannot see it, and the
    // ones that matter choose what Node loads in the workers the run spawns.
    for command in [
        "npx jasmine NODE_OPTIONS=--inspect-brk",
        "npx jasmine --parallel=2 NODE_OPTIONS=--inspect-brk",
        "npx jasmine NODE_OPTIONS=--import=data:text/javascript,console.log(1)",
        "npx jasmine spec/unit_spec.js JASMINE_CONFIG_PATH=spec/support/jasmine.json",
        "npx jasmine -- NODE_OPTIONS=--inspect-brk",
        "jasmine NODE_OPTIONS=--inspect-brk",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }

    // A long option carrying a value is not an assignment to Jasmine, and the
    // other two runners read their lines with ordinary parsers, so an `=` word
    // on their lines is a file or a pattern and stays contained.
    for command in [
        "npx jasmine --filter=auth",
        "npx jasmine --config=spec/support/jasmine.json",
        "npx qunit --filter=auth",
        "npx uvu test a=b",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_relative_tape_or_tsd_entry_reads_as_the_project_runner() {
    for command in [
        "node node_modules/tape/bin/tape test/a.js",
        "node ./node_modules/.bin/tape test/a.js",
        "node node_modules/tsd/dist/cli.js",
        "node /work/app/node_modules/tsd/dist/cli.js packages/core",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_tape_or_tsd_run_inside_its_workspace_is_contained() {
    // tape reads its line with minimist and then requires every operand as a
    // path resolved against the run directory; tsd reads three meow flags and
    // takes its first operand as the project to check. Neither watches, both
    // only read, so a line that names nothing outside the workspace is a
    // single contained pass.
    for command in [
        "npx tape",
        "tape test/a.js",
        "npx tape test/a.js test/b.js",
        "npx tape -r ts-node/register test/a.js",
        "npx tape --require tsm test/a.js",
        "npx tape -i .taperignore test/a.js",
        "bunx tape test/a.js",
        "npx tsd",
        "tsd",
        "npx tsd packages/core",
        "npx tsd --typings dist/index.d.ts",
        "npx tsd --files test/types.test-d.ts --show-diff",
        "npx tsd -f test/types.test-d.ts",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_tape_or_tsd_word_that_leaves_the_workspace_keeps_its_review() {
    // What either runner loads is the paths on its line, so a word naming a
    // module, an ignore file, a typings file or a project outside the
    // workspace is the whole of what the screen has to refuse.
    for command in [
        "npx tape /etc/suite.js",
        "npx tape -r /etc/setup.js test/a.js",
        "npx tape --require ../../tools/tsm test/a.js",
        "npx tape -i ~/.taperignore test/a.js",
        "npx tape ../../other/test/a.js",
        "npx tsd ../../other",
        "npx tsd --typings /etc/index.d.ts",
        "npx tsd --files ../../other/types.test-d.ts",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn a_tap_borp_poku_or_lab_entry_reads_as_the_project_runner() {
    for command in [
        "node node_modules/tap/dist/esm/run.mjs --disable-coverage test/unit.js",
        "node ./node_modules/tap/bin/run.js --no-coverage",
        "node node_modules/borp/borp.js",
        "node /work/app/node_modules/poku/lib/bin/index.js test",
        "node node_modules/@hapi/lab/bin/lab",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_relative_cucumber_entry_reads_as_the_project_runner() {
    for command in [
        "node node_modules/@cucumber/cucumber/bin/cucumber.js",
        "node ./node_modules/.bin/cucumber-js features",
        "node /work/app/node_modules/@cucumber/cucumber/bin/cucumber.js features/login.feature",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_tap_borp_poku_or_lab_run_inside_its_workspace_is_contained() {
    // lab cannot watch at all, and tap, borp and poku watch only when the
    // flag is on the line, so the plain call is the contained one for each
    // of them. borp's reporter writes a file only when its value carries a
    // colon destination, so a plain reporter name stays readable. tap
    // collects coverage unless the line turns it off, so the tap run this
    // route takes is the one that names the word.
    for command in [
        "npx tap --no-coverage",
        "tap --no-cov",
        "npx tap --disable-coverage test/unit.js",
        "npx tap --no-coverage --jobs=4 test/",
        "npx tap --no-coverage --no-browser",
        "npx borp",
        "npx borp test/unit.test.js",
        "npx borp --coverage --reporter=spec",
        "bunx borp",
        "npx poku",
        "npx poku test",
        "npx poku --debug test",
        "npx lab",
        "npx lab -t 100",
        "npx lab -r console -o stdout",
        "npx lab -L",
        "npx borp --reporter spec",
        "npx borp -r spec",
        "npx borp --reporter=tap:stdout",
        "npx borp --reporter tap:stderr",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_cucumber_run_inside_its_workspace_is_contained() {
    // cucumber-js has no watch mode and no command verbs: its operands are
    // feature files, directories or `FILE:LINE` locations, and the options
    // that load anything name a workspace path or a module specifier, which
    // the shared screen already answers for.
    for command in [
        "npx cucumber-js",
        "cucumber-js",
        "npx cucumber-js features/login.feature",
        "npx cucumber-js features/login.feature:12",
        "npx cucumber-js --require features/support/world.js",
        "npx cucumber-js -r features/step_definitions",
        "npx cucumber-js --import features/support/hooks.ts",
        "npx cucumber-js --config cucumber.cjs --profile ci",
        "npx cucumber-js --tags @smoke --fail-fast",
        "npx cucumber-js --format progress-bar",
        "npx cucumber-js --format html:reports/cucumber.html",
        "npx cucumber-js --parallel 4 --retry 2",
        "npx cucumber-js --dry-run",
        "bunx cucumber-js features",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_tap_borp_poku_or_lab_word_that_leaves_the_run_keeps_its_review() {
    // tap takes its command from the first positional word, so the words
    // that print a report, build a plugin or open its repl stop a call being
    // a test run; `--node-arg` forwards arguments to the Node that runs the
    // tests, `--test-env` sets that process's environment, and an HTML or
    // lcov coverage report opens a browser on the generated page.
    //
    // borp reads Node's own `parseArgs`, where `watch` is a boolean: it never
    // takes the next word and `--watch=false` is rejected rather than read as
    // off, so the name alone watches, as QUnit's does.
    //
    // poku reads its line itself, asking whether a word *starts with* the
    // option's spelling, so `--watch=false` turns the watch on. Its other
    // options end processes the run never started or load an environment
    // file, and neither a port, a pid nor a permission name is a path the
    // workspace screen can see.
    //
    // lab's `--inspect` starts the suite under Node's debugger and holds the
    // process open on a listening port.
    //
    // tap declares `coverage` with `default: true`, so a line that does not
    // turn it off collects into `.nyc_output` or `.tap` inside the project.
    // The read-only route carries no workspace write root, so that collection
    // would be denied part-way through the run.
    for command in [
        "npx tap",
        "npx tap test/unit.js",
        "npx tap --coverage-report=text",
        "npx tap report",
        "npx tap list",
        "npx tap repl",
        "npx tap build",
        "npx tap --node-arg=--inspect-brk",
        "npx tap --test-env=NODE_OPTIONS=--inspect-brk",
        "npx tap --coverage-report=html",
        "npx tap --coverage-report lcov",
        "npx tap --browser=firefox",
        "npx tap --reporter /etc/tap-reporter.js",
        "npx borp --watch",
        "npx borp -w",
        "npx borp --watch=false",
        "npx borp -wc",
        "npx borp --reporter /etc/reporter.js",
        "npx poku --watch",
        "npx poku -w",
        "npx poku --watch=false",
        "npx poku --killPort=3000",
        "npx poku --killRange=3000-3010",
        "npx poku --killPid=1",
        "npx poku --envFile=.env",
        "npx poku --denoAllow=net",
        "npx poku --denoDeny=env",
        "npx lab --inspect",
        "npx lab --inspect-brk",
        "npx lab -L --lint-fix",
        "npx lab --coverage-path /etc",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn a_tap_watch_or_a_borp_report_destination_keeps_its_review() {
    // tap declares `watch` as a flag with the short `-w`, so a tap call that
    // names it runs the suite and then keeps re-running it, exactly as borp's
    // and poku's do. Each tap line here turns coverage off, so the watch is
    // the only thing keeping it under review. borp reads a colon in a
    // reporter value as a file to write, which the read-only route carries no
    // root for; `stdout` and `stderr` name a stream instead, so they stay
    // readable. Node's `parseArgs` reads a short group up to the first letter
    // that takes a value, so `-Cr tap:results.txt` carries the same reporter
    // as the long spelling does.
    for command in [
        "npx tap --no-cov --watch",
        "npx tap --no-coverage -w",
        "npx tap --disable-coverage -w test/unit.js",
        "npx tap --no-cov -wj4",
        "node node_modules/tap/bin/run.js --no-cov --watch",
        "npx borp --reporter=tap:results.txt",
        "npx borp --reporter tap:results.txt",
        "npx borp -r tap:results.txt",
        "npx borp -rtap:results.txt",
        "npx borp -Cr tap:results.txt",
        "npx borp -Crtap:results.txt",
        "npx borp -oCr tap:results.txt",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn a_tap_line_that_turns_coverage_back_on_keeps_its_review() {
    // Both of tap's option readers let the last spelling win, so a negation
    // earlier on the line is not the answer. tap 16 and 17 turn the flag back
    // on with `--cov` or `--coverage`, and tap 18 and later with
    // `--no-disable-coverage`; each of these runs collects into `.nyc_output`
    // or `.tap`, which the read-only route carries no write root for.
    for command in [
        "npx tap --no-coverage --coverage test/",
        "npx tap --no-cov --cov",
        "npx tap --disable-coverage --no-disable-coverage test/unit.js",
        "node node_modules/tap/bin/run.js --no-cov --coverage",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
    // The other order is the ordinary one and stays contained.
    for command in [
        "npx tap --coverage --no-coverage test/",
        "npx tap --no-disable-coverage --disable-coverage test/unit.js",
    ] {
        assert_eq!(
            reason(command),
            Some("native_vitest_readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn a_tap_borp_poku_or_lab_lookalike_entry_reads_as_no_runner() {
    for command in [
        "node node_modules/xtap/dist/esm/run.mjs",
        "node node_modules/tap/dist/cjs/run.js",
        "node node_modules/tap/bin/run.mjs",
        "node node_modules/xborp/borp.js",
        "node node_modules/borp/borp.mjs",
        "node node_modules/poku/lib/bin/index.mjs",
        "node node_modules/lab/bin/lab",
        "node node_modules/@hapi/lab/lib/cli.js",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}

#[test]
fn a_cucumber_word_that_leaves_the_workspace_keeps_its_review() {
    // `--publish` uploads the report to cucumber's hosted service, which no
    // path on the line names; everything else the runner loads is a path the
    // workspace screen reads.
    for command in [
        "npx cucumber-js --publish",
        "npx cucumber-js --publish=false",
        "npx cucumber-js features --publish",
        "npx cucumber-js /etc/features",
        "npx cucumber-js --require /etc/world.js",
        "npx cucumber-js --config ../../other/cucumber.cjs",
        "npx cucumber-js --format html:/tmp/cucumber.html",
        "npx cucumber-js --import ~/.cucumber/hooks.js",
    ] {
        assert_eq!(reason(command), None, "{command}");
    }
}
