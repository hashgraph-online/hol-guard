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
